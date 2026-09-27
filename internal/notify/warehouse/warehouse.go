// Package warehouse copies WAF telemetry into a self-hosted ClickHouse for
// long-term analytics (issue #94).
//
// The operational store (SQLite by default) is unchanged and stays the
// source of truth: it serves the admin UI's point lookups, the live SSE
// tail, rules, sessions and services. ClickHouse gets a second copy of the
// telemetry only, where year-long columnar scans are cheap and the admin
// UI's own 30-day --retention prune is no longer a data-loss event.
//
// Two shapes go across:
//
//   - The fact table, waf_requests, streamed live off the log-worker
//     fan-out hook. Every number on the existing dashboard is an aggregate
//     over this, so this table alone reproduces all of them — over a year
//     rather than a day.
//   - Dimension tables, snapshotted whole on an interval, holding the
//     context needed to interpret a fact: was this IP already banned when
//     it hit us, what was its threat score made of, has this JA4 been seen
//     on blocked traffic before.
//
// Nothing secret is ever shipped. Only the five dimension sources named in
// snapshot() are read, by allowlist — meta, api_keys, sessions,
// webauthn_credentials, webhook_config, certificates and
// threat_intel_sources hold password hashes, key digests, session tokens,
// TLS private key paths and sealed secrets, and a warehouse is a second
// system with its own access model.
package warehouse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/internal/storage"
)

const (
	// queueSize matches storage.logQueueSize: the sink should be able to
	// absorb the same burst the log queue itself can.
	queueSize = 10000
	// batchSize caps one INSERT. ClickHouse creates a part per insert and
	// merges them in the background, so many small inserts cost far more
	// than few large ones — this is the single most important knob here.
	batchSize = 1000
	// flushInterval bounds how long a partial batch waits, so a quiet WAF
	// still lands its rows promptly.
	flushInterval = 5 * time.Second
	// snapshotInterval is how often the dimension tables are re-copied
	// whole. They are small (hundreds to low thousands of rows) and change
	// rarely, so this is cheap.
	snapshotInterval = 5 * time.Minute
	// chDateTime is ClickHouse's DateTime64(3) text format.
	chDateTime = "2006-01-02 15:04:05.000"
)

// safeDBName guards the one place a caller-supplied string reaches SQL text
// (the database name, which cannot be parameterized in DDL). Same
// conservative-charset approach as services.safeServiceNameForBan.
var safeDBName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// store is the slice of *storage.DB the dimension snapshot needs; an
// interface so tests run without a real database, matching mailer.store.
type store interface {
	ListIPRules() ([]storage.IPRule, error)
	ListGeoRules() ([]storage.GeoRule, error)
	ListServices() ([]storage.Service, error)
	ListIPThreatScores() ([]storage.IPThreatScore, error)
	ListJA4Reputation() ([]storage.JA4Reputation, error)
}

// Sink batches request logs and ships them to ClickHouse over its HTTP
// interface, which takes SQL as a POST body — there is no separate ingest
// API to build or run.
type Sink struct {
	base     string // scheme://host[:port], no database param
	database string
	client   *http.Client
	store    store

	queue chan storage.RequestLog
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

// New connects to ClickHouse at rawURL, creates the database and tables if
// they do not exist, and starts the background batching goroutine.
//
// The schema is created here rather than by a /docker-entrypoint-initdb.d/
// script because those run only against an empty data volume: a column
// added in a later release would silently never appear. This mirrors
// storage/schema.go, which re-runs CREATE TABLE IF NOT EXISTS on every boot
// for the WAF's own store.
func New(rawURL string, st store) (*Sink, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse warehouse URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("warehouse URL must be http or https, got %q", u.Scheme)
	}
	// url.Query() swallows a malformed query string and returns whatever it
	// could salvage, so "?database=waf;DROP" would silently fall back to
	// the default database rather than being rejected. ParseQuery surfaces
	// that as an error instead: connecting to a different database than the
	// operator asked for is not a safe default.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("parse warehouse URL query: %w", err)
	}
	database := q.Get("database")
	if database == "" {
		database = "waf"
	}
	if !safeDBName.MatchString(database) {
		return nil, fmt.Errorf("invalid warehouse database name %q", database)
	}
	s := &Sink{
		base:     u.Scheme + "://" + u.Host,
		database: database,
		client:   &http.Client{Timeout: 30 * time.Second},
		store:    st,
		queue:    make(chan storage.RequestLog, queueSize),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if err := s.createSchema(); err != nil {
		return nil, err
	}
	go s.run()
	return s, nil
}

// Push enqueues an entry. Non-blocking and drops when full, exactly like
// storage.QueueRequest and webhook.Pusher.Push — this runs on the single log
// worker goroutine, so it must never wait on the network.
func (s *Sink) Push(entry storage.RequestLog) {
	select {
	case s.queue <- entry:
	default:
	}
}

// Stop flushes what is buffered and shuts the goroutine down.
func (s *Sink) Stop() {
	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}

func (s *Sink) run() {
	defer close(s.done)
	batch := make([]storage.RequestLog, 0, batchSize)
	flush := time.NewTicker(flushInterval)
	defer flush.Stop()
	snap := time.NewTicker(snapshotInterval)
	defer snap.Stop()

	// One snapshot up front so a fresh warehouse is immediately joinable
	// instead of empty until the first tick.
	s.snapshot()

	for {
		select {
		case entry := <-s.queue:
			batch = append(batch, entry)
			if len(batch) >= batchSize {
				s.flush(batch)
				batch = batch[:0]
			}
		case <-flush.C:
			if len(batch) > 0 {
				s.flush(batch)
				batch = batch[:0]
			}
		case <-snap.C:
			s.snapshot()
		case <-s.stop:
			// Drain whatever is still queued, bounded by one batch so
			// shutdown can't hang on a flood.
			for len(s.queue) > 0 && len(batch) < batchSize {
				batch = append(batch, <-s.queue)
			}
			if len(batch) > 0 {
				s.flush(batch)
			}
			return
		}
	}
}

func (s *Sink) flush(batch []storage.RequestLog) {
	rows := make([]any, len(batch))
	for i, e := range batch {
		rows[i] = requestRow(e)
	}
	if err := s.insert("waf_requests", rows); err != nil {
		log.Printf("warehouse: insert %d requests: %v", len(rows), err)
	}
}

// snapshot re-copies every dimension table. The ClickHouse tables are
// ReplacingMergeTree keyed by entity, so re-inserting the same key just
// supersedes the previous version on the next merge.
//
// ponytail: current-state only — the fact table carries history, and
// per-snapshot history of a rule table would need a separate versioned
// design. Add one if "when exactly was this IP banned" ever needs more than
// ip_rules.created_at.
func (s *Sink) snapshot() {
	if s.store == nil {
		return
	}
	now := time.Now().UTC().Format(chDateTime)

	if v, err := s.store.ListIPRules(); err != nil {
		log.Printf("warehouse: snapshot ip_rules: %v", err)
	} else {
		rows := make([]any, len(v))
		for i, r := range v {
			rows[i] = map[string]any{
				"snapshot_at": now, "id": r.ID, "app_name": r.AppName, "ip": r.IP,
				"rule_type": r.RuleType, "note": r.Note,
				"created_at": r.CreatedAt.UTC().Format(chDateTime),
			}
		}
		s.insertLogged("waf_ip_rules", rows)
	}

	if v, err := s.store.ListGeoRules(); err != nil {
		log.Printf("warehouse: snapshot geo_rules: %v", err)
	} else {
		rows := make([]any, len(v))
		for i, r := range v {
			rows[i] = map[string]any{
				"snapshot_at": now, "id": r.ID, "app_name": r.AppName,
				"country_code": r.CountryCode, "rule_type": r.RuleType,
				"created_at": r.CreatedAt.UTC().Format(chDateTime),
			}
		}
		s.insertLogged("waf_geo_rules", rows)
	}

	if v, err := s.store.ListServices(); err != nil {
		log.Printf("warehouse: snapshot services: %v", err)
	} else {
		rows := make([]any, len(v))
		for i, r := range v {
			rows[i] = map[string]any{
				"snapshot_at": now, "id": r.ID, "name": r.Name, "host": r.Host,
				"prefix": r.Prefix, "backend": r.Backend, "tls_mode": r.TLSMode,
				"bot_mode": r.BotMode, "cache_enabled": b2i(r.CacheEnabled),
				"rate_limit_rps": r.RateLimitRPS, "rate_limit_burst": r.RateLimitBurst,
				"created_at": r.CreatedAt.UTC().Format(chDateTime),
			}
		}
		s.insertLogged("waf_services", rows)
	}

	if v, err := s.store.ListIPThreatScores(); err != nil {
		log.Printf("warehouse: snapshot ip_threat_scores: %v", err)
	} else {
		rows := make([]any, len(v))
		for i, r := range v {
			rows[i] = map[string]any{
				"snapshot_at": now, "ip": r.IP, "total_score": r.Total,
				"autoban_score": r.AutobanScore, "bot_score": r.BotScore,
				"asn_score": r.ASNScore, "geo_score": r.GeoScore, "ja4_score": r.JA4Score,
				"updated_at": r.UpdatedAt.UTC().Format(chDateTime),
			}
		}
		s.insertLogged("waf_threat_scores", rows)
	}

	if v, err := s.store.ListJA4Reputation(); err != nil {
		log.Printf("warehouse: snapshot ja4_reputation: %v", err)
	} else {
		rows := make([]any, len(v))
		for i, r := range v {
			rows[i] = map[string]any{
				"snapshot_at": now, "ja4": r.JA4, "hits": r.Hits,
				"blocked_hits": r.BlockedHits,
				"last_seen":    r.LastSeen.UTC().Format(chDateTime),
			}
		}
		s.insertLogged("waf_ja4_reputation", rows)
	}
}

func (s *Sink) insertLogged(table string, rows []any) {
	if err := s.insert(table, rows); err != nil {
		log.Printf("warehouse: insert %s: %v", table, err)
	}
}

// insert POSTs rows as JSONEachRow — newline-delimited JSON objects whose
// keys are column names.
func (s *Sink) insert(table string, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body) // writes a trailing newline per value
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode row: %w", err)
		}
	}
	q := fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", table)
	return s.post(q, &body, true)
}

// exec runs a statement with no body (DDL).
func (s *Sink) exec(query string, withDatabase bool) error {
	return s.post(query, nil, withDatabase)
}

func (s *Sink) post(query string, body io.Reader, withDatabase bool) error {
	v := url.Values{"query": {query}}
	if withDatabase {
		v.Set("database", s.database)
	}
	req, err := http.NewRequest(http.MethodPost, s.base+"/?"+v.Encode(), body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "coraza-waf-mod/internal/notify/warehouse")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection is reused
	return nil
}

func (s *Sink) createSchema() error {
	// The database itself can't be created against a database that doesn't
	// exist yet, so this one statement goes without the param.
	if err := s.exec("CREATE DATABASE IF NOT EXISTS "+s.database, false); err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	for _, ddl := range schema {
		if err := s.exec(ddl, true); err != nil {
			return fmt.Errorf("create table: %w", err)
		}
	}
	return nil
}

// schema is the ClickHouse side, one statement per entry.
//
// waf_requests is ORDER BY (ts, real_ip) so the same index serves both
// time-range scans (every dashboard aggregate) and per-IP forensics. Its
// TTL is deliberately longer than the WAF's own --retention: outliving the
// prune is the point of this package. Repetitive columns are
// LowCardinality, which is what makes a year of this data small.
//
// The dimension tables are ReplacingMergeTree(snapshot_at): re-inserting a
// key supersedes the older row on merge, so a periodic full copy needs no
// delete pass.
var schema = []string{
	`CREATE TABLE IF NOT EXISTS waf_requests (
		ts           DateTime64(3),
		app_name     LowCardinality(String),
		real_ip      String,
		proxy_ip     String,
		country      LowCardinality(String),
		method       LowCardinality(String),
		host         String,
		path         String,
		query        String,
		status       UInt16,
		blocked      UInt8,
		rule_id      UInt32,
		action       LowCardinality(String),
		user_agent   String,
		duration_ms  UInt32,
		request_id   String,
		proto        LowCardinality(String),
		tls_version  LowCardinality(String),
		tls_cipher   LowCardinality(String),
		tls_sni      String,
		asn_num      UInt32,
		org          String,
		ja3_hash     String,
		ja4          String,
		visitor_id   String,
		bot_score    UInt16,
		cache_status LowCardinality(String)
	) ENGINE = MergeTree
	ORDER BY (ts, real_ip)
	TTL toDateTime(ts) + INTERVAL 1 YEAR`,

	`CREATE TABLE IF NOT EXISTS waf_ip_rules (
		snapshot_at DateTime64(3),
		id          UInt32,
		app_name    LowCardinality(String),
		ip          String,
		rule_type   LowCardinality(String),
		note        String,
		created_at  DateTime64(3)
	) ENGINE = ReplacingMergeTree(snapshot_at) ORDER BY (ip, app_name)`,

	`CREATE TABLE IF NOT EXISTS waf_geo_rules (
		snapshot_at  DateTime64(3),
		id           UInt32,
		app_name     LowCardinality(String),
		country_code LowCardinality(String),
		rule_type    LowCardinality(String),
		created_at   DateTime64(3)
	) ENGINE = ReplacingMergeTree(snapshot_at) ORDER BY (country_code, app_name)`,

	`CREATE TABLE IF NOT EXISTS waf_services (
		snapshot_at      DateTime64(3),
		id               UInt32,
		name             String,
		host             String,
		prefix           String,
		backend          String,
		tls_mode         LowCardinality(String),
		bot_mode         LowCardinality(String),
		cache_enabled    UInt8,
		rate_limit_rps   Float64,
		rate_limit_burst UInt32,
		created_at       DateTime64(3)
	) ENGINE = ReplacingMergeTree(snapshot_at) ORDER BY name`,

	`CREATE TABLE IF NOT EXISTS waf_threat_scores (
		snapshot_at   DateTime64(3),
		ip            String,
		total_score   UInt16,
		autoban_score UInt16,
		bot_score     UInt16,
		asn_score     UInt16,
		geo_score     UInt16,
		ja4_score     UInt16,
		updated_at    DateTime64(3)
	) ENGINE = ReplacingMergeTree(snapshot_at) ORDER BY ip`,

	`CREATE TABLE IF NOT EXISTS waf_ja4_reputation (
		snapshot_at  DateTime64(3),
		ja4          String,
		hits         UInt64,
		blocked_hits UInt64,
		last_seen    DateTime64(3)
	) ENGINE = ReplacingMergeTree(snapshot_at) ORDER BY ja4`,
}

// requestRow maps a RequestLog onto waf_requests' columns. Column names are
// the JSON keys, which is all JSONEachRow needs.
func requestRow(e storage.RequestLog) map[string]any {
	return map[string]any{
		"ts":           e.Timestamp.UTC().Format(chDateTime),
		"app_name":     e.AppName,
		"real_ip":      e.RealIP,
		"proxy_ip":     e.ProxyIP,
		"country":      e.Country,
		"method":       e.Method,
		"host":         e.Host,
		"path":         e.Path,
		"query":        e.Query,
		"status":       e.Status,
		"blocked":      b2i(e.Blocked),
		"rule_id":      e.RuleID,
		"action":       e.Action,
		"user_agent":   e.UserAgent,
		"duration_ms":  e.Duration,
		"request_id":   e.RequestID,
		"proto":        e.Proto,
		"tls_version":  e.TLSVersion,
		"tls_cipher":   e.TLSCipher,
		"tls_sni":      e.TLSSNI,
		"asn_num":      e.ASN,
		"org":          e.Org,
		"ja3_hash":     e.JA3Hash,
		"ja4":          e.JA4,
		"visitor_id":   e.VisitorID,
		"bot_score":    e.BotScore,
		"cache_status": e.CacheStatus,
	}
}

// b2i converts to ClickHouse's UInt8 boolean convention. headers_json is
// deliberately not shipped: it is the largest column by far and can carry
// Authorization/Cookie values.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
