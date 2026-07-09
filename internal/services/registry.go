// Package services holds the set of backend apps the proxy routes to.
// Unlike config.yaml's static apps: list, this is DB-backed and can change
// at runtime (added/edited/removed from the admin UI) without a restart.
package services

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/internal/security/ratelimit"
	"coraza-waf-mod/internal/storage"

	"golang.org/x/crypto/acme/autocert"
)

const serverHeader = "Coraza WAF Mod"

// probeTimeout bounds how long a single reachability check may take, both
// for the one-shot check on add and for the periodic background sweep.
const probeTimeout = 3 * time.Second

// slowBackendThreshold gates the diagnostic log in timedTransport.RoundTrip —
// logging every backend call would be noise, but anything crossing this is
// worth seeing, since it's the leading edge of what could become a 5s dial
// timeout or 10s response-header timeout (see backendTransport below).
const slowBackendThreshold = 1 * time.Second

// timedTransport wraps backendTransport per service so a hung or slow
// backend shows up in the logs with which service and how long, instead of
// just appearing as the request itself stalling with no visible cause.
type timedTransport struct {
	rt   http.RoundTripper
	name string
}

func (t *timedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.rt.RoundTrip(req)
	dur := time.Since(start)
	if err != nil {
		log.Printf("backend [%s] %s %s: failed after %s: %v", t.name, req.Method, req.URL.Path, dur, err)
	} else if dur >= slowBackendThreshold {
		log.Printf("backend [%s] %s %s: slow response, took %s", t.name, req.Method, req.URL.Path, dur)
	}
	return resp, err
}

// backendTransport is shared by every service's reverse proxy. Go's
// http.DefaultTransport has a 30s dial timeout and NO response-header
// timeout at all, so a dead or unresponsive backend can hang a proxied
// request (and the browser connection slot it occupies) for a very long
// time — including for requests that fall through to the fallback service
// (e.g. favicon.ico, robots.txt) when nothing else matches. Bound both so a
// down backend fails fast instead of stalling unrelated page loads.
var backendTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ResponseHeaderTimeout: 10 * time.Second,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// spoofableHostHeaders are client-controllable headers that frameworks and
// caches use to reconstruct the request host/URL. Forwarding them into
// Varnish would let a client poison cache entries with attacker-chosen
// values (classic X-Forwarded-Host cache poisoning), so they are scrubbed
// before a request is handed to the cache layer. The proxy itself never
// relies on them — client identity comes from --trusted-proxies handling.
var spoofableHostHeaders = []string{
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Original-URL",
	"X-Original-Host",
	"X-Rewrite-URL",
	"X-Host",
	"X-HTTP-Host-Override",
	"Forwarded",
}

// Registry holds the current service list plus a pre-built reverse proxy
// per service, refreshed wholesale on Reload.
type Registry struct {
	mu        sync.RWMutex
	list      []storage.Service
	proxies   map[string]*httputil.ReverseProxy
	direct    map[string]*httputil.ReverseProxy // straight-to-backend proxies for the cache-return path
	limiters  map[string]*ratelimit.Limiter     // service name -> per-service limiter (nil if not configured)
	certs     map[string]*tls.Certificate       // host (lowercase) -> uploaded custom cert
	autoHosts map[string]bool                   // host (lowercase) -> true if tls_mode == "auto"

	healthMu sync.RWMutex
	health   map[string]bool // service name -> reachable; absent = not checked yet
}

func New(db *storage.DB) (*Registry, error) {
	r := &Registry{health: make(map[string]bool), limiters: make(map[string]*ratelimit.Limiter)}
	return r, r.Reload(db)
}

// Reload re-reads all services from the DB and rebuilds their reverse
// proxies. Call after adding/editing/removing a service via the UI.
func (r *Registry) Reload(db *storage.DB) error {
	list, err := db.ListServices()
	if err != nil {
		return err
	}
	vcfg, err := db.GetVarnishConfig()
	if err != nil {
		return err
	}

	reg := r // avoid shadowing by the *http.Request param named "r" below
	proxies := make(map[string]*httputil.ReverseProxy, len(list))
	direct := make(map[string]*httputil.ReverseProxy, len(list))
	for _, s := range list {
		target, err := url.Parse(s.Backend)
		if err != nil {
			log.Printf("invalid backend URL for service %q: %v", s.Name, err)
			continue
		}
		name := s.Name
		rp := httputil.NewSingleHostReverseProxy(target)
		if vcfg.Enabled && s.CacheEnabled {
			// Route this service's clean traffic through the local Varnish
			// daemon instead of straight to the backend. The stock director
			// runs first so the path/query are exactly what the backend
			// expects; then the request is re-targeted at Varnish. Cache
			// misses come back to the WAF's cache-return listener (see
			// CacheReturnHandler), which routes to the real backend from
			// this registry — the VCL never needs a per-service backend.
			// Spoofable host headers are scrubbed here — after WAF
			// inspection, before the cache — so no client-controlled host
			// value can ever become part of a cached response.
			// X-Cache-Service keys both the cache-hash partition in the VCL
			// and the return listener's backend lookup; X-Waf-Backend is
			// diagnostic (varnishlog shows where the miss will land).
			stock := rp.Director
			varnishAddr := vcfg.Addr
			backendHost := target.Host
			cacheBySession := s.CacheBySession
			sessionCookieName := s.SessionCookieName
			ttlFloor, ttlCeiling, grace, keep := s.CacheTTLFloor, s.CacheTTLCeiling, s.CacheGrace, s.CacheKeep
			rp.Director = func(req *http.Request) {
				stock(req)
				for _, hn := range spoofableHostHeaders {
					req.Header.Del(hn)
				}
				req.Header.Set("X-Cache-Service", name)
				req.Header.Set("X-Waf-Backend", backendHost)
				// Opt-in session-aware caching (admin toggle, off by default):
				// partition the cache by this service's session cookie value
				// instead of Varnish refusing to cache any cookie-bearing
				// request. The value is hashed rather than forwarded raw —
				// keeps the header short regardless of cookie size, avoids
				// putting a live session token into Varnish's own logs, and
				// sidesteps any header-injection concern from an arbitrary
				// client-controlled cookie value. This request has already
				// passed the full WAF pipeline (challenge gate, WAF
				// inspection) before reaching here, so nothing client-
				// controlled that wasn't already validated is entering the
				// cache key.
				if cacheBySession && sessionCookieName != "" {
					if ck, err := req.Cookie(sessionCookieName); err == nil && ck.Value != "" {
						sum := sha256.Sum256([]byte(ck.Value))
						req.Header.Set("X-Cache-Session", hex.EncodeToString(sum[:16]))
					}
				}
				// Per-service cache tuning (admin-configurable, 0 = unset —
				// the VCL falls back to its own defaults for any header
				// that's absent). Sent as plain seconds; the VCL parses them
				// with std.duration().
				if ttlFloor > 0 {
					req.Header.Set("X-Cache-TTL-Floor", strconv.Itoa(ttlFloor))
				}
				if ttlCeiling > 0 {
					req.Header.Set("X-Cache-TTL-Ceiling", strconv.Itoa(ttlCeiling))
				}
				if grace > 0 {
					req.Header.Set("X-Cache-Grace", strconv.Itoa(grace))
				}
				if keep > 0 {
					req.Header.Set("X-Cache-Keep", strconv.Itoa(keep))
				}
				req.URL.Scheme = "http"
				req.URL.Host = varnishAddr
			}
		}
		rp.Transport = &timedTransport{rt: backendTransport, name: name}
		// Passive health tracking: no separate probe traffic at all — a
		// service is marked down the instant a real proxied request fails
		// to reach it, and healthy again on the next real request that
		// gets a response (matches how nginx/HAProxy/Envoy do "passive"
		// health checks, and how SafeLine avoids logging synthetic probes).
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error [%s]: %v", name, err)
			reg.markHealth(name, false)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}
		// Override whatever Server header the backend sends — the WAF/proxy
		// is what the client actually talks to, so it should identify itself.
		// Also strip security headers from the backend response so the WAF's
		// globally-set versions (from SecurityMiddleware) are the only ones
		// the client sees, avoiding duplicate headers.
		rp.ModifyResponse = func(resp *http.Response) error {
			resp.Header.Set("Server", serverHeader)
			for _, h := range []string{
				"X-Content-Type-Options",
				"X-Frame-Options",
				"X-XSS-Protection",
				"Referrer-Policy",
				"Permissions-Policy",
				"Cross-Origin-Opener-Policy",
				"Strict-Transport-Security",
			} {
				resp.Header.Del(h)
			}
			reg.markHealth(name, true)
			return nil
		}
		proxies[s.Name] = rp

		// Straight-to-backend twin used by the cache-return listener when
		// Varnish fetches a miss. The target deliberately drops any path
		// component of the backend URL: the outer director already joined it
		// before the request went to Varnish, so joining again here would
		// double it (backend /base + /base/x). Health/response hooks are the
		// same as the outer proxy — on the cache path this hop is the one
		// that actually talks to the backend.
		drp := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: target.Scheme, Host: target.Host})
		drp.Transport = &timedTransport{rt: backendTransport, name: name}
		drp.ErrorHandler = rp.ErrorHandler
		drp.ModifyResponse = rp.ModifyResponse
		direct[s.Name] = drp
	}

	certs := make(map[string]*tls.Certificate)
	autoHosts := make(map[string]bool)
	for _, s := range list {
		if s.Host == "" {
			continue // TLS only applies to Host-matched services (SNI needs a domain)
		}
		// Strip any accidental scheme prefix (http://, https://) that may have
		// been stored before the sanitizeHost fix was in place.
		rawHost := s.Host
		if i := strings.Index(rawHost, "://"); i >= 0 {
			rawHost = rawHost[i+3:]
		}
		host := strings.ToLower(strings.TrimRight(rawHost, "/"))
		switch s.TLSMode {
		case "custom":
			certPath, keyPath := s.TLSCertPath, s.TLSKeyPath
			if s.CertID > 0 {
				// Pool cert: look up paths from the certificates table.
				poolCert, err := db.GetCertificate(s.CertID)
				if err != nil {
					log.Printf("pool cert for service %q (cert_id=%d): %v", s.Name, s.CertID, err)
					continue
				}
				certPath, keyPath = poolCert.CertPath, poolCert.KeyPath
			}
			if certPath == "" || keyPath == "" {
				continue
			}
			cert, err := LoadCertificate(certPath, keyPath)
			if err != nil {
				log.Printf("load custom TLS cert for service %q: %v", s.Name, err)
				continue
			}
			certs[host] = cert
		case "auto":
			autoHosts[host] = true
		}
	}

	// Build per-service rate limiters for any service that has RPS configured.
	newLimiters := make(map[string]*ratelimit.Limiter, len(list))
	for _, s := range list {
		if s.RateLimitRPS > 0 {
			burst := s.RateLimitBurst
			if burst <= 0 {
				burst = int(s.RateLimitRPS) * 2
			}
			newLimiters[s.Name] = ratelimit.NewWithParams(s.RateLimitRPS, burst)
		}
	}

	r.mu.Lock()
	oldLimiters := r.limiters
	r.list = list
	r.proxies = proxies
	r.direct = direct
	r.limiters = newLimiters
	r.certs = certs
	r.autoHosts = autoHosts
	r.mu.Unlock()

	// Stop old janitor goroutines after the swap so in-flight checks still work.
	for _, l := range oldLimiters {
		l.Stop()
	}

	// Drop health entries for services that no longer exist, so a removed
	// (or renamed) service can't leave a stale dot behind.
	valid := make(map[string]bool, len(list))
	for _, s := range list {
		valid[s.Name] = true
	}
	r.healthMu.Lock()
	for name := range r.health {
		if !valid[name] {
			delete(r.health, name)
		}
	}
	r.healthMu.Unlock()

	return nil
}

// AllowService checks the per-service rate limiter for the named service and
// client IP. Returns a zero Result (Allowed: true, Limit: 0) if the service
// has no per-service limit configured. Falls through — it does not replace
// the global limiter in proxy/handler.go.
func (r *Registry) AllowService(name, ip string) ratelimit.Result {
	r.mu.RLock()
	l := r.limiters[name]
	r.mu.RUnlock()
	if l == nil {
		return ratelimit.Result{Allowed: true}
	}
	return l.Allow(ip)
}

// PrefixMatch reports whether path falls under prefix at a path-segment
// boundary: prefix "/api" matches "/api" and "/api/users" but not "/apiary"
// or "/api-v2" — a raw HasPrefix would misroute those to the API backend. A
// trailing slash on the configured prefix is ignored, and a bare "/"
// matches every path.
func PrefixMatch(path, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// StripPrefix removes a PrefixMatch-ed prefix from path, returning "/" for
// an exact match so the backend always sees a rooted path. Paths that don't
// fall under prefix are returned unchanged.
func StripPrefix(path, prefix string) string {
	if !PrefixMatch(path, prefix) {
		return path
	}
	rest := strings.TrimPrefix(path, strings.TrimSuffix(prefix, "/"))
	if rest == "" {
		return "/"
	}
	return rest
}

// Match picks the service for a request. Path-prefix rules are more
// specific than a host-wide rule, so the longest matching Prefix wins first
// (mirrors nginx: location blocks beat a bare server_name default) — this
// lets a host-wide catch-all service and path-scoped services coexist on
// the same host. Prefixes only match at path-segment boundaries (see
// PrefixMatch). Only if no Prefix matches does an exact Host match apply,
// falling back to the first configured service if nothing matches at all.
// Returns nil if no services are configured.
func (r *Registry) Match(host, path string) *storage.Service {
	host = strings.ToLower(strings.Split(host, ":")[0])

	r.mu.RLock()
	defer r.mu.RUnlock()

	var best *storage.Service
	for i := range r.list {
		s := &r.list[i]
		if s.Prefix != "" && PrefixMatch(path, s.Prefix) {
			if best == nil || len(s.Prefix) > len(best.Prefix) {
				best = s
			}
		}
	}
	if best != nil {
		return best
	}

	for i := range r.list {
		s := &r.list[i]
		if s.Host != "" && strings.ToLower(s.Host) == host {
			return s
		}
	}
	if len(r.list) > 0 {
		return &r.list[0]
	}
	return nil
}

// Proxy returns the reverse proxy for the named service.
func (r *Registry) Proxy(name string) (*httputil.ReverseProxy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rp, ok := r.proxies[name]
	return rp, ok
}

// CacheReturnHandler serves the loopback listener Varnish fetches cache
// misses from (VarnishConfig.ReturnAddr). Requests arriving here already
// passed the full WAF pipeline on the way in — the outer proxy tagged them
// with X-Cache-Service before handing them to Varnish — so this hop only
// looks up that service and proxies straight to its backend. It must never
// be reachable from outside the host: the listener binds loopback, and the
// peer check below is defense in depth against accidental rebinding.
func (r *Registry) CacheReturnHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		name := req.Header.Get("X-Cache-Service")
		r.mu.RLock()
		rp := r.direct[name]
		r.mu.RUnlock()
		if rp == nil {
			// Unknown or missing service tag: either Varnish got traffic
			// that didn't come from the WAF, or the service was removed
			// between the outer hop and the miss fetch.
			http.Error(w, "unknown service", http.StatusNotFound)
			return
		}
		req.Header.Del("X-Waf-Backend")
		rp.ServeHTTP(w, req)
	})
}

// List returns a snapshot of all configured services.
func (r *Registry) List() []storage.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]storage.Service, len(r.list))
	copy(out, r.list)
	return out
}

// Validate checks that a backend URL is well-formed and absolute, used by
// the admin UI before saving a new service.
func Validate(backend string) error {
	u, err := url.Parse(backend)
	if err != nil {
		return fmt.Errorf("invalid backend URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("backend URL must be absolute (e.g. http://127.0.0.1:3000)")
	}
	return nil
}

// Probe checks whether a backend URL is currently reachable. Any HTTP
// response (even 404/500) counts as reachable — we're checking connectivity,
// not whether the backend has a route at "/". Only a dial/timeout failure
// counts as unreachable. Redirects are not followed: the admin-entered URL
// is the only target this probe should ever contact.
func Probe(backend string) error {
	client := &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, backend, nil)
	if err != nil {
		return fmt.Errorf("invalid backend URL: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("backend not reachable: %w", err)
	}
	resp.Body.Close()
	return nil
}

// safeServiceNameForBan matches the conservative character set allowed to be
// concatenated into a Varnish ban() expression (see Purge) — Varnish's ban
// grammar has no escaping mechanism for the compared value (the same
// unescaped-concatenation pattern is what Varnish's own docs show), so a
// service name containing e.g. a quote or "||" could widen or break the ban
// expression. Service names aren't otherwise character-restricted, so this
// is enforced here rather than at service-creation time.
var safeServiceNameForBan = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Purge invalidates every object cached for one service by sending a PURGE
// request directly to Varnish's client port over loopback — the WAF issuing
// it, never client traffic, same trust model as the cache-return listener
// (see main.go's startCacheReturn). deploy/varnish/default.vcl bans on
// obj.http.X-Cache-Service, the same header the outer Director already tags
// every cached object with, so this only affects objects belonging to
// serviceName. Intended for the admin UI's "Purge" button, e.g. right after
// deploying new content to a backend.
func Purge(vcfg storage.VarnishConfig, serviceName string) error {
	if !vcfg.Enabled {
		return fmt.Errorf("varnish integration is not enabled")
	}
	if !safeServiceNameForBan.MatchString(serviceName) {
		return fmt.Errorf("service name contains characters not safe to purge by")
	}
	host, _, err := net.SplitHostPort(vcfg.Addr)
	if err != nil || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		return fmt.Errorf("refusing to purge a non-loopback varnish address")
	}

	client := &http.Client{Timeout: probeTimeout}
	req, err := http.NewRequest("PURGE", "http://"+vcfg.Addr+"/", nil)
	if err != nil {
		return fmt.Errorf("invalid varnish address: %w", err)
	}
	req.Header.Set("X-Cache-Service", serviceName)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("varnish not reachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("varnish returned %s for purge", resp.Status)
	}
	return nil
}

// IsHealthy returns the last known reachability of a service, tracked
// passively from real proxied traffic (see Reload's ErrorHandler/
// ModifyResponse hooks) — no separate probe requests are ever sent. known is
// false if no real request has been proxied to it yet, e.g. a brand new or
// fully idle service.
func (r *Registry) IsHealthy(name string) (healthy, known bool) {
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()
	healthy, known = r.health[name]
	return healthy, known
}

// markHealth records the outcome of a real proxied request to a service.
func (r *Registry) markHealth(name string, healthy bool) {
	r.healthMu.Lock()
	r.health[name] = healthy
	r.healthMu.Unlock()
}

// ── TLS ──────────────────────────────────────────────────────────────────────

// GetCertificateFunc returns a tls.Config.GetCertificate callback that picks
// a certificate by SNI hostname: a per-service uploaded cert first, then
// autocert (if am is non-nil and the host is configured for "auto" mode).
// Returns an error if neither applies, failing that TLS handshake cleanly
// without affecting other domains that do have certs configured.
func (r *Registry) GetCertificateFunc(am *autocert.Manager) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host := strings.ToLower(hello.ServerName)

		r.mu.RLock()
		cert, hasCustom := r.certs[host]
		_, isAuto := r.autoHosts[host]
		r.mu.RUnlock()

		if hasCustom {
			return cert, nil
		}
		if isAuto && am != nil {
			return am.GetCertificate(hello)
		}
		return nil, fmt.Errorf("no certificate configured for %q", hello.ServerName)
	}
}

// HostPolicy returns an autocert.HostPolicy that allows exactly the hosts of
// services currently configured with tls_mode = "auto" — autocert refuses to
// request a cert for anything this rejects.
func (r *Registry) HostPolicy() autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		r.mu.RLock()
		_, ok := r.autoHosts[strings.ToLower(host)]
		r.mu.RUnlock()
		if !ok {
			return fmt.Errorf("host %q is not configured for automatic TLS", host)
		}
		return nil
	}
}
