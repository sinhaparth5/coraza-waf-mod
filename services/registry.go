// Package services holds the set of backend apps the proxy routes to.
// Unlike config.yaml's static apps: list, this is DB-backed and can change
// at runtime (added/edited/removed from the admin UI) without a restart.
package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/ratelimit"
	"coraza-waf-mod/storage"

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

// Registry holds the current service list plus a pre-built reverse proxy
// per service, refreshed wholesale on Reload.
type Registry struct {
	mu        sync.RWMutex
	list      []storage.Service
	proxies   map[string]*httputil.ReverseProxy
	limiters  map[string]*ratelimit.Limiter // service name -> per-service limiter (nil if not configured)
	certs     map[string]*tls.Certificate   // host (lowercase) -> uploaded custom cert
	autoHosts map[string]bool               // host (lowercase) -> true if tls_mode == "auto"

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

	reg := r // avoid shadowing by the *http.Request param named "r" below
	proxies := make(map[string]*httputil.ReverseProxy, len(list))
	for _, s := range list {
		target, err := url.Parse(s.Backend)
		if err != nil {
			log.Printf("invalid backend URL for service %q: %v", s.Name, err)
			continue
		}
		name := s.Name
		rp := httputil.NewSingleHostReverseProxy(target)
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
		rp.ModifyResponse = func(resp *http.Response) error {
			resp.Header.Set("Server", serverHeader)
			reg.markHealth(name, true)
			return nil
		}
		proxies[s.Name] = rp
	}

	certs := make(map[string]*tls.Certificate)
	autoHosts := make(map[string]bool)
	for _, s := range list {
		if s.Host == "" {
			continue // TLS only applies to Host-matched services (SNI needs a domain)
		}
		host := strings.ToLower(s.Host)
		switch s.TLSMode {
		case "custom":
			if s.TLSCertPath == "" || s.TLSKeyPath == "" {
				continue
			}
			cert, err := LoadCertificate(s.TLSCertPath, s.TLSKeyPath)
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

// Match picks the service for a request. Path-prefix rules are more
// specific than a host-wide rule, so the longest matching Prefix wins first
// (mirrors nginx: location blocks beat a bare server_name default) — this
// lets a host-wide catch-all service and path-scoped services coexist on
// the same host. Only if no Prefix matches does an exact Host match apply,
// falling back to the first configured service if nothing matches at all.
// Returns nil if no services are configured.
func (r *Registry) Match(host, path string) *storage.Service {
	host = strings.ToLower(strings.Split(host, ":")[0])

	r.mu.RLock()
	defer r.mu.RUnlock()

	var best *storage.Service
	for i := range r.list {
		s := &r.list[i]
		if s.Prefix != "" && strings.HasPrefix(path, s.Prefix) {
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
// counts as unreachable.
func Probe(backend string) error {
	client := &http.Client{Timeout: probeTimeout}
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
