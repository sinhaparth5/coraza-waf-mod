package services

import (
	"context"
	"log"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"palisade/internal/storage"
)

// passiveCooldown is how long a backend that failed a real request sits out
// of the rotation when its service has no active health check to bring it
// back sooner. After it, the backend gets traffic again and either stays in
// (a response) or goes back out (another failure).
const passiveCooldown = 10 * time.Second

// backendHealth is one backend's rotation state. It lives in the Registry
// keyed by service and backend URL, so it survives Reload.
type backendHealth struct {
	downUntil atomic.Int64 // unix nanos; the backend is out of rotation before this
	known     atomic.Bool  // false until any request or check has reached it
}

func (h *backendHealth) available(now int64) bool { return now >= h.downUntil.Load() }

func (h *backendHealth) markUp() {
	h.known.Store(true)
	h.downUntil.Store(0)
}

func (h *backendHealth) markDown(until int64) {
	h.known.Store(true)
	h.downUntil.Store(until)
}

// BackendStatus is one backend's health as shown on /admin/services.
type BackendStatus struct {
	URL     string
	Healthy bool
	Known   bool
}

type upstream struct {
	raw      string
	base     *url.URL // scheme+host, for active checks
	rp       *httputil.ReverseProxy
	health   *backendHealth
	inflight atomic.Int64
}

// pool balances one service's traffic across its backends. A single-backend
// service is a pool of one, so there is only one proxy path.
type pool struct {
	name      string
	leastConn bool
	active    bool // an active health check brings failed backends back
	ups       []*upstream
	next      atomic.Uint64
}

type attemptKey struct{}

// attempt rides in the request context so a backend's ErrorHandler can
// retry the original request (not ReverseProxy's rewritten copy) once.
type attempt struct {
	req     *http.Request
	retried bool
}

func newPool(s storage.Service, health func(raw string) *backendHealth, stripPath bool, modify func(*http.Response) error) *pool {
	p := &pool{name: s.Name, leastConn: s.LBPolicy == "least_conn", active: s.HealthPath != ""}
	for _, raw := range s.Backends() {
		target, err := url.Parse(raw)
		if err != nil || target.Host == "" {
			log.Printf("invalid backend URL %q for service %q: %v", raw, s.Name, err)
			continue
		}
		base := &url.URL{Scheme: target.Scheme, Host: target.Host}
		if stripPath {
			// Varnish's miss fetch already carries the joined backend
			// path (see Reload); joining again would double it.
			target = base
		}
		u := &upstream{raw: raw, base: base, health: health(raw)}
		u.rp = httputil.NewSingleHostReverseProxy(target)
		u.rp.Transport = &timedTransport{rt: backendTransport, name: s.Name}
		u.rp.ModifyResponse = func(resp *http.Response) error {
			u.health.markUp()
			return modify(resp)
		}
		u.rp.ErrorHandler = func(w http.ResponseWriter, out *http.Request, err error) {
			log.Printf("proxy error [%s → %s]: %v", p.name, u.raw, err)
			if out.Context().Err() == nil { // a client hanging up says nothing about the backend
				until := time.Now().Add(passiveCooldown).UnixNano()
				if p.active {
					until = math.MaxInt64
				}
				u.health.markDown(until)
			}
			if a, ok := out.Context().Value(attemptKey{}).(*attempt); ok && !a.retried && retryable(a.req) {
				a.retried = true
				p.serve(w, a.req, u)
				return
			}
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}
		p.ups = append(p.ups, u)
	}
	if len(p.ups) == 0 {
		return nil
	}
	return p
}

// retryable: only bodiless GET/HEAD are replayed on another backend, since
// the failed attempt may have reached the backend before erroring.
func retryable(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.ContentLength == 0 && r.Context().Err() == nil
}

func (p *pool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &attempt{}
	a.req = r.WithContext(context.WithValue(r.Context(), attemptKey{}, a))
	p.serve(w, a.req, nil)
}

func (p *pool) serve(w http.ResponseWriter, r *http.Request, skip *upstream) {
	u := p.pick(skip)
	if u == nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	u.inflight.Add(1)
	defer u.inflight.Add(-1)
	u.rp.ServeHTTP(w, r)
}

// pick chooses a backend in rotation, other than skip. With every backend
// out of rotation it falls back to all of them: a guess beats a certain 502.
func (p *pool) pick(skip *upstream) *upstream {
	now := time.Now().UnixNano()
	cands := make([]*upstream, 0, len(p.ups))
	for _, u := range p.ups {
		if u != skip && u.health.available(now) {
			cands = append(cands, u)
		}
	}
	if len(cands) == 0 {
		for _, u := range p.ups {
			if u != skip {
				cands = append(cands, u)
			}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	start := int(p.next.Add(1) % uint64(len(cands)))
	if !p.leastConn {
		return cands[start]
	}
	// Scan from the round-robin position so ties still rotate.
	best := cands[start]
	for i := 1; i < len(cands); i++ {
		if u := cands[(start+i)%len(cands)]; u.inflight.Load() < best.inflight.Load() {
			best = u
		}
	}
	return best
}

// runChecks probes every backend's path every interval until stop closes.
// Any 2xx/3xx puts a backend back in rotation; anything else, or no
// answer, takes it out until a later check passes.
func (p *pool) runChecks(path string, interval time.Duration, stop <-chan struct{}) {
	client := &http.Client{
		Transport:     backendTransport,
		Timeout:       probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	check := func(u *upstream) {
		resp, err := client.Get(u.base.String() + path)
		if err != nil {
			u.health.markDown(math.MaxInt64)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			u.health.markUp()
		} else {
			u.health.markDown(math.MaxInt64)
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		var wg sync.WaitGroup
		for _, u := range p.ups {
			wg.Go(func() { check(u) })
		}
		wg.Wait()
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}
