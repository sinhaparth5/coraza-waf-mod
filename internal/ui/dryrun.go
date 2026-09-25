package ui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"coraza-waf-mod/internal/security/waf"
	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

// WAF rule dry-run (issue #8): replay recently logged requests through two
// throwaway engines — today's global config, and the same plus a candidate
// rule snippet — and report every request whose verdict differs. Neither
// engine is ever handed to proxy.Handler, so a bad candidate can't touch
// live traffic.

const (
	dryRunDefaultLimit = 500
	dryRunMaxLimit     = 2000
)

// dryRunMu allows one dry run at a time: each run compiles two full CRS
// engines, so concurrent runs would multiply that memory for no benefit.
var dryRunMu sync.Mutex

type dryRunHit struct {
	ID      int
	AppName string
	Method  string
	Host    string
	Target  string // path + query, as logged
	Before  waf.Result
	After   waf.Result
}

// replayRequest rebuilds a logged request for WAF inspection. Bodies are
// never logged, so the replay covers method, URL and headers only.
func replayRequest(l storage.RequestLog) *http.Request {
	r := &http.Request{
		Method:     l.Method,
		URL:        &url.URL{Path: l.Path, RawQuery: l.Query},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       l.Host,
		Header:     http.Header{},
		Body:       http.NoBody,
		RemoteAddr: l.RealIP + ":0",
	}
	r.RequestURI = r.URL.RequestURI() // what the engine hands Coraza
	var hdrs map[string]string
	if json.Unmarshal([]byte(l.HeadersJSON), &hdrs) == nil {
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
	}
	return r
}

// dryRunDiff returns the logs whose blocked/rule verdict differs between the
// two engines, in the order given.
func dryRunDiff(base, cand *waf.Engine, logs []storage.RequestLog) ([]dryRunHit, error) {
	var hits []dryRunHit
	for _, l := range logs {
		before, err := base.Check(replayRequest(l), l.RealIP)
		if err != nil {
			return nil, err
		}
		after, err := cand.Check(replayRequest(l), l.RealIP)
		if err != nil {
			return nil, err
		}
		if before.Blocked == after.Blocked && before.RuleID == after.RuleID {
			continue
		}
		target := l.Path
		if l.Query != "" {
			target += "?" + l.Query
		}
		hits = append(hits, dryRunHit{ID: l.ID, AppName: l.AppName, Method: l.Method, Host: l.Host, Target: target, Before: *before, After: *after})
	}
	return hits, nil
}

// WAFDryRun handles POST /admin/waf-rules/dry-run.
func (h *Handler) WAFDryRun(c echo.Context) error {
	render := func(data map[string]any) error {
		return h.renderPartial(c, "waf_rules", "waf-dryrun-result", data)
	}
	candidate := strings.TrimSpace(c.FormValue("rules"))
	if candidate == "" {
		return render(map[string]any{"Error": "Paste at least one rule to test."})
	}
	if !h.cfg.WAF.Enabled {
		return render(map[string]any{"Error": "The WAF is disabled, so there is nothing to compare against."})
	}
	limit, err := strconv.Atoi(c.FormValue("limit"))
	if err != nil || limit < 1 {
		limit = dryRunDefaultLimit
	}
	limit = min(limit, dryRunMaxLimit)

	if !dryRunMu.TryLock() {
		return render(map[string]any{"Error": "Another dry run is in progress — try again in a moment."})
	}
	defer dryRunMu.Unlock()

	ids, err := h.db.GetDisabledWAFRuleIDs()
	if err != nil {
		return err
	}
	base, err := waf.New(h.cfg.WAF, ids)
	if err != nil {
		return render(map[string]any{"Error": "Building the current engine failed: " + err.Error()})
	}
	cand, err := waf.NewWithDirectives(h.cfg.WAF, ids, candidate)
	if err != nil {
		return render(map[string]any{"Error": "Candidate rules don't compile: " + err.Error()})
	}
	logs, err := h.db.ListReplayRequests(limit)
	if err != nil {
		return err
	}
	hits, err := dryRunDiff(base, cand, logs)
	if err != nil {
		return render(map[string]any{"Error": "Replay failed: " + err.Error()})
	}
	return render(map[string]any{"Replayed": len(logs), "Hits": hits})
}
