package waf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"coraza-waf-mod/config"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
)

type Engine struct {
	waf     coraza.WAF
	enabled bool
}

type Result struct {
	Blocked bool
	Status  int
	RuleID  int
	Action  string
}

// requestBodyLimit is the SecRequestBodyLimit value passed to Coraza and the
// most Check ever buffers of a request body in memory (13107200 = the
// coraza.conf-recommended default, ~12.5 MiB).
const requestBodyLimit = 13107200

// bodyReplay lets the proxy forward a body Check only partially buffered:
// it replays the inspected head from memory, then streams the unread
// remainder straight from the original request body.
type bodyReplay struct {
	io.Reader
	io.Closer
}

// New builds a WAF engine with the OWASP CRS loaded.
// disabledRuleIDs lists CRS rule IDs to suppress via SecRuleRemoveById — used
// to handle false positives without editing config files or restarting.
func New(cfg config.WAFConfig, disabledRuleIDs []int) (*Engine, error) {
	if !cfg.Enabled {
		return &Engine{enabled: false}, nil
	}

	// Base directives + OWASP CRS (embedded via coraza-coreruleset).
	//
	// Our own overrides must come AFTER the includes: @coraza.conf-recommended
	// sets "SecRuleEngine DetectionOnly" (and "SecResponseBodyAccess On") as a
	// safe-by-default, and directives apply in the order they're parsed, so
	// anything we set before the includes gets silently clobbered back to
	// those defaults — every rule still matches and scores, but nothing is
	// ever actually blocked.
	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit %d
SecRequestBodyNoFilesLimit 131072
SecDebugLogLevel 0
`, requestBodyLimit)
	if len(disabledRuleIDs) > 0 {
		ids := make([]string, len(disabledRuleIDs))
		for i, id := range disabledRuleIDs {
			ids[i] = strconv.Itoa(id)
		}
		directives += "SecRuleRemoveById " + strings.Join(ids, " ") + "\n"
	}

	wafCfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives)

	// Load any extra custom rules on top of CRS.
	if cfg.RulesDir != "" {
		wafCfg = wafCfg.WithDirectives(fmt.Sprintf(`Include "%s/*.conf"`, cfg.RulesDir))
	}

	w, err := coraza.NewWAF(wafCfg)
	if err != nil {
		return nil, fmt.Errorf("coraza init: %w", err)
	}

	return &Engine{waf: w, enabled: true}, nil
}

// Check runs r through the WAF using clientIP as the real remote address.
// It buffers the request body so it can be read again by the proxy after inspection.
func (e *Engine) Check(r *http.Request, clientIP string) (*Result, error) {
	if !e.enabled {
		return &Result{}, nil
	}

	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	tx.ProcessConnection(clientIP, 0, "", 0)
	tx.ProcessURI(r.RequestURI, r.Method, r.Proto)

	for name, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(name, v)
		}
	}
	// Ensure Host is always set even when it's not in r.Header.
	tx.AddRequestHeader("Host", r.Host)

	if it := tx.ProcessRequestHeaders(); it != nil {
		return &Result{Blocked: true, Status: it.Status, RuleID: it.RuleID, Action: it.Action}, nil
	}

	// Buffer body so Coraza can inspect it and the proxy can still forward
	// it — but never more than the WAF's own body limit plus one byte: an
	// uncapped io.ReadAll would allocate a whole multi-GB (or chunked,
	// no-Content-Length) upload in RAM before SecRequestBodyLimit was ever
	// consulted, so a handful of concurrent large POSTs could exhaust
	// memory. The extra byte lets Coraza see that the body exceeds its
	// limit and apply SecRequestBodyLimitAction itself (Reject → 413 with
	// the recommended config), keeping the limit logic in one place.
	if r.Body != nil && r.Body != http.NoBody {
		orig := r.Body
		body, err := io.ReadAll(io.LimitReader(orig, requestBodyLimit+1))
		if err != nil {
			return nil, fmt.Errorf("reading request body: %w", err)
		}
		if len(body) > requestBodyLimit {
			// Over-limit body with more bytes still on the wire: chain the
			// buffered head with the unread tail so the proxy can forward
			// the full upload if the configured action is ProcessPartial
			// rather than Reject.
			r.Body = &bodyReplay{Reader: io.MultiReader(bytes.NewReader(body), orig), Closer: orig}
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		if it, _, err := tx.WriteRequestBody(body); err != nil {
			return nil, fmt.Errorf("waf body write: %w", err)
		} else if it != nil {
			return &Result{Blocked: true, Status: it.Status, RuleID: it.RuleID, Action: it.Action}, nil
		}
	}

	it, err := tx.ProcessRequestBody()
	if err != nil {
		return nil, fmt.Errorf("waf body process: %w", err)
	}
	if it != nil {
		return &Result{Blocked: true, Status: it.Status, RuleID: it.RuleID, Action: it.Action}, nil
	}

	return &Result{}, nil
}
