package waf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

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

func New(cfg config.WAFConfig) (*Engine, error) {
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
	directives := `
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecDebugLogLevel 0
`

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

	// Buffer body so Coraza can inspect it and the proxy can still forward it.
	if r.Body != nil && r.Body != http.NoBody {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("reading request body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

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
