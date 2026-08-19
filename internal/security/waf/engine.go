package waf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"coraza-waf-mod/internal/config"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
)

type Engine struct {
	waf     coraza.WAF
	enabled bool
	cache   *verdictCache // nil when enabled == false
}

type Result struct {
	Blocked bool
	Status  int
	RuleID  int
	Action  string
}

// requestBodyLimit is the SecRequestBodyLimit value passed to Coraza and the
// most Check ever buffers of a *multipart* request body in memory (13107200 =
// the coraza.conf-recommended default, ~12.5 MiB). Multipart is the one shape
// that can carry a large body cheaply: Coraza's multipart processor routes
// file parts to FILES/FILES_TMP_NAMES rather than ARGS, so CRS's argument
// rules never scan the payload — a 3.5 MiB upload measures at ~28ms.
const requestBodyLimit = 13107200

// noFilesBodyLimit is the same idea for every other inspectable body — the
// limit ModSecurity spells SecRequestBodyNoFilesLimit, and the reason that
// directive exists: a body with no file parts is parsed into ARGS in full, and
// CRS then runs ~200 rules over every one of them.
//
// It has to be enforced here because Coraza does not implement the directive.
// It parses SecRequestBodyNoFilesLimit and then ignores it (see the TODO at
// internal/corazawaf/waf.go referencing corazawaf/coraza#896), which is why
// coraza.conf-recommended ships the line commented out with a note saying so.
// This package used to set it anyway, which read like a 128 KiB cap was in
// force when the only limit that ever applied was the 12.5 MiB one above.
//
// The cost this bounds is not theoretical: measured against CRS 4, a
// non-multipart body costs roughly 2.8s and 800 MiB of allocations at 128 KiB,
// 30s and 6.4 GiB at 1 MiB, and 52s and 4.4 GiB at 3.5 MiB. The curve is
// superlinear and it does not care whether the bytes are an attack or a
// holiday photo.
const noFilesBodyLimit = 131072

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
SecRequestBodyLimitAction Reject
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

	return &Engine{waf: w, enabled: true, cache: newVerdictCache(verdictCacheTTL, verdictCacheCapacity)}, nil
}

// bodyInspection says what Check should do with a request body of a given
// content type.
type bodyInspection int

const (
	// inspectSkip streams the body straight to the backend, uninspected.
	inspectSkip bodyInspection = iota
	// inspectNoFiles buffers and inspects up to noFilesBodyLimit.
	inspectNoFiles
	// inspectFiles buffers and inspects up to requestBodyLimit.
	inspectFiles
)

// inspectionFor decides, from the declared Content-Type alone, whether a body
// is worth handing to the rule engine.
//
// The reason this gate has to exist is a collaboration between Coraza and CRS
// that nobody chose. Coraza infers a body processor for exactly two content
// types — x-www-form-urlencoded and multipart/form-data — and leaves it unset
// for everything else. CRS rule 901340 then matches "processor is not
// URLENCODED|MULTIPART|XML|JSON" and fires ctl:forceRequestBodyVariable=On,
// and Coraza's response to that flag is to default the processor to
// URLENCODED. So a PDF, a video, or an S3 PUT payload gets parsed as an HTML
// form: 3.5 MiB of binary contains an "&" roughly every 256 bytes, which is
// ~14,000 junk ARGS entries for CRS to scan, each transformation of each one
// cached as a full string copy for the length of the phase. That is where the
// minute of latency and the 2 GB of resident memory came from.
//
// Skipping those bodies is a real trade, not a free win: a client that
// declares application/octet-stream on a payload the backend then parses as a
// form has evaded body inspection. Two things bound it. CRS 920420 already
// flags content types outside its allow-list at PL1, so the declaration is not
// free; and the alternative — inspecting the bytes — does not work either,
// since binary data scores 830 against CRS's XSS/SQLi/RCE detectors and is
// refused outright. The status quo was not "these uploads are inspected", it
// was "these uploads take a minute and are then rejected as an attack".
//
// An absent Content-Type is inspected, deliberately: otherwise omitting the
// header would be the bypass.
func inspectionFor(contentType string) bodyInspection {
	mediaType := contentType
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		return inspectFiles
	case mediaType == "":
		return inspectNoFiles
	case strings.HasPrefix(mediaType, "text/"):
		return inspectNoFiles
	case strings.HasSuffix(mediaType, "+json"), strings.HasSuffix(mediaType, "+xml"):
		return inspectNoFiles
	case mediaType == "application/x-www-form-urlencoded",
		mediaType == "application/json",
		mediaType == "application/xml",
		mediaType == "application/graphql",
		mediaType == "application/javascript",
		mediaType == "application/ecmascript":
		return inspectNoFiles
	default:
		return inspectSkip
	}
}

// Check runs r through the WAF using clientIP as the real remote address.
// A body the rule engine will inspect is buffered so the proxy can read it
// again afterwards; one it will not (see inspectionFor) is left on the socket
// and streams straight through. Repeated byte-identical requests (same
// method/host/path/query/body — a flood or scanner replaying the same probe)
// can skip the Coraza transaction entirely and reuse a recent verdict; see
// verdictcache.go.
func (e *Engine) Check(r *http.Request, clientIP string) (*Result, error) {
	if !e.enabled {
		return &Result{}, nil
	}

	// Buffer body up front — never more than the limit for its kind plus one
	// byte: an uncapped io.ReadAll would allocate a whole multi-GB (or
	// chunked, no-Content-Length) upload in RAM before any limit was
	// consulted, so a handful of concurrent large POSTs could exhaust
	// memory. The extra byte is what distinguishes "exactly at the limit"
	// from "over it".
	//
	// A body the rule engine will not look at is never touched at all: r.Body
	// is left as the socket, so the upload streams to the backend instead of
	// landing in this process first.
	var body []byte
	hadBody := r.Body != nil && r.Body != http.NoBody
	mode := inspectSkip
	if hadBody {
		mode = inspectionFor(r.Header.Get("Content-Type"))
	}

	// buffered means `body` holds the request in full — trivially true when
	// there is no body at all. It gates the verdict cache below.
	buffered := !hadBody
	if hadBody && mode != inspectSkip {
		limit := int64(noFilesBodyLimit)
		if mode == inspectFiles {
			limit = requestBodyLimit
		}
		orig := r.Body
		b, err := io.ReadAll(io.LimitReader(orig, limit+1))
		if err != nil {
			return nil, fmt.Errorf("reading request body: %w", err)
		}
		body = b
		switch {
		case int64(len(body)) <= limit:
			r.Body = io.NopCloser(bytes.NewReader(body))
			buffered = true
		case mode == inspectNoFiles:
			// Coraza cannot enforce this one for us (see noFilesBodyLimit),
			// so the refusal is issued here — matching, not inventing, the
			// SecRequestBodyLimitAction Reject posture the multipart path
			// gets from Coraza itself. r.Body is restored so the request
			// stays well-formed for whatever unwinds it.
			r.Body = &bodyReplay{Reader: io.MultiReader(bytes.NewReader(body), orig), Closer: orig}
			return &Result{Blocked: true, Status: http.StatusRequestEntityTooLarge, Action: "deny"}, nil
		default:
			// Over-limit multipart with more bytes still on the wire: chain
			// the buffered head with the unread tail so the proxy can forward
			// the full upload if the configured action is ProcessPartial
			// rather than Reject.
			r.Body = &bodyReplay{Reader: io.MultiReader(bytes.NewReader(body), orig), Closer: orig}
		}
	}

	// Only fingerprint a body held in full. A truncated one takes the rare
	// ProcessPartial/Reject path above, where the outcome depends on exactly
	// how much was on the wire rather than on its buffered head; an
	// uninspected one was never read at all, so a fingerprint over it would
	// key two different uploads to the same verdict.
	var cacheKey string
	if buffered && fingerprintEligible(r) {
		cacheKey = fingerprint(r, body)
		if cached, ok := e.cache.get(cacheKey); ok {
			return &cached, nil
		}
	}

	result, err := e.evaluate(r, clientIP, body, hadBody && mode != inspectSkip)
	if err != nil {
		return nil, err
	}
	if cacheKey != "" {
		e.cache.put(cacheKey, *result)
	}
	return result, nil
}

// evaluate runs the actual Coraza transaction against the already-buffered
// body. Split out of Check so the verdict-cache fast path above never has to
// touch a coraza.Transaction at all.
func (e *Engine) evaluate(r *http.Request, clientIP string, body []byte, inspectBody bool) (*Result, error) {
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

	if inspectBody {
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
