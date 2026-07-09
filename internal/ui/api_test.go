package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/security/blocklist"
	"coraza-waf-mod/internal/services"
	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

// newTestAPIHandler builds a Handler backed by a real (temp-file) SQLite DB,
// services.Registry, and blocklist.IPBlocklist — the same trio api.go's
// handlers touch — and registers the /api/v1 group on a real Echo instance,
// so requests exercise the full auth-middleware-to-DB path via httptest
// rather than a server process (see CLAUDE.md: don't start the server to verify).
func newTestAPIHandler(t *testing.T) (*Handler, *echo.Echo) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	registry, err := services.New(db)
	if err != nil {
		t.Fatal(err)
	}
	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		t.Fatal(err)
	}

	h := &Handler{
		cfg:           &config.Config{Admin: config.AdminConfig{Path: "/admin"}},
		db:            db,
		ipbl:          ipbl,
		registry:      registry,
		apiKeyLimiter: newLoginLimiter(),
	}
	e := echo.New()
	h.RegisterAPI(e)
	return h, e
}

func createTestKey(t *testing.T, h *Handler) string {
	t.Helper()
	raw, prefix, hash, err := newAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.CreateAPIKey("test", prefix, hash); err != nil {
		t.Fatal(err)
	}
	return raw
}

// apiRequest drives a request through the full registered route (auth
// middleware + handler) via httptest, returning the recorded response.
func apiRequest(e *echo.Echo, method, path, key string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestAPIKeyAuthRejectsMissingHeader(t *testing.T) {
	_, e := newTestAPIHandler(t)
	rec := apiRequest(e, http.MethodGet, "/admin/api/v1/services", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAPIKeyAuthRejectsInvalidKey(t *testing.T) {
	_, e := newTestAPIHandler(t)
	rec := apiRequest(e, http.MethodGet, "/admin/api/v1/services", "cwaf_bogus", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAPIKeyAuthAcceptsValidKey(t *testing.T) {
	h, e := newTestAPIHandler(t)
	key := createTestKey(t, h)
	rec := apiRequest(e, http.MethodGet, "/admin/api/v1/services", key, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAPIKeyAuthRejectsRevokedKey(t *testing.T) {
	h, e := newTestAPIHandler(t)
	key := createTestKey(t, h)
	keys, err := h.db.ListAPIKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListAPIKeys() = %v, %v", keys, err)
	}
	if err := h.db.RemoveAPIKey(keys[0].ID); err != nil {
		t.Fatal(err)
	}
	rec := apiRequest(e, http.MethodGet, "/admin/api/v1/services", key, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for revoked key", rec.Code)
	}
}

// TestAPIKeyAuthLocksOutAfterFailures mirrors TestLoginLimiterLocksAfterMaxFailures
// (loginlimit_test.go) but through the real HTTP path, since apiKeyAuth reuses
// the same loginLimiter type against a second instance keyed by client IP.
func TestAPIKeyAuthLocksOutAfterFailures(t *testing.T) {
	_, e := newTestAPIHandler(t)
	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/admin/api/v1/services", nil)
		r.Header.Set("Authorization", "Bearer cwaf_bogus")
		r.RemoteAddr = "203.0.113.9:1234"
		return r
	}
	var last *httptest.ResponseRecorder
	for i := 0; i < maxLoginFailures; i++ {
		last = httptest.NewRecorder()
		e.ServeHTTP(last, newReq())
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status after %d failures = %d, want 429", maxLoginFailures, last.Code)
	}
}

func TestAPIServiceCRUD(t *testing.T) {
	h, e := newTestAPIHandler(t)
	key := createTestKey(t, h)

	// services.Probe dials the backend for real, so point it at a live
	// httptest server rather than an arbitrary URL.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	rec := apiRequest(e, http.MethodPost, "/admin/api/v1/services", key, map[string]any{
		"name": "svc1", "match_type": "prefix", "match_value": "/svc1", "backend": backend.URL,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created storage.Service
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "svc1" || created.Prefix != "/svc1" {
		t.Fatalf("created service = %+v, want name=svc1 prefix=/svc1", created)
	}

	rec = apiRequest(e, http.MethodGet, "/admin/api/v1/services", key, nil)
	var list []storage.Service
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}

	rec = apiRequest(e, http.MethodGet, fmt.Sprintf("/admin/api/v1/services/%d", created.ID), key, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Partial update: only "name" is sent. Backend/rate-limit/bot-mode must
	// survive untouched — this is the pointer-fields-mean-omitted contract.
	rec = apiRequest(e, http.MethodPut, fmt.Sprintf("/admin/api/v1/services/%d", created.ID), key, map[string]any{
		"name": "svc1-renamed",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var updated storage.Service
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "svc1-renamed" || updated.Backend != backend.URL || updated.Prefix != "/svc1" {
		t.Fatalf("updated service = %+v, want renamed with backend/prefix preserved", updated)
	}

	rec = apiRequest(e, http.MethodDelete, fmt.Sprintf("/admin/api/v1/services/%d", created.ID), key, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = apiRequest(e, http.MethodGet, "/admin/api/v1/services", key, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("list after delete len = %d, want 0", len(list))
	}
}

func TestAPIIPRulesCRUD(t *testing.T) {
	h, e := newTestAPIHandler(t)
	key := createTestKey(t, h)

	rec := apiRequest(e, http.MethodPost, "/admin/api/v1/ip-rules", key, map[string]any{"ip": "10.0.0.5", "rule_type": "block"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ip-rule: status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = apiRequest(e, http.MethodGet, "/admin/api/v1/ip-rules", key, nil)
	var rules []storage.IPRule
	if err := json.Unmarshal(rec.Body.Bytes(), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].IP != "10.0.0.5" || rules[0].RuleType != "block" {
		t.Fatalf("ip-rules = %+v, want one block rule for 10.0.0.5", rules)
	}

	rec = apiRequest(e, http.MethodDelete, fmt.Sprintf("/admin/api/v1/ip-rules/%d", rules[0].ID), key, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete ip-rule: status=%d", rec.Code)
	}
	rec = apiRequest(e, http.MethodGet, "/admin/api/v1/ip-rules", key, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("ip-rules after delete len = %d, want 0", len(rules))
	}
}

// TestAPIBansAreFilteredGlobalBlocks checks the "bans is just a filtered
// ip_rules view" design: a global block created via /bans carries the
// API-specific note prefix (distinct from autoban's own "Auto-banned —",
// so the two sources stay distinguishable in the admin UI's badge logic),
// and a per-service block rule must never show up as a "ban".
func TestAPIBansAreFilteredGlobalBlocks(t *testing.T) {
	h, e := newTestAPIHandler(t)
	key := createTestKey(t, h)

	rec := apiRequest(e, http.MethodPost, "/admin/api/v1/bans", key, map[string]any{"ip": "10.0.0.9", "reason": "abuse"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ban: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// A per-service (non-global) block rule must not surface as a "ban".
	rec = apiRequest(e, http.MethodPost, "/admin/api/v1/ip-rules", key, map[string]any{
		"app_name": "svc1", "ip": "10.0.0.10", "rule_type": "block",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create scoped ip-rule: status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = apiRequest(e, http.MethodGet, "/admin/api/v1/bans", key, nil)
	var bans []storage.IPRule
	if err := json.Unmarshal(rec.Body.Bytes(), &bans); err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("bans = %+v, want exactly 1 (the global one, not the per-service rule)", bans)
	}
	if bans[0].IP != "10.0.0.9" || bans[0].Note != apiBanNotePrefix+"abuse" {
		t.Fatalf("ban = %+v, want ip=10.0.0.9 note=%q", bans[0], apiBanNotePrefix+"abuse")
	}

	rec = apiRequest(e, http.MethodDelete, fmt.Sprintf("/admin/api/v1/bans/%d", bans[0].ID), key, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete ban: status=%d", rec.Code)
	}
	rec = apiRequest(e, http.MethodGet, "/admin/api/v1/bans", key, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &bans); err != nil {
		t.Fatal(err)
	}
	if len(bans) != 0 {
		t.Fatalf("bans after delete = %+v, want empty", bans)
	}
}
