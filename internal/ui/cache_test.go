package ui

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

func TestAPIPurgeService(t *testing.T) {
	var gotService, gotURL string
	varnish := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PURGE" {
			t.Errorf("method = %s, want PURGE", r.Method)
		}
		gotService, gotURL = r.Header.Get("X-Cache-Service"), r.Header.Get("X-Cache-Purge-Url")
	}))
	defer varnish.Close()

	h, e := newTestAPIHandler(t)
	key := createTestKey(t, h, false)
	if err := h.db.AddService("blog", "", "/blog", "http://10.0.0.9:8000/base", 0, 0); err != nil {
		t.Fatal(err)
	}
	list, _ := h.db.ListServices()
	id := strconv.Itoa(list[0].ID)
	if err := h.db.SetVarnishConfig(storage.VarnishConfig{Enabled: true, Addr: strings.TrimPrefix(varnish.URL, "http://")}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, id string
		body     any
		status   int
		svc, url string
	}{
		{"whole service", id, nil, http.StatusOK, "blog", ""},
		{"path prefix mapped to backend URL", id, map[string]string{"path": "/blog/x.css"}, http.StatusOK, "blog", "^/base/x[.]css"},
		{"unsafe path", id, map[string]string{"path": "/a && obj.status"}, http.StatusBadRequest, "", ""},
		{"unknown service", "9999", nil, http.StatusNotFound, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotService, gotURL = "", ""
			rec := apiRequest(e, http.MethodPost, "/admin/api/v1/services/"+tc.id+"/purge", key, tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if gotService != tc.svc || gotURL != tc.url {
				t.Errorf("varnish got service=%q url=%q, want %q %q", gotService, gotURL, tc.svc, tc.url)
			}
		})
	}
}

func TestServicesCacheStatsRenders(t *testing.T) {
	h, _ := newTestAPIHandler(t)
	if err := h.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	render := func() string {
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/admin/services/cache-stats", nil), rec)
		if err := h.ServicesCacheStats(c); err != nil {
			t.Fatal(err)
		}
		return rec.Body.String()
	}

	if body := render(); !strings.Contains(body, "Varnish integration is off") {
		t.Errorf("disabled: missing off notice:\n%s", body)
	}

	if err := h.db.SetVarnishConfig(storage.VarnishConfig{Enabled: true, Addr: "127.0.0.1:6081"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"HIT", "HIT", "MISS", "PASS"} {
		if _, err := h.db.InsertRequest(storage.RequestLog{Timestamp: time.Now().UTC(), AppName: "shop", CacheStatus: s}); err != nil {
			t.Fatal(err)
		}
	}
	body := render()
	for _, want := range []string{"shop", "66.7%"} {
		if !strings.Contains(body, want) {
			t.Errorf("enabled: missing %q:\n%s", want, body)
		}
	}
	// varnishstat is absent in test environments: the card must degrade to
	// a notice, not fail the whole partial.
	if !strings.Contains(body, "Varnish counters unavailable") && !strings.Contains(body, "Hit ratio") {
		t.Errorf("enabled: neither counters nor unavailable notice:\n%s", body)
	}
}
