package services

import (
	"bufio"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func TestNegotiateEncoding(t *testing.T) {
	for _, tc := range []struct{ accept, want string }{
		{"", ""},
		{"gzip", "gzip"},
		{"gzip, deflate, br, zstd", "zstd"},
		{"GZIP", "gzip"},
		{"zstd;q=0, gzip;q=0.5", "gzip"},
		{"gzip;q=0.0", ""},
		{"br, deflate", ""},
		{"identity", ""},
	} {
		if got := negotiateEncoding(tc.accept); got != tc.want {
			t.Errorf("negotiateEncoding(%q) = %q, want %q", tc.accept, got, tc.want)
		}
	}
}

func TestCompressResponseSkips(t *testing.T) {
	big := strings.Repeat("hello world ", 200)
	for _, tc := range []struct {
		name   string
		status int
		method string
		header http.Header
		length int64
		want   string // Content-Encoding after compressResponse
	}{
		{"html", 200, "GET", http.Header{"Content-Type": {"text/html; charset=utf-8"}}, -1, "zstd"},
		{"json", 200, "GET", http.Header{"Content-Type": {"application/problem+json"}}, int64(len(big)), "zstd"},
		{"websocket upgrade", 101, "GET", http.Header{"Content-Type": {"text/plain"}, "Upgrade": {"websocket"}}, -1, ""},
		{"sse", 200, "GET", http.Header{"Content-Type": {"text/event-stream"}}, -1, ""},
		{"png", 200, "GET", http.Header{"Content-Type": {"image/png"}}, -1, ""},
		{"head", 200, "HEAD", http.Header{"Content-Type": {"text/html"}}, -1, ""},
		{"not modified", 304, "GET", http.Header{"Content-Type": {"text/html"}}, -1, ""},
		{"partial", 206, "GET", http.Header{"Content-Type": {"text/html"}}, -1, ""},
		{"small", 200, "GET", http.Header{"Content-Type": {"text/html"}}, 100, ""},
		{"already encoded", 200, "GET", http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"br"}}, -1, "br"},
		{"no-transform", 200, "GET", http.Header{"Content-Type": {"text/html"}, "Cache-Control": {"public, no-transform"}}, -1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			req.Header.Set("Accept-Encoding", "gzip, zstd")
			resp := &http.Response{StatusCode: tc.status, Header: tc.header, ContentLength: tc.length,
				Body: io.NopCloser(strings.NewReader(big)), Request: req}
			compressResponse(resp)
			if got := resp.Header.Get("Content-Encoding"); got != tc.want {
				t.Errorf("Content-Encoding = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRegistryCompress covers issue #108 end to end: a large text response
// arrives compressed and decodes back to the original, only on services with
// the toggle on, and a streamed response still reaches the client chunk by
// chunk instead of being held back by the encoder.
func TestRegistryCompress(t *testing.T) {
	page := strings.Repeat("<p>hello world</p>\n", 1000)
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("ETag", `"v1"`)
			_, _ = io.WriteString(w, page)
		case "/stream":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			<-release
			_, _ = io.WriteString(w, "second\n")
		}
	}))
	defer backend.Close()
	defer close(release)

	db := openTestDB(t)
	for _, name := range []string{"on", "off"} {
		if err := db.AddService(name, name+".example.com", "", backend.URL, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	list, err := db.ListServices()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetServiceCompress(list[0].ID, true); err != nil { // "on", added first
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	get := func(svc, path, accept string) *http.Response {
		t.Helper()
		rp, _ := reg.Proxy(svc)
		srv := httptest.NewServer(rp)
		t.Cleanup(srv.Close)
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("Accept-Encoding", accept)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	for _, tc := range []struct{ svc, accept, want string }{
		{"on", "gzip, deflate, br, zstd", "zstd"},
		{"on", "gzip", "gzip"},
		{"on", "", ""},
		{"off", "gzip, zstd", ""},
	} {
		resp := get(tc.svc, "/page", tc.accept)
		enc := resp.Header.Get("Content-Encoding")
		if enc != tc.want {
			t.Fatalf("%s %q: Content-Encoding = %q, want %q", tc.svc, tc.accept, enc, tc.want)
		}
		var body io.Reader = resp.Body
		switch enc {
		case "gzip":
			body, _ = gzip.NewReader(resp.Body)
		case "zstd":
			body, _ = zstd.NewReader(resp.Body)
		}
		got, err := io.ReadAll(body)
		if err != nil || string(got) != page {
			t.Fatalf("%s %q: decoded body mismatch (len %d, err %v)", tc.svc, tc.accept, len(got), err)
		}
		if tc.svc == "on" && resp.Header.Get("Vary") != "Accept-Encoding" {
			t.Errorf("%s %q: Vary = %q", tc.svc, tc.accept, resp.Header.Get("Vary"))
		}
		if enc != "" && resp.Header.Get("ETag") != `W/"v1"` {
			t.Errorf("%s %q: ETag = %q, want weak", tc.svc, tc.accept, resp.Header.Get("ETag"))
		}
	}

	resp := get("on", "/stream", "gzip")
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(gz).ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		if s != "first\n" {
			t.Fatalf("first chunk = %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first chunk held back until the backend finished")
	}
}
