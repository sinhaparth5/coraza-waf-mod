package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTLSInfo(t *testing.T) {
	if v, c, s := tlsInfo(httptest.NewRequest("GET", "/", nil)); v+c+s != "" {
		t.Errorf("plain HTTP = %q %q %q", v, c, s)
	}
	for ver, want := range map[uint16]string{
		tls.VersionTLS13: "TLS 1.3", tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS11: "TLS 1.1", tls.VersionTLS10: "TLS 1.0", 0x7f00: "0x7f00",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.TLS = &tls.ConnectionState{Version: ver, CipherSuite: tls.TLS_AES_128_GCM_SHA256, ServerName: "a.test"}
		v, c, s := tlsInfo(r)
		if v != want || c != "TLS_AES_128_GCM_SHA256" || s != "a.test" {
			t.Errorf("tlsInfo(%#x) = %q %q %q", ver, v, c, s)
		}
	}
}

func TestIPHelpers(t *testing.T) {
	if got := parseTrustedProxyCIDRs([]string{" 10.0.0.0/8 ", "", "bogus", "::1/128"}); len(got) != 2 {
		t.Errorf("trusted CIDRs = %v", got)
	}
	for in, want := range map[string]string{"1.2.3.4:80": "1.2.3.4", "no-port": "no-port", "[::1]:80": "::1"} {
		if got := socketPeerIP(in); got != want {
			t.Errorf("socketPeerIP(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]string{"::ffff:127.0.0.1": "127.0.0.1", "::1": "::1", "garbage": "garbage"} {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q) = %q", in, got)
		}
	}
	h := &Handler{}
	if h.isTrustedProxy("not-an-ip") {
		t.Error("unparseable peer trusted")
	}
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
	hijacked, flushed bool
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}
func (h *hijackRecorder) Flush() { h.flushed = true }

// TestResponseWriterPassthrough pins the reason responseWriter exists:
// WebSocket upgrades need Hijack and SSE needs Flush to reach the real writer.
func TestResponseWriterPassthrough(t *testing.T) {
	inner := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	rw := &responseWriter{ResponseWriter: inner}
	if _, _, err := rw.Hijack(); err != nil || !inner.hijacked {
		t.Errorf("Hijack not delegated: %v", err)
	}
	rw.Flush()
	if !inner.flushed {
		t.Error("Flush not delegated")
	}
	rw.WriteHeader(http.StatusTeapot)
	if rw.status != http.StatusTeapot || inner.Code != http.StatusTeapot {
		t.Errorf("status = %d / %d", rw.status, inner.Code)
	}

	plain := &responseWriter{ResponseWriter: struct{ http.ResponseWriter }{httptest.NewRecorder()}}
	if _, _, err := plain.Hijack(); err == nil {
		t.Error("Hijack should fail when the inner writer can't")
	}
	plain.Flush() // no-op, must not panic
}
