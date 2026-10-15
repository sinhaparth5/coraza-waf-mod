package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"palisade/internal/services"
	"palisade/internal/storage"

	"github.com/labstack/echo/v4"
	"github.com/quic-go/quic-go/http3"
)

// TestHTTP3PerServiceOptIn drives a real QUIC round trip: the opted-in host
// is served, any other host gets 421, and only the opted-in host's TCP
// responses advertise Alt-Svc.
func TestHTTP3PerServiceOptIn(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, name := range []string{"h3", "h2"} {
		if err := db.AddService(name, name+".example.com", "", "http://127.0.0.1:1", 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	list, err := db.ListServices()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range list {
		if s.Name == "h3" {
			if err := db.SetServiceHTTP3(s.ID, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	reg, err := services.New(db)
	if err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	e.Any("/*", func(c echo.Context) error { return c.String(http.StatusOK, c.Request().Proto) })

	addr := freeUDPAddr(t)
	srv, err := startHTTP3(e, addr, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}, reg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // self-signed test cert
	t.Cleanup(func() { tr.Close() })
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	cases := []struct {
		host string
		want int
	}{
		{"h3.example.com", http.StatusOK},
		{"h2.example.com", http.StatusMisdirectedRequest},
		{"127.0.0.1", http.StatusMisdirectedRequest}, // admin UI / bare IP stays on TCP
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
		req.Host = tc.host
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.host, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want || resp.ProtoMajor != 3 {
			t.Errorf("%s: got %d over %s, want %d over HTTP/3", tc.host, resp.StatusCode, resp.Proto, tc.want)
		}
	}

	_, port, _ := net.SplitHostPort(addr)
	for host, want := range map[string]string{
		"h3.example.com": `h3=":` + port + `"; ma=86400`,
		"h2.example.com": "",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		e.ServeHTTP(rec, req)
		if got := rec.Header().Get("Alt-Svc"); got != want {
			t.Errorf("%s: Alt-Svc = %q, want %q", host, got, want)
		}
	}
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"h3.example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
