package services

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBackendTransportReusesConns pins issue #107: with Go's default of 2
// idle conns per host, repeated bursts of concurrent requests to one backend
// open new connections every burst. The count must stay at the burst size.
func TestBackendTransportReusesConns(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond) // keep the burst in flight together
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	client := &http.Client{Transport: backendTransport}
	const concurrency, rounds = 20, 10
	for range rounds {
		var wg sync.WaitGroup
		for range concurrency {
			wg.Go(func() {
				resp, err := client.Get(srv.URL)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			})
		}
		wg.Wait()
	}
	if n := newConns.Load(); n > concurrency {
		t.Fatalf("opened %d backend connections for %d rounds of %d concurrent requests, want <= %d", n, rounds, concurrency, concurrency)
	}
}
