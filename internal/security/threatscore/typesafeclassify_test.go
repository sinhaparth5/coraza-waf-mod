package threatscore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJudgeHostingSendsExpectedRequestAndParsesNoul(t *testing.T) {
	var gotAuth, gotContentType string
	var gotReq typesafeRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"jev-1.0.0","answers":{"is_hosting":{"type":"noul","noul":0.92}},"usage":{"input_tokens":296,"output_tokens":20}}`))
	}))
	defer srv.Close()

	c := newTypeSafeClient("test-key")
	c.baseURL = srv.URL

	judgment, err := c.judgeHosting("Some Hosting Provider LLC")
	if err != nil {
		t.Fatalf("judgeHosting: %v", err)
	}
	if !judgment.Hosting {
		t.Fatal("noul 0.92 should classify as hosting (>= 0.5)")
	}
	if judgment.InputTokens != 296 || judgment.OutputTokens != 20 {
		t.Errorf("token usage = %d/%d, want 296/20", judgment.InputTokens, judgment.OutputTokens)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer test-key")
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type header = %q, want application/json", gotContentType)
	}
	if gotReq.State != "Some Hosting Provider LLC" {
		t.Errorf("state = %q, want the org name", gotReq.State)
	}
	q, ok := gotReq.Questions["is_hosting"]
	if !ok || q.Type != "noul" {
		t.Fatalf("questions.is_hosting missing or wrong type: %+v", gotReq.Questions)
	}
}

func TestJudgeHostingBelowThresholdIsNotHosting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answers":{"is_hosting":{"type":"noul","noul":0.1}}}`))
	}))
	defer srv.Close()

	c := newTypeSafeClient("test-key")
	c.baseURL = srv.URL

	judgment, err := c.judgeHosting("Comcast Cable Communications")
	if err != nil {
		t.Fatalf("judgeHosting: %v", err)
	}
	if judgment.Hosting {
		t.Fatal("noul 0.1 should not classify as hosting")
	}
}

func TestJudgeHostingErrorsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTypeSafeClient("bad-key")
	c.baseURL = srv.URL

	if _, err := c.judgeHosting("Anything"); err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
}
