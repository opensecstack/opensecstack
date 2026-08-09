package advisory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildAdvisoryURL(t *testing.T) {
	cases := []struct {
		name       string
		explicit   string
		host, port string
		want       string
	}{
		{"explicit wins", "http://explicit:9", "h", "p", "http://explicit:9"},
		{"host+port", "", "pyhost", "1234", "http://pyhost:1234"},
		{"defaults", "", "", "", "http://localhost:8089"},
		{"host only defaults port", "", "pyhost", "", "http://pyhost:8089"},
		{"port only defaults host", "", "", "1234", "http://localhost:1234"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BuildAdvisoryURL(c.explicit, c.host, c.port)
			if got != c.want {
				t.Errorf("BuildAdvisoryURL(%q,%q,%q) = %q, want %q", c.explicit, c.host, c.port, got, c.want)
			}
		})
	}
}

func TestNewHTTPClientImplementsPythonClient(t *testing.T) {
	c := NewHTTPClient("http://localhost:8089", "some-jwt")
	if c == nil {
		t.Fatal("NewHTTPClient returned nil")
	}
	if _, ok := c.(*httpClient); !ok {
		t.Fatalf("NewHTTPClient returned %T, want *httpClient", c)
	}
}

func TestHTTPClientGenerate_SuccessDecodesResponse(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewEncoder(w).Encode(GenerateResponse{CSAFID: "CSAF-1", Doc: map[string]any{"k": "v"}})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "my-jwt")
	resp, err := c.Generate(context.Background(), GenerateRequest{Title: "T", TLP: "green"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.CSAFID != "CSAF-1" {
		t.Errorf("CSAFID = %q, want CSAF-1", resp.CSAFID)
	}
	if gotAuth != "Bearer my-jwt" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer my-jwt")
	}
	if gotPath != "/generate" {
		t.Errorf("path = %q, want /generate", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
}

func TestHTTPClientGenerate_UpstreamErrorReturnsSentinelNotRawBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("some internal secret stack trace"))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "")
	_, err := c.Generate(context.Background(), GenerateRequest{Title: "T"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrAdvisoryUpstream) {
		t.Fatalf("got %v, want wrapping ErrAdvisoryUpstream", err)
	}
	if got := err.Error(); got == "" {
		t.Fatal("expected non-empty error message")
	}
	// The raw body must never leak into the error surfaced to callers.
	if strings.Contains(err.Error(), "secret stack trace") {
		t.Fatalf("error leaked raw upstream body: %q", err.Error())
	}
}

func TestHTTPClientGenerate_NoAuthHeaderWhenJWTEmpty(t *testing.T) {
	var gotAuth string
	sawAuthHeader := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		sawAuthHeader = r.Header.Get("Authorization") != ""
		_ = json.NewEncoder(w).Encode(GenerateResponse{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "")
	if _, err := c.Generate(context.Background(), GenerateRequest{Title: "T"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if sawAuthHeader {
		t.Errorf("Authorization header = %q, want empty when jwt is empty", gotAuth)
	}
}

func TestHTTPClientEnrichIOCs_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enrich/iocs" {
			t.Errorf("path = %q, want /enrich/iocs", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"iocs": []EnrichedIOC{{IOC: IOC{Type: "ip", Value: "1.2.3.4"}, Reputation: 50}},
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "")
	out, err := c.EnrichIOCs(context.Background(), []IOC{{Type: "ip", Value: "1.2.3.4"}})
	if err != nil {
		t.Fatalf("EnrichIOCs: %v", err)
	}
	if len(out) != 1 || out[0].Reputation != 50 {
		t.Fatalf("got %+v", out)
	}
}

func TestHTTPClientTriageAbuseEmail_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/triage/abuse-email" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "message/rfc822" {
			t.Errorf("content-type = %q, want message/rfc822", ct)
		}
		_ = json.NewEncoder(w).Encode(TriageResult{Classification: "phishing", Confidence: 0.9})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "")
	res, err := c.TriageAbuseEmail(context.Background(), []byte("From: a@b.com\n\nbody"))
	if err != nil {
		t.Fatalf("TriageAbuseEmail: %v", err)
	}
	if res.Classification != "phishing" {
		t.Errorf("Classification = %q, want phishing", res.Classification)
	}
}

func TestHTTPClientTriageAbuseEmail_UpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "")
	_, err := c.TriageAbuseEmail(context.Background(), []byte("raw"))
	if !errors.Is(err, ErrAdvisoryUpstream) {
		t.Fatalf("got %v, want ErrAdvisoryUpstream", err)
	}
}

func TestHTTPClientHealth_SuccessAndFailure(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path = %q, want /health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if err := NewHTTPClient(ok.URL, "").Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if err := NewHTTPClient(bad.URL, "").Health(context.Background()); err == nil {
		t.Fatal("expected error for 503 health response")
	}
}
