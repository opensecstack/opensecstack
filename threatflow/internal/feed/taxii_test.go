package feed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTAXII_Poll_WrapsObjectsInBundle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "" {
			t.Errorf("Accept header not set")
		}
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"objects":[{"type":"indicator","id":"indicator--11111111-1111-1111-1111-111111111111","spec_version":"2.1","pattern":"[ipv4-addr:value = '1.1.1.1']","pattern_type":"stix","created":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z","valid_from":"2026-01-01T00:00:00Z"}]}`))
	}))
	defer srv.Close()

	p := NewTAXII(Config{Name: "test", URL: srv.URL})
	payload, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 object, got %d", n)
	}

	var bundle struct {
		Type    string            `json:"type"`
		ID      string            `json:"id"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if bundle.Type != "bundle" {
		t.Errorf("type = %q", bundle.Type)
	}
	if len(bundle.Objects) != 1 {
		t.Errorf("bundle objects = %d", len(bundle.Objects))
	}
}

func TestTAXII_Poll_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	p := NewTAXII(Config{Name: "x", URL: srv.URL})
	_, _, err := p.Poll(context.Background())
	if err == nil {
		t.Fatal("expected error on 403")
	}
}
