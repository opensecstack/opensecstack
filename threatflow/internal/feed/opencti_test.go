package feed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const openctiSample = `{
  "data": {
    "indicators": {
      "edges": [
        {
          "node": {
            "id": "indicator--1",
            "name": "Malicious IP",
            "pattern": "[ipv4-addr:value = '198.51.100.1']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z",
            "confidence": 80,
            "description": "C2 server",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "objectLabel": {"edges": [{"node": {"value": "apt"}}]}
          }
        },
        {
          "node": {
            "id": "indicator--2",
            "name": "Bad Domain",
            "pattern": "[domain-name:value = 'evil.example.com']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z",
            "confidence": 70,
            "description": "",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "objectLabel": {"edges": []}
          }
        }
      ]
    }
  }
}`

const openctiSampleWithSigma = `{
  "data": {
    "indicators": {
      "edges": [
        {
          "node": {
            "id": "indicator--1",
            "name": "STIX Indicator",
            "pattern": "[ipv4-addr:value = '10.0.0.1']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z",
            "confidence": 60,
            "objectLabel": {"edges": []}
          }
        },
        {
          "node": {
            "id": "indicator--sigma",
            "name": "Sigma Rule",
            "pattern": "title: SomeRule\ndetection: ...",
            "pattern_type": "sigma",
            "valid_from": "2026-01-01T00:00:00Z",
            "confidence": 50,
            "objectLabel": {"edges": []}
          }
        }
      ]
    }
  }
}`

func TestOpenCTI_Poll_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		if !strings.HasSuffix(r.URL.Path, "/graphql") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(openctiSample))
	}))
	defer srv.Close()

	p := NewOpenCTI(Config{Name: "opencti1", URL: srv.URL, APIKey: "test-key", ConfidenceBase: 50})
	payload, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 2 {
		t.Fatalf("want 2 indicators, got %d", n)
	}

	var bundle map[string]any
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	objs := bundle["objects"].([]any)
	if len(objs) != 2 {
		t.Fatalf("bundle objects: want 2, got %d", len(objs))
	}
	bundleStr := string(payload)
	if !strings.Contains(bundleStr, "198.51.100.1") {
		t.Error("missing first indicator value")
	}
	if !strings.Contains(bundleStr, "evil.example.com") {
		t.Error("missing second indicator value")
	}
}

func TestOpenCTI_Poll_SkipsNonSTIX(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(openctiSampleWithSigma))
	}))
	defer srv.Close()

	p := NewOpenCTI(Config{Name: "opencti2", URL: srv.URL, ConfidenceBase: 50})
	payload, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 indicator (sigma skipped), got %d", n)
	}
	if strings.Contains(string(payload), "sigma") {
		t.Error("sigma indicator should be excluded from bundle")
	}
}

func TestOpenCTI_Poll_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	p := NewOpenCTI(Config{Name: "opencti3", URL: srv.URL})
	_, _, err := p.Poll(context.Background())
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestOpenCTI_Poll_GraphQLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"errors": [{"message": "unauthorized"}]}`))
	}))
	defer srv.Close()

	p := NewOpenCTI(Config{Name: "opencti4", URL: srv.URL})
	_, _, err := p.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected graphql error, got: %v", err)
	}
}
