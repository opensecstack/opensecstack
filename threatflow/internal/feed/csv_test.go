package feed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSV_Poll_AbuseUrlhaus(t *testing.T) {
	csvBody := `# urlhaus dump
# generated 2026-01-01
id,dateadded,url,url_status,threat,tags
1,2026-01-01,http://bad.example/a,online,malware_download,foo
2,2026-01-01,http://bad.example/b,online,phishing,bar
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(csvBody))
	}))
	defer srv.Close()

	p := NewCSV(Config{Name: "urlhaus", URL: srv.URL, ConfidenceBase: 60})
	payload, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n < 2 {
		t.Fatalf("want >=2 indicators, got %d", n)
	}

	var bundle struct {
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(bundle.Objects) < 2 {
		t.Fatalf("objects = %d", len(bundle.Objects))
	}
	// Verify at least one indicator is a url type.
	found := false
	for _, o := range bundle.Objects {
		if strings.Contains(string(o), `[url:value =`) {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected url indicator pattern in bundle")
	}
}

func TestCSV_Poll_TypeValuePairs(t *testing.T) {
	csvBody := `ipv4,1.2.3.4
domain,evil.test
email,x@y.z
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(csvBody))
	}))
	defer srv.Close()

	p := NewCSV(Config{Name: "otx", URL: srv.URL, ConfidenceBase: 70})
	payload, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 indicators, got %d", n)
	}
	if !strings.Contains(string(payload), "ipv4-addr") {
		t.Error("missing ipv4-addr translation")
	}
	if !strings.Contains(string(payload), "domain-name") {
		t.Error("missing domain-name translation")
	}
}
