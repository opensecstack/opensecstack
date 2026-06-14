package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const mispSample = `{
  "response": [
    {
      "Event": {
        "uuid": "ev1",
        "info": "Campaign X",
        "threat_level_id": "2",
        "Attribute": [
          {"uuid":"a1","type":"ip-dst","value":"10.0.0.1","to_ids":true,"comment":"c2"},
          {"uuid":"a2","type":"domain","value":"bad.example","to_ids":true,"comment":""},
          {"uuid":"a3","type":"text","value":"ignored","to_ids":true,"comment":""},
          {"uuid":"a4","type":"ip-dst","value":"10.0.0.2","to_ids":false,"comment":"skipped"}
        ]
      }
    }
  ]
}`

func TestMISP_Poll_FiltersToIDSAndMapsTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "test-key" {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(mispSample))
	}))
	defer srv.Close()

	p := NewMISP(Config{Name: "misp1", URL: srv.URL, APIKey: "test-key", ConfidenceBase: 75})
	payload, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	// Expect 2 indicators: a1 (ip-dst), a2 (domain). a3 is unmapped type, a4 is to_ids=false.
	if n != 2 {
		t.Fatalf("want 2 indicators, got %d", n)
	}
	s := string(payload)
	if !strings.Contains(s, "10.0.0.1") {
		t.Error("missing ip-dst attribute")
	}
	if strings.Contains(s, "10.0.0.2") {
		t.Error("to_ids=false attribute should be filtered")
	}
	if strings.Contains(s, "ignored") {
		t.Error("unmapped type should be filtered")
	}
}
