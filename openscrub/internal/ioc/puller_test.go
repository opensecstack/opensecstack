package ioc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
)

func TestNormaliseIP(t *testing.T) {
	cases := map[string]string{
		"198.51.100.7":   "198.51.100.7/32",
		"203.0.113.0/24": "203.0.113.0/24",
		"203.0.113.5/24": "203.0.113.0/24",
		"2001:db8::1":    "2001:db8::1/128",
		"2001:db8::/32":  "2001:db8::/32",
	}
	for in, want := range cases {
		got, err := normaliseIP(in)
		if err != nil || got != want {
			t.Errorf("normaliseIP(%q) = %q,%v want %q", in, got, err, want)
		}
	}
	if _, err := normaliseIP("not-an-ip"); err == nil {
		t.Error("expected err for garbage input")
	}
}

func TestPullerTickConvertsIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items": [
				{"type": "ip", "value": "198.51.100.7"},
				{"type": "ip", "value": "203.0.113.0/24"},
				{"type": "domain", "value": "evil.example.com"},
				{"type": "ip", "value": "garbage"}
			]
		}`))
	}))
	defer srv.Close()

	plane := dataplane.NewNoopClient()
	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: plane, Emitter: nil,
		NodeName: "n", Logger: zerolog.Nop(),
	})

	var loggedSHA string
	puller := New(Config{BaseURL: srv.URL, Interval: time.Hour, RuleTTL: time.Hour}, svc, zerolog.Nop(),
		func(_ context.Context, source, sha string, count int) error {
			loggedSHA = sha
			if source != rules.SourceThreatFlow {
				t.Errorf("source = %q", source)
			}
			if count != 4 {
				t.Errorf("count = %d", count)
			}
			return nil
		})

	if err := puller.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if loggedSHA == "" {
		t.Fatal("expected ingest log entry")
	}
	snap, _ := plane.Snapshot(context.Background())
	if len(snap.BlocklistV4) != 2 {
		t.Fatalf("expected 2 v4 blocklist entries, got %d", len(snap.BlocklistV4))
	}
}
