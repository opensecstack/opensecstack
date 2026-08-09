package feed

import (
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

func TestNewScheduler_DefaultsTickToOneMinute(t *testing.T) {
	s := NewScheduler(nil, nil, zerolog.Nop())
	if s.tick != time.Minute {
		t.Errorf("tick = %v, want 1m default", s.tick)
	}
}

func TestWithTick_OverridesAndReturnsSameScheduler(t *testing.T) {
	s := NewScheduler(nil, nil, zerolog.Nop())
	got := s.WithTick(100 * time.Millisecond)
	if got != s {
		t.Error("WithTick should return the same *Scheduler for chaining")
	}
	if s.tick != 100*time.Millisecond {
		t.Errorf("tick = %v, want 100ms", s.tick)
	}
}

func TestBuildPoller_KnownTypesReturnMatchingPoller(t *testing.T) {
	cases := map[string]string{
		"taxii21": "taxii21",
		"csv":     "csv",
		"misp":    "misp",
		"opencti": "opencti",
	}
	for feedType, wantKind := range cases {
		f := &store.Feed{Name: "test-feed", FeedType: feedType, URL: "https://example.com"}
		p, err := buildPoller(f)
		if err != nil {
			t.Errorf("buildPoller(%q): unexpected error: %v", feedType, err)
			continue
		}
		if p == nil {
			t.Errorf("buildPoller(%q) returned nil poller", feedType)
			continue
		}
		if p.Kind() != wantKind {
			t.Errorf("buildPoller(%q).Kind() = %q, want %q", feedType, p.Kind(), wantKind)
		}
	}
}

func TestBuildPoller_ManualTypeReturnsError(t *testing.T) {
	f := &store.Feed{Name: "manual-feed", FeedType: "manual"}
	p, err := buildPoller(f)
	if err == nil {
		t.Fatal("expected error for manual feed type (no poller)")
	}
	if p != nil {
		t.Errorf("expected nil poller on error, got %v", p)
	}
}

func TestBuildPoller_UnknownTypeReturnsError(t *testing.T) {
	f := &store.Feed{Name: "weird-feed", FeedType: "carbon-pigeon"}
	_, err := buildPoller(f)
	if err == nil {
		t.Fatal("expected error for unknown feed type")
	}
}

func TestSetHTTPClient_OverridesSharedClient(t *testing.T) {
	original := HTTPClient()
	defer SetHTTPClient(original)

	custom := &http.Client{Timeout: 7 * time.Second}
	SetHTTPClient(custom)
	if HTTPClient() != custom {
		t.Error("SetHTTPClient did not override the shared client")
	}
}

func TestSetHTTPClient_NilRestoresDefaultSixtySecondTimeout(t *testing.T) {
	original := HTTPClient()
	defer SetHTTPClient(original)

	SetHTTPClient(&http.Client{Timeout: 1 * time.Second})
	SetHTTPClient(nil)
	restored := HTTPClient()
	if restored.Timeout != 60*time.Second {
		t.Errorf("SetHTTPClient(nil) restored client with Timeout = %v, want 60s", restored.Timeout)
	}
}
