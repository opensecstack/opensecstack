package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCSV_EmptyBody_ReturnsZeroIndicators — abuse.ch occasionally returns
// just a banner + no data rows. Should be a zero-count success, not an error.
func TestCSV_EmptyBody_ReturnsZeroIndicators(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# banner only\n# nothing else\n"))
	}))
	defer srv.Close()

	p := NewCSV(Config{Name: "abusech-empty", URL: srv.URL})
	_, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0 indicators on empty feed, got %d", n)
	}
}

// TestTAXII_ContextCancelled — scheduler must not hang when ctx is cancelled
// mid-poll (e.g. during graceful shutdown).
func TestTAXII_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang until the client disconnects.
		<-r.Context().Done()
	}))
	defer srv.Close()

	p := NewTAXII(Config{Name: "slow", URL: srv.URL})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	_, _, err := p.Poll(ctx)
	if err == nil {
		t.Fatal("expected error on pre-cancelled context")
	}
}

// TestCSV_RejectsNon2xx — a 500 on the feed endpoint should surface as an
// error so the scheduler can bump error_count.
func TestCSV_RejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	_, _, err := NewCSV(Config{URL: srv.URL}).Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("want 500 error, got %v", err)
	}
}

// TestMISP_EmptyResponse — events array of length zero should produce an empty
// bundle (not an error). MISP returns this when a filter matches nothing.
func TestMISP_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response": []}`))
	}))
	defer srv.Close()

	_, n, err := NewMISP(Config{URL: srv.URL, APIKey: "k"}).Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0, got %d", n)
	}
}
