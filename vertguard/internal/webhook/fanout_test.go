package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/citadel"
)

type stubInnerEmitter struct {
	called bool
	result bool
	gotEv  citadel.Evidence
}

func (s *stubInnerEmitter) EmitAsync(_ context.Context, ev citadel.Evidence) bool {
	s.called = true
	s.gotEv = ev
	return s.result
}

func TestFanoutEmitter_ForwardsToInnerAndDispatcher(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "secret", "kid")
	store := newFakeStore(sub)
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: 2 * time.Second}, store, store, zerolog.Nop(), newStubMetrics())

	inner := &stubInnerEmitter{result: true}
	f := NewFanoutEmitter(inner, disp)

	ev := citadel.Evidence{EventType: "prompt_scan", CorrelationID: "corr-1", Verdict: "BLOCKED"}
	ok := f.EmitAsync(context.Background(), ev)

	if !ok {
		t.Error("EmitAsync() = false, want true (inner result passed through)")
	}
	if !inner.called {
		t.Error("inner.EmitAsync was not called")
	}
	if inner.gotEv.CorrelationID != "corr-1" {
		t.Errorf("inner received CorrelationID = %q, want corr-1", inner.gotEv.CorrelationID)
	}
	if store.deliveredCount() != 1 {
		t.Fatalf("delivered=%d, want 1 (fanout must publish to dispatcher too)", store.deliveredCount())
	}
	if len(gotBody) == 0 {
		t.Error("webhook subscriber received empty body")
	}
}

func TestFanoutEmitter_InnerFailureDoesNotBlockDispatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sub := newSub(srv.URL, "secret", "kid")
	store := newFakeStore(sub)
	disp := NewDispatcher(Config{Enabled: true, MaxRetries: 1, BackoffBase: time.Millisecond, RequestTimeout: 2 * time.Second}, store, store, zerolog.Nop(), newStubMetrics())

	inner := &stubInnerEmitter{result: false} // CITADEL path failed
	f := NewFanoutEmitter(inner, disp)

	ok := f.EmitAsync(context.Background(), citadel.Evidence{EventType: "prompt_scan", CorrelationID: "corr-2"})

	if ok {
		t.Error("EmitAsync() = true, want false (must surface inner failure)")
	}
	if store.deliveredCount() != 1 {
		t.Fatal("webhook fanout must still deliver even when the CITADEL emit failed")
	}
}

func TestFanoutEmitter_NilInnerAndNilDispatcherSafe(t *testing.T) {
	f := NewFanoutEmitter(nil, nil)
	ok := f.EmitAsync(context.Background(), citadel.Evidence{EventType: "prompt_scan"})
	if !ok {
		t.Error("EmitAsync() with nil Inner should default to true (no CITADEL failure to report)")
	}
}
