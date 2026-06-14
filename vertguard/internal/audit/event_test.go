package audit

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// fakeSink records every call; flag controls forced error.
type fakeSink struct {
	mu     sync.Mutex
	events []Event
	fail   error
}

func (f *fakeSink) Record(_ context.Context, e Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return f.fail
}

func (f *fakeSink) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func TestMultiSinkFansOutToAll(t *testing.T) {
	a, b := &fakeSink{}, &fakeSink{}
	logger := zerolog.New(io.Discard)
	m := NewMultiSink(&logger, a, b)
	if err := m.Record(context.Background(), Event{ID: uuid.New()}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if a.calls() != 1 || b.calls() != 1 {
		t.Fatalf("want 1 call each, got a=%d b=%d", a.calls(), b.calls())
	}
}

func TestMultiSinkBestEffortSwallowsErrors(t *testing.T) {
	bad := &fakeSink{fail: errors.New("db down")}
	good := &fakeSink{}
	logger := zerolog.New(io.Discard)
	m := NewMultiSink(&logger, bad, good)

	// Even when first sink fails, second must still receive the event,
	// and Record itself must not surface the error to the caller.
	if err := m.Record(context.Background(), Event{ID: uuid.New()}); err != nil {
		t.Fatalf("multisink should swallow errors, got: %v", err)
	}
	if good.calls() != 1 {
		t.Fatalf("downstream sink not called after upstream failure")
	}
}

func TestMultiSinkSkipsNilSinks(t *testing.T) {
	good := &fakeSink{}
	logger := zerolog.New(io.Discard)
	m := NewMultiSink(&logger, nil, good, nil)
	_ = m.Record(context.Background(), Event{ID: uuid.New()})
	if good.calls() != 1 {
		t.Fatalf("want 1, got %d", good.calls())
	}
}

func TestParseRemoteIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:1234": "127.0.0.1",
		"10.0.0.5":       "10.0.0.5",
		"":               "",
		"garbage":        "",
		"[::1]:80":       "::1",
	}
	for in, want := range cases {
		if got := ParseRemoteIP(in); got != want {
			t.Errorf("ParseRemoteIP(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestLoggerSinkNilSafe(t *testing.T) {
	var s *LoggerSink
	if err := s.Record(context.Background(), Event{}); err != nil {
		t.Fatal(err)
	}
}
