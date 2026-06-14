package feed

import (
	"testing"
	"time"

	"github.com/opensecstack/threatflow/internal/db/store"
)

func TestDueForPoll_NeverPolled(t *testing.T) {
	f := &store.Feed{PollInterval: "1 hour"}
	if !dueForPoll(f) {
		t.Error("never-polled feed should be due")
	}
}

func TestDueForPoll_IntervalNotReached(t *testing.T) {
	now := time.Now().Add(-5 * time.Minute)
	f := &store.Feed{PollInterval: "1 hour", LastPollAt: &now}
	if dueForPoll(f) {
		t.Error("feed polled 5min ago with 1hr interval should not be due")
	}
}

func TestDueForPoll_IntervalReached(t *testing.T) {
	now := time.Now().Add(-2 * time.Hour)
	f := &store.Feed{PollInterval: "1 hour", LastPollAt: &now}
	if !dueForPoll(f) {
		t.Error("feed polled 2hr ago with 1hr interval should be due")
	}
}

func TestParsePostgresInterval(t *testing.T) {
	cases := map[string]time.Duration{
		"01:00:00":   time.Hour,
		"00:30:00":   30 * time.Minute,
		"1 hour":     time.Hour,
		"30 mins":    30 * time.Minute,
		"2 days":     48 * time.Hour,
		"1 hr 15 mins": time.Hour + 15*time.Minute,
	}
	for input, want := range cases {
		got, err := parsePostgresInterval(input)
		if err != nil {
			t.Errorf("%s: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("%s: got %v, want %v", input, got, want)
		}
	}
}
