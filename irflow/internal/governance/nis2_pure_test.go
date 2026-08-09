package governance

import (
	"testing"
	"time"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

// ---------------------------------------------------------------------------
// nis2Deadline — computes the Article 23 notification deadline from the
// incident's severity-derived threshold. Empty string signals "no
// regulatory deadline applies" (e.g. severities with no NIS2Thresholds entry
// or a zero/negative threshold).
// ---------------------------------------------------------------------------

func TestNis2Deadline_P1AddsThreshold(t *testing.T) {
	created := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	inc := &incident.Incident{Severity: incident.SeverityP1, CreatedAt: created}

	threshold, ok := incident.NIS2Thresholds[incident.SeverityP1]
	if !ok || threshold <= 0 {
		t.Fatalf("test assumes P1 has a positive NIS2 threshold configured, got %v/%v", threshold, ok)
	}

	want := created.Add(threshold).UTC().Format(time.RFC3339)
	got := nis2Deadline(inc)
	if got != want {
		t.Errorf("nis2Deadline() = %q, want %q", got, want)
	}
}

func TestNis2Deadline_UnknownSeverityReturnsEmpty(t *testing.T) {
	inc := &incident.Incident{Severity: incident.Severity("unmapped"), CreatedAt: time.Now()}
	if got := nis2Deadline(inc); got != "" {
		t.Errorf("nis2Deadline() for unmapped severity = %q, want empty string", got)
	}
}

func TestNis2Deadline_P4HasNoThreshold(t *testing.T) {
	// P4 is deliberately excluded from mandatory NIS2 notification.
	if threshold, ok := incident.NIS2Thresholds[incident.SeverityP4]; ok && threshold > 0 {
		t.Skip("test assumes P4 carries no positive NIS2 threshold; adjust if that changes")
	}
	inc := &incident.Incident{Severity: incident.SeverityP4, CreatedAt: time.Now()}
	if got := nis2Deadline(inc); got != "" {
		t.Errorf("nis2Deadline() for P4 = %q, want empty string", got)
	}
}

// ---------------------------------------------------------------------------
// firstNonEmpty
// ---------------------------------------------------------------------------

func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"first is non-empty", []string{"a", "b"}, "a"},
		{"first empty falls through to second", []string{"", "b"}, "b"},
		{"all empty returns empty", []string{"", "", ""}, ""},
		{"no args returns empty", nil, ""},
		{"middle non-empty wins over later non-empty", []string{"", "x", "y"}, "x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstNonEmpty(c.in...); got != c.want {
				t.Errorf("firstNonEmpty(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
