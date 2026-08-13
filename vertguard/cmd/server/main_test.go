package main

import (
	"context"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/threatfeed/webhook"
)

// ── stubPinger ──────────────────────────────────────────────────────

func TestStubPinger_PingAlwaysNil(t *testing.T) {
	var p stubPinger
	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("stubPinger.Ping() = %v, want nil", err)
	}
}

// ── mispAuthHeader ──────────────────────────────────────────────────

func TestMispAuthHeader(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"empty token stays empty", "", ""},
		{"bare token gets Bearer prefix", "abc123", "Bearer abc123"},
		{"already-prefixed token is untouched", "Bearer abc123", "Bearer abc123"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mispAuthHeader(tc.token); got != tc.want {
				t.Errorf("mispAuthHeader(%q) = %q, want %q", tc.token, got, tc.want)
			}
		})
	}
}

// ── effectiveDrainGrace ─────────────────────────────────────────────

func TestEffectiveDrainGrace(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero falls back to 5s default", 0, 5 * time.Second},
		{"negative falls back to 5s default", -1 * time.Second, 5 * time.Second},
		{"positive value passes through", 12 * time.Second, 12 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveDrainGrace(tc.in); got != tc.want {
				t.Errorf("effectiveDrainGrace(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// ── buildThreatflowSeed ─────────────────────────────────────────────

func TestBuildThreatflowSeed(t *testing.T) {
	t.Run("no secret produces no seed", func(t *testing.T) {
		got := buildThreatflowSeed("https://threatflow.example/webhook", "")
		if got != nil {
			t.Fatalf("got %#v, want nil", got)
		}
	})

	t.Run("secret produces one active default subscriber", func(t *testing.T) {
		got := buildThreatflowSeed("https://threatflow.example/webhook", "s3cr3t")
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		want := webhook.Subscriber{
			ID:         "default",
			URL:        "https://threatflow.example/webhook",
			HMACSecret: "s3cr3t",
			Active:     true,
		}
		if got[0].ID != want.ID || got[0].URL != want.URL ||
			got[0].HMACSecret != want.HMACSecret || got[0].Active != want.Active {
			t.Errorf("got %#v, want %#v", got[0], want)
		}
	})
}

// ── buildIOCSources ─────────────────────────────────────────────────

func TestBuildIOCSources_Empty(t *testing.T) {
	got := buildIOCSources(config.IOCConfig{})
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}

func TestBuildIOCSources_MISPConvenienceKnob(t *testing.T) {
	got := buildIOCSources(config.IOCConfig{
		MISPURL:   "https://misp.example",
		MISPToken: "tok",
		Interval:  10 * time.Minute,
	})
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Interval != 10*time.Minute {
		t.Errorf("interval = %v, want 10m", got[0].Interval)
	}
}

func TestBuildIOCSources_AbuseChConvenienceKnob(t *testing.T) {
	got := buildIOCSources(config.IOCConfig{
		AbuseChEnabled: true,
		AbuseChURLs:    "https://abuse.ch/urls",
		AbuseChHashes:  "https://abuse.ch/hashes",
		Interval:       5 * time.Minute,
	})
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Interval != 5*time.Minute {
		t.Errorf("interval = %v, want 5m", got[0].Interval)
	}
}

func TestBuildIOCSources_BothConvenienceKnobsCombine(t *testing.T) {
	got := buildIOCSources(config.IOCConfig{
		MISPURL:        "https://misp.example",
		AbuseChEnabled: true,
		Interval:       time.Minute,
	})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (MISP + abuse.ch)", len(got))
	}
}

func TestBuildIOCSources_DeclaredSources(t *testing.T) {
	got := buildIOCSources(config.IOCConfig{
		Interval: time.Minute,
		Sources: []config.SourceConfig{
			{Type: "misp", Name: "custom-misp", URL: "https://misp2.example", AuthHeader: "Bearer xyz", Enabled: true},
			{Type: "abusech", Name: "custom-abusech", URL: "https://abuse2.example", HashURL: "https://abuse2.example/hashes", Enabled: true},
			{Type: "file", Name: "custom-file", Path: "/tmp/iocs.json", Enabled: true},
			{Type: "unknown", Name: "ignored", Enabled: true},
			{Type: "misp", Name: "disabled-misp", Enabled: false},
		},
	})
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (misp + abusech + file; unknown type and disabled entry skipped)", len(got))
	}
}

func TestBuildIOCSources_DeclaredSourceIntervalOverride(t *testing.T) {
	got := buildIOCSources(config.IOCConfig{
		Interval: time.Minute,
		Sources: []config.SourceConfig{
			{Type: "file", Name: "custom", Path: "/tmp/x.json", Enabled: true, Interval: 30 * time.Second},
			{Type: "file", Name: "fallback", Path: "/tmp/y.json", Enabled: true}, // no interval -> falls back to global
		},
	})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Interval != 30*time.Second {
		t.Errorf("first source interval = %v, want 30s (explicit override)", got[0].Interval)
	}
	if got[1].Interval != time.Minute {
		t.Errorf("second source interval = %v, want 1m (fallback to global)", got[1].Interval)
	}
}
