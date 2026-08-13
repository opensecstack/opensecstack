package db

import (
	"context"
	"strings"
	"testing"
)

func newPhishingScan(scanID string) *PhishingScan {
	return &PhishingScan{
		ScanID:         scanID,
		Classification: "BLOCKED",
		Confidence:     0.97,
		InputHash:      "hash-abc",
		InputLength:    128,
		Kind:           "url",
		IndicatorCount: 1,
		Indicators:     []byte(`[{"type":"lookalike_domain"}]`),
		DurationMS:     3.4,
	}
}

func TestPhishingScan_SaveAndGetIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "phishing_scans")
	ctx := context.Background()

	s := newPhishingScan("phish-scan-1")
	if err := d.SavePhishingScan(ctx, s); err != nil {
		t.Fatalf("SavePhishingScan: %v", err)
	}

	got, err := d.GetPhishingScan(ctx, "phish-scan-1")
	if err != nil {
		t.Fatalf("GetPhishingScan: %v", err)
	}
	if got.Classification != "BLOCKED" {
		t.Errorf("Classification: got %q, want BLOCKED", got.Classification)
	}
	if got.Kind != "url" {
		t.Errorf("Kind: got %q, want url", got.Kind)
	}
	if !strings.Contains(string(got.Indicators), "lookalike_domain") {
		t.Errorf("Indicators: got %s", got.Indicators)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be populated")
	}
}

func TestPhishingScan_SaveDefaultsNilIndicatorsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "phishing_scans")
	ctx := context.Background()

	s := newPhishingScan("phish-scan-nil")
	s.Indicators = nil
	if err := d.SavePhishingScan(ctx, s); err != nil {
		t.Fatalf("SavePhishingScan: %v", err)
	}

	got, err := d.GetPhishingScan(ctx, "phish-scan-nil")
	if err != nil {
		t.Fatalf("GetPhishingScan: %v", err)
	}
	if string(got.Indicators) != "[]" {
		t.Errorf("Indicators: got %s, want []", got.Indicators)
	}
}

func TestPhishingScan_GetNotFoundIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "phishing_scans")

	_, err := d.GetPhishingScan(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing scan_id")
	}
}

func TestPhishingScan_SaveDuplicateScanIDFailsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "phishing_scans")
	ctx := context.Background()

	s := newPhishingScan("phish-scan-dup")
	if err := d.SavePhishingScan(ctx, s); err != nil {
		t.Fatalf("SavePhishingScan (first): %v", err)
	}
	dup := newPhishingScan("phish-scan-dup")
	if err := d.SavePhishingScan(ctx, dup); err == nil {
		t.Error("expected unique constraint violation on duplicate scan_id")
	}
}
