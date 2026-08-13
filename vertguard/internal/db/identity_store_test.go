package db

import (
	"context"
	"strings"
	"testing"
)

func newIdentityScan(scanID string) *IdentityScan {
	return &IdentityScan{
		ScanID:         scanID,
		Classification: "SUSPICIOUS",
		Confidence:     0.85,
		ClaimHash:      "deadbeef",
		ClaimType:      "voice_clone",
		Context:        "video_call",
		IndicatorCount: 2,
		Indicators:     []byte(`[{"type":"deepfake_marker"}]`),
		DurationMS:     12.5,
	}
}

func TestIdentityScan_SaveAndGetIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "identity_scans")
	ctx := context.Background()

	s := newIdentityScan("id-scan-1")
	if err := d.SaveIdentityScan(ctx, s); err != nil {
		t.Fatalf("SaveIdentityScan: %v", err)
	}

	got, err := d.GetIdentityScan(ctx, "id-scan-1")
	if err != nil {
		t.Fatalf("GetIdentityScan: %v", err)
	}
	if got.Classification != "SUSPICIOUS" {
		t.Errorf("Classification: got %q, want SUSPICIOUS", got.Classification)
	}
	if got.ClaimType != "voice_clone" {
		t.Errorf("ClaimType: got %q, want voice_clone", got.ClaimType)
	}
	if got.IndicatorCount != 2 {
		t.Errorf("IndicatorCount: got %d, want 2", got.IndicatorCount)
	}
	if !strings.Contains(string(got.Indicators), "deepfake_marker") {
		t.Errorf("Indicators: got %s", got.Indicators)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be populated")
	}
}

func TestIdentityScan_SaveDefaultsNilIndicatorsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "identity_scans")
	ctx := context.Background()

	s := newIdentityScan("id-scan-nil-indicators")
	s.Indicators = nil
	if err := d.SaveIdentityScan(ctx, s); err != nil {
		t.Fatalf("SaveIdentityScan: %v", err)
	}

	got, err := d.GetIdentityScan(ctx, "id-scan-nil-indicators")
	if err != nil {
		t.Fatalf("GetIdentityScan: %v", err)
	}
	if string(got.Indicators) != "[]" {
		t.Errorf("Indicators: got %s, want []", got.Indicators)
	}
}

func TestIdentityScan_GetNotFoundIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "identity_scans")

	_, err := d.GetIdentityScan(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing scan_id")
	}
}

func TestIdentityScan_SaveDuplicateScanIDFailsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "identity_scans")
	ctx := context.Background()

	s := newIdentityScan("id-scan-dup")
	if err := d.SaveIdentityScan(ctx, s); err != nil {
		t.Fatalf("SaveIdentityScan (first): %v", err)
	}

	dup := newIdentityScan("id-scan-dup")
	if err := d.SaveIdentityScan(ctx, dup); err == nil {
		t.Error("expected unique constraint violation on duplicate scan_id")
	}
}
