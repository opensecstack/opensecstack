package db

import (
	"context"
	"strings"
	"testing"
)

func newPromptScan(scanID string) *PromptScan {
	return &PromptScan{
		ScanID:         scanID,
		Classification: "SUSPICIOUS",
		Confidence:     0.72,
		InputHash:      "hash-xyz",
		InputLength:    256,
		Context:        "user_chat_input",
		MatchCount:     1,
		Matches:        []byte(`[{"rule":"ignore_previous_instructions"}]`),
		DurationMS:     5.1,
	}
}

func TestPromptScan_SaveAndGetIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "prompt_scans")
	ctx := context.Background()

	s := newPromptScan("prompt-scan-1")
	if err := d.SavePromptScan(ctx, s); err != nil {
		t.Fatalf("SavePromptScan: %v", err)
	}

	got, err := d.GetPromptScan(ctx, "prompt-scan-1")
	if err != nil {
		t.Fatalf("GetPromptScan: %v", err)
	}
	if got.Classification != "SUSPICIOUS" {
		t.Errorf("Classification: got %q, want SUSPICIOUS", got.Classification)
	}
	if got.Context != "user_chat_input" {
		t.Errorf("Context: got %q, want user_chat_input", got.Context)
	}
	if !strings.Contains(string(got.Matches), "ignore_previous_instructions") {
		t.Errorf("Matches: got %s", got.Matches)
	}
	if got.MLConfidence != nil || got.MLVerdict != nil || got.MLBackendVersion != nil {
		t.Errorf("expected nil ML fields when unset, got confidence=%v verdict=%v backend=%v",
			got.MLConfidence, got.MLVerdict, got.MLBackendVersion)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be populated")
	}
}

func TestPromptScan_SaveWithMLFieldsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "prompt_scans")
	ctx := context.Background()

	conf := 0.91
	verdict := "BLOCKED"
	backend := "vertguard-ml-v2"
	s := newPromptScan("prompt-scan-ml")
	s.MLConfidence = &conf
	s.MLVerdict = &verdict
	s.MLBackendVersion = &backend

	if err := d.SavePromptScan(ctx, s); err != nil {
		t.Fatalf("SavePromptScan: %v", err)
	}

	got, err := d.GetPromptScan(ctx, "prompt-scan-ml")
	if err != nil {
		t.Fatalf("GetPromptScan: %v", err)
	}
	if got.MLConfidence == nil || *got.MLConfidence != conf {
		t.Errorf("MLConfidence: got %v, want %v", got.MLConfidence, conf)
	}
	if got.MLVerdict == nil || *got.MLVerdict != verdict {
		t.Errorf("MLVerdict: got %v, want %v", got.MLVerdict, verdict)
	}
	if got.MLBackendVersion == nil || *got.MLBackendVersion != backend {
		t.Errorf("MLBackendVersion: got %v, want %v", got.MLBackendVersion, backend)
	}
}

func TestPromptScan_SaveDefaultsNilMatchesIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "prompt_scans")
	ctx := context.Background()

	s := newPromptScan("prompt-scan-nil-matches")
	s.Matches = nil
	if err := d.SavePromptScan(ctx, s); err != nil {
		t.Fatalf("SavePromptScan: %v", err)
	}

	got, err := d.GetPromptScan(ctx, "prompt-scan-nil-matches")
	if err != nil {
		t.Fatalf("GetPromptScan: %v", err)
	}
	if string(got.Matches) != "[]" {
		t.Errorf("Matches: got %s, want []", got.Matches)
	}
}

func TestPromptScan_GetNotFoundIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "prompt_scans")

	_, err := d.GetPromptScan(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing scan_id")
	}
}

func TestPromptScan_SaveDuplicateScanIDFailsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "prompt_scans")
	ctx := context.Background()

	s := newPromptScan("prompt-scan-dup")
	if err := d.SavePromptScan(ctx, s); err != nil {
		t.Fatalf("SavePromptScan (first): %v", err)
	}
	dup := newPromptScan("prompt-scan-dup")
	if err := d.SavePromptScan(ctx, dup); err == nil {
		t.Error("expected unique constraint violation on duplicate scan_id")
	}
}
