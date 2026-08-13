package db

import (
	"context"
	"testing"
)

func newMediaScan(scanID string) *MediaScan {
	signer := "Example CA"
	return &MediaScan{
		ScanID:         scanID,
		FileHash:       "abc123",
		FileSize:       4096,
		ContentHint:    "image/png",
		HasManifest:    true,
		SignatureValid: true,
		Signer:         &signer,
		ClaimsCount:    3,
		Format:         "png",
		Errors:         []string{},
		Warnings:       []string{"low_resolution"},
		DurationMS:     8.2,
	}
}

func TestMediaScan_SaveAndGetIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "media_scans")
	ctx := context.Background()

	s := newMediaScan("media-scan-1")
	if err := d.SaveMediaScan(ctx, s); err != nil {
		t.Fatalf("SaveMediaScan: %v", err)
	}

	got, err := d.GetMediaScan(ctx, "media-scan-1")
	if err != nil {
		t.Fatalf("GetMediaScan: %v", err)
	}
	if got.FileHash != "abc123" {
		t.Errorf("FileHash: got %q, want abc123", got.FileHash)
	}
	if !got.HasManifest || !got.SignatureValid {
		t.Errorf("HasManifest/SignatureValid: got %v/%v, want true/true", got.HasManifest, got.SignatureValid)
	}
	if got.Signer == nil || *got.Signer != "Example CA" {
		t.Errorf("Signer: got %v, want Example CA", got.Signer)
	}
	if got.ContentHint != "image/png" {
		t.Errorf("ContentHint: got %q, want image/png", got.ContentHint)
	}
	if len(got.Warnings) != 1 || got.Warnings[0] != "low_resolution" {
		t.Errorf("Warnings: got %v", got.Warnings)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be populated")
	}
}

func TestMediaScan_SaveEmptyOptionalFieldsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "media_scans")
	ctx := context.Background()

	s := &MediaScan{
		ScanID:   "media-scan-empty",
		FileHash: "def456",
		FileSize: 10,
		// ContentHint, Format left empty; Errors/Warnings left nil.
	}
	if err := d.SaveMediaScan(ctx, s); err != nil {
		t.Fatalf("SaveMediaScan: %v", err)
	}

	got, err := d.GetMediaScan(ctx, "media-scan-empty")
	if err != nil {
		t.Fatalf("GetMediaScan: %v", err)
	}
	if got.ContentHint != "" {
		t.Errorf("ContentHint: got %q, want empty", got.ContentHint)
	}
	if got.Format != "" {
		t.Errorf("Format: got %q, want empty", got.Format)
	}
	if len(got.Errors) != 0 || len(got.Warnings) != 0 {
		t.Errorf("expected empty Errors/Warnings, got %v / %v", got.Errors, got.Warnings)
	}
	if got.Signer != nil {
		t.Errorf("expected nil Signer, got %v", got.Signer)
	}
}

func TestMediaScan_GetNotFoundIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "media_scans")

	_, err := d.GetMediaScan(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing scan_id")
	}
}

func TestMediaScan_SaveDuplicateScanIDFailsIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "media_scans")
	ctx := context.Background()

	s := newMediaScan("media-scan-dup")
	if err := d.SaveMediaScan(ctx, s); err != nil {
		t.Fatalf("SaveMediaScan (first): %v", err)
	}
	dup := newMediaScan("media-scan-dup")
	if err := d.SaveMediaScan(ctx, dup); err == nil {
		t.Error("expected unique constraint violation on duplicate scan_id")
	}
}
