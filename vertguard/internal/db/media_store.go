package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MediaScan is the persisted form of a Module 1 C2PA verification result.
type MediaScan struct {
	ID             uuid.UUID `json:"-"`
	ScanID         string    `json:"scan_id"`
	FileHash       string    `json:"file_hash"`
	FileSize       int64     `json:"file_size"`
	ContentHint    string    `json:"content_hint,omitempty"`
	HasManifest    bool      `json:"has_manifest"`
	SignatureValid bool      `json:"signature_valid"`
	Signer         *string   `json:"signer,omitempty"`
	ClaimsCount    int       `json:"claims_count"`
	Format         string    `json:"format,omitempty"`
	Errors         []string  `json:"errors"`
	Warnings       []string  `json:"warnings"`
	DurationMS     float64   `json:"duration_ms"`
	CreatedAt      time.Time `json:"created_at"`
}

// SaveMediaScan inserts a completed media scan record.
func (d *DB) SaveMediaScan(ctx context.Context, s *MediaScan) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.Errors == nil {
		s.Errors = []string{}
	}
	if s.Warnings == nil {
		s.Warnings = []string{}
	}

	_, err := d.Pool.Exec(ctx, `
		INSERT INTO media_scans (
			id, scan_id, file_hash, file_size, content_hint,
			has_manifest, signature_valid, signer, claims_count,
			format, errors, warnings, duration_ms
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		s.ID, s.ScanID, s.FileHash, s.FileSize, stringOrNil(s.ContentHint),
		s.HasManifest, s.SignatureValid, s.Signer, s.ClaimsCount,
		stringOrNil(s.Format), s.Errors, s.Warnings, s.DurationMS,
	)
	if err != nil {
		return fmt.Errorf("insert media scan: %w", err)
	}
	return nil
}

// GetMediaScan retrieves a media scan by its public scan_id.
func (d *DB) GetMediaScan(ctx context.Context, scanID string) (*MediaScan, error) {
	var s MediaScan
	var contentHint, format *string
	var errs, warns []string

	err := d.Pool.QueryRow(ctx, `
		SELECT id, scan_id, file_hash, file_size, content_hint,
		       has_manifest, signature_valid, signer, claims_count,
		       format, errors, warnings, COALESCE(duration_ms, 0), created_at
		FROM media_scans WHERE scan_id = $1`,
		scanID,
	).Scan(
		&s.ID, &s.ScanID, &s.FileHash, &s.FileSize, &contentHint,
		&s.HasManifest, &s.SignatureValid, &s.Signer, &s.ClaimsCount,
		&format, &errs, &warns, &s.DurationMS, &s.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get media scan: %w", err)
	}

	if contentHint != nil {
		s.ContentHint = *contentHint
	}
	if format != nil {
		s.Format = *format
	}
	s.Errors = errs
	s.Warnings = warns
	return &s, nil
}

func stringOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
