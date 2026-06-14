package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// IdentityScan is the persisted form of a Module 6 scan result.
type IdentityScan struct {
	ID             uuid.UUID `json:"-"`
	ScanID         string    `json:"scan_id"`
	Classification string    `json:"classification"`
	Confidence     float64   `json:"confidence"`
	ClaimHash      string    `json:"claim_hash"`
	ClaimType      string    `json:"claim_type"`
	Context        string    `json:"context"`
	IndicatorCount int       `json:"indicator_count"`
	Indicators     []byte    `json:"-"` // raw JSONB
	WORMEntryID    *string   `json:"worm_entry_id,omitempty"`
	DurationMS     float64   `json:"duration_ms"`
	CreatedAt      time.Time `json:"created_at"`
}

// SaveIdentityScan inserts a completed scan record.
func (d *DB) SaveIdentityScan(ctx context.Context, s *IdentityScan) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.Indicators == nil {
		s.Indicators = []byte("[]")
	}
	_, err := d.Pool.Exec(ctx, `
		INSERT INTO identity_scans (
			id, scan_id, classification, confidence, claim_hash,
			claim_type, context, indicator_count, indicators,
			worm_entry_id, duration_ms
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		s.ID, s.ScanID, s.Classification, s.Confidence, s.ClaimHash,
		s.ClaimType, s.Context, s.IndicatorCount, s.Indicators,
		s.WORMEntryID, s.DurationMS,
	)
	if err != nil {
		return fmt.Errorf("insert identity scan: %w", err)
	}
	return nil
}

// GetIdentityScan retrieves a scan by its public scan_id.
func (d *DB) GetIdentityScan(ctx context.Context, scanID string) (*IdentityScan, error) {
	var s IdentityScan
	var indicatorsRaw json.RawMessage
	err := d.Pool.QueryRow(ctx, `
		SELECT id, scan_id, classification, confidence, claim_hash,
		       claim_type, context, indicator_count, indicators,
		       worm_entry_id, COALESCE(duration_ms, 0), created_at
		FROM identity_scans WHERE scan_id = $1`,
		scanID,
	).Scan(
		&s.ID, &s.ScanID, &s.Classification, &s.Confidence, &s.ClaimHash,
		&s.ClaimType, &s.Context, &s.IndicatorCount, &indicatorsRaw,
		&s.WORMEntryID, &s.DurationMS, &s.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get identity scan: %w", err)
	}
	s.Indicators = indicatorsRaw
	return &s, nil
}
