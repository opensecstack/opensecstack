package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PhishingScan is the persisted form of a Module 5 scan result.
type PhishingScan struct {
	ID             uuid.UUID `json:"-"`
	ScanID         string    `json:"scan_id"`
	Classification string    `json:"classification"`
	Confidence     float64   `json:"confidence"`
	InputHash      string    `json:"input_hash"`
	InputLength    int       `json:"input_length"`
	Kind           string    `json:"kind"`
	IndicatorCount int       `json:"indicator_count"`
	Indicators     []byte    `json:"-"` // raw JSONB
	WORMEntryID    *string   `json:"worm_entry_id,omitempty"`
	DurationMS     float64   `json:"duration_ms"`
	CreatedAt      time.Time `json:"created_at"`
}

// SavePhishingScan inserts a completed scan record.
func (d *DB) SavePhishingScan(ctx context.Context, s *PhishingScan) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.Indicators == nil {
		s.Indicators = []byte("[]")
	}

	_, err := d.Pool.Exec(ctx, `
		INSERT INTO phishing_scans (
			id, scan_id, classification, confidence,
			input_hash, input_length, kind,
			indicator_count, indicators, worm_entry_id, duration_ms
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		s.ID, s.ScanID, s.Classification, s.Confidence,
		s.InputHash, s.InputLength, s.Kind,
		s.IndicatorCount, s.Indicators, s.WORMEntryID, s.DurationMS,
	)
	if err != nil {
		return fmt.Errorf("insert phishing scan: %w", err)
	}
	return nil
}

// GetPhishingScan retrieves a scan by its public scan_id.
func (d *DB) GetPhishingScan(ctx context.Context, scanID string) (*PhishingScan, error) {
	var s PhishingScan
	var indicatorsRaw json.RawMessage

	err := d.Pool.QueryRow(ctx, `
		SELECT id, scan_id, classification, confidence, input_hash, input_length,
		       kind, indicator_count, indicators, worm_entry_id,
		       COALESCE(duration_ms, 0), created_at
		FROM phishing_scans WHERE scan_id = $1`,
		scanID,
	).Scan(
		&s.ID, &s.ScanID, &s.Classification, &s.Confidence, &s.InputHash, &s.InputLength,
		&s.Kind, &s.IndicatorCount, &indicatorsRaw, &s.WORMEntryID,
		&s.DurationMS, &s.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get phishing scan: %w", err)
	}

	s.Indicators = indicatorsRaw
	return &s, nil
}
