package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PromptScan is the persisted form of a Module 3 scan result.
type PromptScan struct {
	ID             uuid.UUID `json:"-"`
	ScanID         string    `json:"scan_id"`
	Classification string    `json:"classification"`
	Confidence     float64   `json:"confidence"`
	InputHash      string    `json:"input_hash"`
	InputLength    int       `json:"input_length"`
	Context        string    `json:"context"`
	MatchCount     int       `json:"match_count"`
	Matches        []byte    `json:"-"` // raw JSONB
	WORMEntryID    *string   `json:"worm_entry_id,omitempty"`
	DurationMS     float64   `json:"duration_ms"`
	CreatedAt      time.Time `json:"created_at"`

	// ML enricher fields (Phase 4.2+, migration 009). Zero values are
	// persisted as SQL NULL via *float64 / *string semantics — a scan
	// that never reached the ML enricher must not look like an ML
	// CLEAN verdict in downstream analytics.
	MLConfidence     *float64 `json:"ml_confidence,omitempty"`
	MLVerdict        *string  `json:"ml_verdict,omitempty"`
	MLBackendVersion *string  `json:"ml_backend_version,omitempty"`
}

// SavePromptScan inserts a completed scan record.
// Returns the generated ID.
func (d *DB) SavePromptScan(ctx context.Context, s *PromptScan) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.Matches == nil {
		s.Matches = []byte("[]")
	}

	_, err := d.Pool.Exec(ctx, `
		INSERT INTO prompt_scans (
			id, scan_id, classification, confidence,
			input_hash, input_length, context,
			match_count, matches, worm_entry_id, duration_ms,
			ml_confidence, ml_verdict, ml_backend_version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		s.ID, s.ScanID, s.Classification, s.Confidence,
		s.InputHash, s.InputLength, s.Context,
		s.MatchCount, s.Matches, s.WORMEntryID, s.DurationMS,
		s.MLConfidence, s.MLVerdict, s.MLBackendVersion,
	)
	if err != nil {
		return fmt.Errorf("insert prompt scan: %w", err)
	}
	return nil
}

// GetPromptScan retrieves a scan by its public scan_id.
func (d *DB) GetPromptScan(ctx context.Context, scanID string) (*PromptScan, error) {
	var s PromptScan
	var matchesRaw json.RawMessage

	err := d.Pool.QueryRow(ctx, `
		SELECT id, scan_id, classification, confidence, input_hash, input_length,
		       COALESCE(context, ''), match_count, matches, worm_entry_id,
		       COALESCE(duration_ms, 0), created_at,
		       ml_confidence, ml_verdict, ml_backend_version
		FROM prompt_scans WHERE scan_id = $1`,
		scanID,
	).Scan(
		&s.ID, &s.ScanID, &s.Classification, &s.Confidence, &s.InputHash, &s.InputLength,
		&s.Context, &s.MatchCount, &matchesRaw, &s.WORMEntryID,
		&s.DurationMS, &s.CreatedAt,
		&s.MLConfidence, &s.MLVerdict, &s.MLBackendVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("get prompt scan: %w", err)
	}

	s.Matches = matchesRaw
	return &s, nil
}
