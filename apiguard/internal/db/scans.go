package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateScan inserts a new scan record and populates the generated fields.
func (d *DB) CreateScan(ctx context.Context, scan *Scan) error {
	query := `
		INSERT INTO scans (spec_url, spec_hash, target_url, status, modules, config_json, auth_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`

	return d.Pool.QueryRow(ctx, query,
		scan.SpecURL,
		scan.SpecHash,
		scan.TargetURL,
		scan.Status,
		scan.Modules,
		scan.ConfigJSON,
		scan.AuthType,
	).Scan(&scan.ID, &scan.CreatedAt, &scan.UpdatedAt)
}

// GetScan retrieves a scan by ID.
func (d *DB) GetScan(ctx context.Context, id uuid.UUID) (*Scan, error) {
	query := `
		SELECT id, spec_url, spec_hash, target_url, status, modules,
		       started_at, completed_at, created_at, updated_at,
		       config_json, total_findings, critical_count, high_count,
		       medium_count, low_count, info_count, auth_type, error_message
		FROM scans
		WHERE id = $1`

	var s Scan
	err := d.Pool.QueryRow(ctx, query, id).Scan(
		&s.ID, &s.SpecURL, &s.SpecHash, &s.TargetURL, &s.Status, &s.Modules,
		&s.StartedAt, &s.CompletedAt, &s.CreatedAt, &s.UpdatedAt,
		&s.ConfigJSON, &s.TotalFindings, &s.CriticalCount, &s.HighCount,
		&s.MediumCount, &s.LowCount, &s.InfoCount, &s.AuthType, &s.ErrorMessage,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("scan not found: %s", id)
		}
		return nil, fmt.Errorf("querying scan: %w", err)
	}
	return &s, nil
}

// ListScans returns a paginated list of scans ordered by creation date (newest first).
// It returns the scans, the total count, and any error.
func (d *DB) ListScans(ctx context.Context, limit, offset int) ([]Scan, int, error) {
	const maxPageSize = 100
	if limit <= 0 || limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}

	countQuery := `SELECT COUNT(*) FROM scans`
	var total int
	if err := d.Pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting scans: %w", err)
	}

	query := `
		SELECT id, spec_url, spec_hash, target_url, status, modules,
		       started_at, completed_at, created_at, updated_at,
		       config_json, total_findings, critical_count, high_count,
		       medium_count, low_count, info_count, auth_type, error_message
		FROM scans
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := d.Pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying scans: %w", err)
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var s Scan
		if err := rows.Scan(
			&s.ID, &s.SpecURL, &s.SpecHash, &s.TargetURL, &s.Status, &s.Modules,
			&s.StartedAt, &s.CompletedAt, &s.CreatedAt, &s.UpdatedAt,
			&s.ConfigJSON, &s.TotalFindings, &s.CriticalCount, &s.HighCount,
			&s.MediumCount, &s.LowCount, &s.InfoCount, &s.AuthType, &s.ErrorMessage,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning row: %w", err)
		}
		scans = append(scans, s)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating rows: %w", err)
	}

	return scans, total, nil
}

// UpdateScanStatus updates a scan's status and related timestamps.
func (d *DB) UpdateScanStatus(ctx context.Context, id uuid.UUID, status ScanStatus) error {
	var query string
	var args []interface{}

	switch status {
	case ScanStatusRunning:
		query = `UPDATE scans SET status = $1, started_at = $2, updated_at = $2 WHERE id = $3`
		now := time.Now()
		args = []interface{}{status, now, id}
	case ScanStatusCompleted, ScanStatusFailed, ScanStatusCancelled:
		query = `UPDATE scans SET status = $1, completed_at = $2, updated_at = $2 WHERE id = $3`
		now := time.Now()
		args = []interface{}{status, now, id}
	default:
		query = `UPDATE scans SET status = $1, updated_at = NOW() WHERE id = $2`
		args = []interface{}{status, id}
	}

	ct, err := d.Pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("updating scan status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("scan not found: %s", id)
	}
	return nil
}

// UpdateScanSummary updates the finding counts on a scan.
func (d *DB) UpdateScanSummary(ctx context.Context, id uuid.UUID, summary ScanSummary) error {
	query := `
		UPDATE scans
		SET total_findings = $1, critical_count = $2, high_count = $3,
		    medium_count = $4, low_count = $5, info_count = $6, updated_at = NOW()
		WHERE id = $7`

	ct, err := d.Pool.Exec(ctx, query,
		summary.TotalFindings, summary.CriticalCount, summary.HighCount,
		summary.MediumCount, summary.LowCount, summary.InfoCount, id,
	)
	if err != nil {
		return fmt.Errorf("updating scan summary: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("scan not found: %s", id)
	}
	return nil
}

// DeleteScan removes a scan and its associated findings (via CASCADE).
func (d *DB) DeleteScan(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM scans WHERE id = $1`

	ct, err := d.Pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("deleting scan: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("scan not found: %s", id)
	}
	return nil
}
