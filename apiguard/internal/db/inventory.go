package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ListAPIInventory returns a paginated list of tracked APIs ordered by
// last_scanned_at (most recently scanned first).
func (d *DB) ListAPIInventory(ctx context.Context, limit, offset int) ([]APIInventory, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const maxPageSize = 100
	if limit <= 0 || limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_inventory`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting inventory: %w", err)
	}
	if total == 0 {
		return nil, 0, nil
	}

	rows, err := d.Pool.Query(ctx, `
		SELECT id, target_url, spec_hash, api_version, first_seen_at,
		       last_scanned_at, scan_count, created_at, updated_at
		FROM api_inventory
		ORDER BY last_scanned_at DESC NULLS LAST
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing inventory: %w", err)
	}
	defer rows.Close()

	var items []APIInventory
	for rows.Next() {
		var inv APIInventory
		if err := rows.Scan(
			&inv.ID, &inv.TargetURL, &inv.SpecHash, &inv.APIVersion,
			&inv.FirstSeenAt, &inv.LastScannedAt, &inv.ScanCount,
			&inv.CreatedAt, &inv.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning inventory row: %w", err)
		}
		items = append(items, inv)
	}
	return items, total, nil
}

// GetAPIInventoryByID retrieves a single inventory record by UUID.
func (d *DB) GetAPIInventoryByID(ctx context.Context, id uuid.UUID) (*APIInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var inv APIInventory
	err := d.Pool.QueryRow(ctx, `
		SELECT id, target_url, spec_hash, api_version, first_seen_at,
		       last_scanned_at, scan_count, created_at, updated_at
		FROM api_inventory
		WHERE id = $1`, id).Scan(
		&inv.ID, &inv.TargetURL, &inv.SpecHash, &inv.APIVersion,
		&inv.FirstSeenAt, &inv.LastScannedAt, &inv.ScanCount,
		&inv.CreatedAt, &inv.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("inventory item not found: %s", id)
		}
		return nil, fmt.Errorf("querying inventory: %w", err)
	}
	return &inv, nil
}

// GetAPIInventoryHistory returns all scans for the given inventory item,
// ordered by creation date (newest first). This joins on the target_url
// to find matching scans.
func (d *DB) GetAPIInventoryHistory(ctx context.Context, inventoryID uuid.UUID, limit, offset int) ([]Scan, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const maxPageSize = 100
	if limit <= 0 || limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	err := d.Pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM scans s
		JOIN api_inventory inv ON s.target_url = inv.target_url
		WHERE inv.id = $1`, inventoryID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("counting inventory history: %w", err)
	}
	if total == 0 {
		return nil, 0, nil
	}

	rows, err := d.Pool.Query(ctx, `
		SELECT s.id, s.spec_url, s.spec_hash, s.target_url, s.status, s.modules,
		       s.started_at, s.completed_at, s.created_at, s.updated_at,
		       s.config_json, s.total_findings, s.critical_count, s.high_count,
		       s.medium_count, s.low_count, s.info_count, s.auth_type, s.error_message
		FROM scans s
		JOIN api_inventory inv ON s.target_url = inv.target_url
		WHERE inv.id = $1
		ORDER BY s.created_at DESC
		LIMIT $2 OFFSET $3`, inventoryID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing inventory history: %w", err)
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
			return nil, 0, fmt.Errorf("scanning history row: %w", err)
		}
		scans = append(scans, s)
	}
	return scans, total, nil
}
