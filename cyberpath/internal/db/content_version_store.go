// Package db — content_version_store manages `content_versions`.
// Append-only snapshot table; DELETE is forbidden by a DB trigger.
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContentVersion mirrors a row in `content_versions`.
// EntityID is varchar(128) so it can hold UUIDs (tracks/lessons/...) or
// slug-style ids (lab definitions); modeled as string for both.
type ContentVersion struct {
	ID            uuid.UUID       `json:"id"`
	EntityType    string          `json:"entity_type"`
	EntityID      string          `json:"entity_id"`
	Version       int             `json:"version"`
	ContentHash   string          `json:"content_hash"`
	Payload       json.RawMessage `json:"payload"`
	PublishedAt   time.Time       `json:"published_at"`
	PublishedBy   *uuid.UUID      `json:"published_by,omitempty"`
	SupersededAt  *time.Time      `json:"superseded_at,omitempty"`
	ChangeSummary string          `json:"change_summary"`
}

// ContentVersionStore wraps a pgx pool for `content_versions`.
//
// Note: there is intentionally no Delete method. The table has a
// BEFORE DELETE trigger (`trg_content_versions_no_delete`) that raises
// `restrict_violation` for any DELETE attempt — content versions are
// load-bearing audit evidence and removing them would break completion
// reproducibility. Use Publish to supersede an old version instead.
type ContentVersionStore struct {
	Pool *pgxpool.Pool
}

// NewContentVersionStore wires a ContentVersionStore.
func NewContentVersionStore(pool *pgxpool.Pool) *ContentVersionStore {
	return &ContentVersionStore{Pool: pool}
}

const contentVersionColumns = `id, entity_type, entity_id, version, content_hash,
	payload, published_at, published_by, superseded_at, change_summary`

func scanContentVersion(row pgx.Row) (*ContentVersion, error) {
	var c ContentVersion
	if err := row.Scan(
		&c.ID, &c.EntityType, &c.EntityID, &c.Version, &c.ContentHash,
		&c.Payload, &c.PublishedAt, &c.PublishedBy, &c.SupersededAt, &c.ChangeSummary,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

// Publish appends a new content version. Auto-increments `version` based on
// the highest existing one for (entity_type, entity_id), and marks the
// previous latest row's superseded_at = now() in the same transaction.
func (s *ContentVersionStore) Publish(ctx context.Context, entityType, entityID string, payload json.RawMessage, hash string, publishedBy *uuid.UUID, summary string) (*ContentVersion, error) {
	const op = "content_version.Publish"

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("store/%s: begin: %w", op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var nextVersion int
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(version), 0) + 1
		FROM content_versions WHERE entity_type = $1 AND entity_id = $2`,
		entityType, entityID,
	).Scan(&nextVersion); err != nil {
		return nil, fmt.Errorf("store/%s: next version: %w", op, err)
	}

	if nextVersion > 1 {
		if _, err := tx.Exec(ctx, `
			UPDATE content_versions SET superseded_at = now()
			WHERE entity_type = $1 AND entity_id = $2 AND superseded_at IS NULL`,
			entityType, entityID); err != nil {
			return nil, fmt.Errorf("store/%s: supersede: %w", op, err)
		}
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO content_versions (
			id, entity_type, entity_id, version, content_hash,
			payload, published_by, change_summary
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING `+contentVersionColumns,
		uuid.New(), entityType, entityID, nextVersion, hash,
		[]byte(payload), nullableUUID(publishedBy), summary,
	)
	stored, err := scanContentVersion(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: insert: %w", op, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store/%s: commit: %w", op, err)
	}
	return stored, nil
}

// GetByID returns a content version by its UUID primary key.
func (s *ContentVersionStore) GetByID(ctx context.Context, id uuid.UUID) (*ContentVersion, error) {
	const op = "content_version.GetByID"
	row := s.Pool.QueryRow(ctx, `
		SELECT `+contentVersionColumns+` FROM content_versions WHERE id = $1`, id)
	out, err := scanContentVersion(row)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return out, nil
}

// GetLatest returns the current (non-superseded) version for an entity.
func (s *ContentVersionStore) GetLatest(ctx context.Context, entityType, entityID string) (*ContentVersion, error) {
	const op = "content_version.GetLatest"
	row := s.Pool.QueryRow(ctx, `
		SELECT `+contentVersionColumns+` FROM content_versions
		WHERE entity_type = $1 AND entity_id = $2 AND superseded_at IS NULL
		ORDER BY version DESC LIMIT 1`, entityType, entityID)
	out, err := scanContentVersion(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// GetVersion returns a specific version of an entity.
func (s *ContentVersionStore) GetVersion(ctx context.Context, entityType, entityID string, version int) (*ContentVersion, error) {
	const op = "content_version.GetVersion"
	row := s.Pool.QueryRow(ctx, `
		SELECT `+contentVersionColumns+` FROM content_versions
		WHERE entity_type = $1 AND entity_id = $2 AND version = $3`,
		entityType, entityID, version)
	out, err := scanContentVersion(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// ListVersions returns every version row for an entity, newest first.
func (s *ContentVersionStore) ListVersions(ctx context.Context, entityType, entityID string) ([]ContentVersion, error) {
	const op = "content_version.ListVersions"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+contentVersionColumns+` FROM content_versions
		WHERE entity_type = $1 AND entity_id = $2
		ORDER BY version DESC`, entityType, entityID)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]ContentVersion, 0, 4)
	for rows.Next() {
		v, err := scanContentVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}
