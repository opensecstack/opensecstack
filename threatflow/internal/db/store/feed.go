package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FeedStore persists feeds rows.
type FeedStore struct {
	pool *pgxpool.Pool
}

// NewFeedStore returns a store bound to the given pool.
func NewFeedStore(pool *pgxpool.Pool) *FeedStore {
	return &FeedStore{pool: pool}
}

// Create inserts a new feed. Name must be unique.
func (s *FeedStore) Create(ctx context.Context, f *Feed) error {
	const q = `
INSERT INTO feeds (name, feed_type, url, poll_interval, confidence_base, accuracy_ratio, enabled)
VALUES ($1, $2, $3, $4::interval, $5, $6, $7)
RETURNING id, poll_interval::text, created_at, updated_at`
	return s.pool.QueryRow(ctx, q,
		f.Name, f.FeedType, nullIfEmpty(f.URL),
		defaultInterval(f.PollInterval), f.ConfidenceBase, f.AccuracyRatio, f.Enabled,
	).Scan(&f.ID, &f.PollInterval, &f.CreatedAt, &f.UpdatedAt)
}

// Get fetches a feed by ID.
func (s *FeedStore) Get(ctx context.Context, id uuid.UUID) (*Feed, error) {
	const q = `
SELECT id, name, feed_type, coalesce(url, ''), poll_interval::text,
       confidence_base, accuracy_ratio, last_poll_at, last_poll_count,
       error_count, enabled, created_at, updated_at
FROM feeds WHERE id = $1`
	f, err := scanFeed(s.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

// GetByName fetches a feed by its unique name.
func (s *FeedStore) GetByName(ctx context.Context, name string) (*Feed, error) {
	const q = `
SELECT id, name, feed_type, coalesce(url, ''), poll_interval::text,
       confidence_base, accuracy_ratio, last_poll_at, last_poll_count,
       error_count, enabled, created_at, updated_at
FROM feeds WHERE name = $1`
	f, err := scanFeed(s.pool.QueryRow(ctx, q, name))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

// List returns all feeds ordered by name.
func (s *FeedStore) List(ctx context.Context, enabledOnly bool) ([]*Feed, error) {
	q := `
SELECT id, name, feed_type, coalesce(url, ''), poll_interval::text,
       confidence_base, accuracy_ratio, last_poll_at, last_poll_count,
       error_count, enabled, created_at, updated_at
FROM feeds`
	if enabledOnly {
		q += " WHERE enabled = TRUE"
	}
	q += " ORDER BY name"

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query feeds: %w", err)
	}
	defer rows.Close()

	var out []*Feed
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RecordPoll updates last_poll_at, last_poll_count, and resets error_count on success.
func (s *FeedStore) RecordPoll(ctx context.Context, id uuid.UUID, count int, success bool) error {
	var q string
	var args []any
	if success {
		q = `UPDATE feeds SET last_poll_at = $1, last_poll_count = $2, error_count = 0, updated_at = now() WHERE id = $3`
		args = []any{time.Now().UTC(), count, id}
	} else {
		q = `UPDATE feeds SET error_count = error_count + 1, updated_at = now() WHERE id = $1`
		args = []any{id}
	}
	tag, err := s.pool.Exec(ctx, q, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetEnabled toggles the enabled flag.
func (s *FeedStore) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE feeds SET enabled = $1, updated_at = now() WHERE id = $2`, enabled, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a feed. Associated IOCs have feed_id set to NULL.
func (s *FeedStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM feeds WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanFeed(r rowScanner) (*Feed, error) {
	var f Feed
	if err := r.Scan(
		&f.ID, &f.Name, &f.FeedType, &f.URL, &f.PollInterval,
		&f.ConfidenceBase, &f.AccuracyRatio, &f.LastPollAt, &f.LastPollCount,
		&f.ErrorCount, &f.Enabled, &f.CreatedAt, &f.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &f, nil
}

func defaultInterval(v string) string {
	if v == "" {
		return "1 hour"
	}
	return v
}
