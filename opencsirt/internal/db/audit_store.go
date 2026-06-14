package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditEntry struct {
	ID         uuid.UUID
	ActorID    *uuid.UUID
	ActorRole  string
	Action     string
	TargetType string
	TargetID   *uuid.UUID
	Metadata   map[string]any
	CreatedAt  time.Time
}

type AuditStore struct{ pool *pgxpool.Pool }

func NewAuditStore(pool *pgxpool.Pool) *AuditStore { return &AuditStore{pool: pool} }

func (s *AuditStore) Insert(ctx context.Context, a *AuditEntry) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.Metadata == nil {
		a.Metadata = map[string]any{}
	}
	meta, err := json.Marshal(a.Metadata)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_log (id, actor_id, actor_role, action, target_type, target_id, metadata, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, a.ID, a.ActorID, a.ActorRole, a.Action, a.TargetType, a.TargetID, meta, a.CreatedAt)
	return err
}

type IOCIngestEntry struct {
	ID           uuid.UUID
	Source       string
	BundleSHA256 string
	Count        int
	IngestedAt   time.Time
}

type IOCIngestStore struct{ pool *pgxpool.Pool }

func NewIOCIngestStore(pool *pgxpool.Pool) *IOCIngestStore { return &IOCIngestStore{pool: pool} }

func (s *IOCIngestStore) Insert(ctx context.Context, e *IOCIngestEntry) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.IngestedAt.IsZero() {
		e.IngestedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ioc_ingest_log (id, source, bundle_sha256, count, ingested_at)
		VALUES ($1,$2,$3,$4,$5)
	`, e.ID, e.Source, e.BundleSHA256, e.Count, e.IngestedAt)
	return err
}

func (s *IOCIngestStore) LastForSource(ctx context.Context, source string) (*IOCIngestEntry, error) {
	e := &IOCIngestEntry{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, source, bundle_sha256, count, ingested_at
		  FROM ioc_ingest_log
		 WHERE source = $1
	     ORDER BY ingested_at DESC
	     LIMIT 1
	`, source).Scan(&e.ID, &e.Source, &e.BundleSHA256, &e.Count, &e.IngestedAt)
	return e, err
}
