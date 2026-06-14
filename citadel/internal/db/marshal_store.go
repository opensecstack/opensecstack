package db

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/citadel/internal/marshal"
)

// MarshalStore wraps DB and adapts it to the marshal.Store interface.
// This adapter lives in the db package so it can access db internals
// without creating an import cycle (db does NOT import marshal).
type MarshalStore struct {
	db *DB
}

// NewMarshalStore creates a marshal.Store backed by the given DB.
func NewMarshalStore(d *DB) marshal.Store {
	return &MarshalStore{db: d}
}

// SessionExists implements marshal.Store.
func (s *MarshalStore) SessionExists(ctx context.Context, userID int64) (role, roleGroup string, exists bool, err error) {
	return s.db.SessionExists(ctx, userID)
}

// ActionCount implements marshal.Store.
func (s *MarshalStore) ActionCount(ctx context.Context, userID int64, windowDur time.Duration) (int, error) {
	return s.db.ActionCount(ctx, userID, windowDur)
}

// AppendWORM implements marshal.Store — converts *db.WORMEntry → *marshal.WORMEntry.
func (s *MarshalStore) AppendWORM(ctx context.Context, source, eventType, projectID string, payload []byte) (*marshal.WORMEntry, error) {
	entry, err := s.db.AppendWORM(ctx, source, eventType, projectID, payload)
	if err != nil {
		return nil, err
	}
	return &marshal.WORMEntry{
		ID:          uuid.UUID(entry.ID),
		SequenceNum: entry.SequenceNum,
		ChainHash:   entry.ChainHash,
	}, nil
}
