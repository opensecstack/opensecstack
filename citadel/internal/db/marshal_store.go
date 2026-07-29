package db

import (
	"context"
	"crypto/ed25519"
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

// ActionCount implements marshal.Store.
func (s *MarshalStore) ActionCount(ctx context.Context, userID string, windowDur time.Duration) (int, error) {
	return s.db.ActionCount(ctx, userID, windowDur)
}

// AppendWORM implements marshal.Store — converts *db.WORMEntry → *marshal.WORMEntry.
func (s *MarshalStore) AppendWORM(ctx context.Context, source, eventType, projectID string, payload []byte, sigOperator, sigVerifier string) (*marshal.WORMEntry, error) {
	entry, err := s.db.AppendWORM(ctx, source, eventType, projectID, payload, sigOperator, sigVerifier)
	if err != nil {
		return nil, err
	}
	return &marshal.WORMEntry{
		ID:          uuid.UUID(entry.ID),
		SequenceNum: entry.SequenceNum,
		ChainHash:   entry.ChainHash,
		SigOperator: entry.SigOperator,
		SigVerifier: entry.SigVerifier,
	}, nil
}

// GetSigningKey implements marshal.Store.
func (s *MarshalStore) GetSigningKey(ctx context.Context, userID string) (ed25519.PublicKey, bool, error) {
	pub, _, exists, err := s.db.GetActiveKey(ctx, userID)
	return pub, exists, err
}
