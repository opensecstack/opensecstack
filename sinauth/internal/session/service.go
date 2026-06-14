package session

import (
	"context"
	"time"
)

// Session represents an SSO browser session (one login = access to all clients).
type Session struct {
	ID        string
	UserID    string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Service struct {
	store *Store
}

func NewService(store *Store) *Service { return &Service{store: store} }

func (s *Service) Create(ctx context.Context, userID, username string, ttl time.Duration) (*Session, error) {
	return s.store.Create(ctx, userID, username, ttl)
}

func (s *Service) Get(ctx context.Context, sessionID string) (*Session, error) {
	return s.store.Get(ctx, sessionID)
}

func (s *Service) Revoke(ctx context.Context, sessionID string) error {
	return s.store.Delete(ctx, sessionID)
}

func (s *Service) ListAll(ctx context.Context) ([]Session, error) {
	return s.store.ListAll(ctx)
}

func (s *Service) ListByUsername(ctx context.Context, username string) ([]Session, error) {
	return s.store.ListByUsername(ctx, username)
}
