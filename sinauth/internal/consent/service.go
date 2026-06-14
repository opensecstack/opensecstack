package consent

import (
	"context"
)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service { return &Service{store: store} }

// HasConsent returns true if the user has previously consented to the given scopes for the client.
func (s *Service) HasConsent(ctx context.Context, userID, clientID string, scopes []string) (bool, error) {
	granted, err := s.store.GetGrantedScopes(ctx, userID, clientID)
	if err != nil {
		return false, err
	}
	grantedSet := make(map[string]struct{}, len(granted))
	for _, sc := range granted {
		grantedSet[sc] = struct{}{}
	}
	for _, sc := range scopes {
		if _, ok := grantedSet[sc]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// Grant saves the user's consent for the given scopes.
func (s *Service) Grant(ctx context.Context, userID, clientID string, scopes []string) error {
	return s.store.Upsert(ctx, userID, clientID, scopes)
}

// Revoke removes consent for a user+client pair.
func (s *Service) Revoke(ctx context.Context, userID, clientID string) error {
	return s.store.Delete(ctx, userID, clientID)
}
