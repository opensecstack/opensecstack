package consent

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) GetGrantedScopes(ctx context.Context, userID, clientID string) ([]string, error) {
	var scopes []string
	err := s.pool.QueryRow(ctx,
		`SELECT scopes FROM oauth_consents WHERE user_id=$1 AND client_id=$2`,
		userID, clientID,
	).Scan(&scopes)
	if err != nil {
		return nil, nil
	}
	return scopes, nil
}

func (s *Store) Upsert(ctx context.Context, userID, clientID string, scopes []string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_consents (user_id, client_id, scopes)
         VALUES ($1,$2,$3)
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = now()`,
		userID, clientID, scopes,
	)
	return err
}

func (s *Store) Delete(ctx context.Context, userID, clientID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM oauth_consents WHERE user_id=$1 AND client_id=$2`,
		userID, clientID)
	return err
}
