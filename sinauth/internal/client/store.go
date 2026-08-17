package client

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	err := s.pool.QueryRow(ctx,
		`SELECT id, client_id, COALESCE(client_secret_hash,''), name, COALESCE(logo_url,''),
                redirect_uris, allowed_scopes, grant_types, require_pkce, is_confidential
         FROM oauth_clients WHERE client_id = $1`,
		clientID,
	).Scan(&c.ID, &c.ClientID, &c.ClientSecret, &c.Name, &c.LogoURL,
		&c.RedirectURIs, &c.AllowedScopes, &c.GrantTypes, &c.RequirePKCE, &c.IsConfidential)
	if err != nil {
		return nil, ErrNotFound
	}
	return &c, nil
}

func (s *Store) Create(ctx context.Context, c *Client) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_clients
            (client_id, client_secret_hash, name, logo_url, redirect_uris,
             allowed_scopes, grant_types, require_pkce, is_confidential)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		c.ClientID, c.ClientSecret, c.Name, c.LogoURL,
		c.RedirectURIs, c.AllowedScopes, c.GrantTypes, c.RequirePKCE, c.IsConfidential,
	)
	return err
}

func (s *Store) List(ctx context.Context) ([]Client, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, client_id, COALESCE(client_secret_hash,''), name, COALESCE(logo_url,''),
                redirect_uris, allowed_scopes, grant_types, require_pkce, is_confidential
         FROM oauth_clients ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ID, &c.ClientID, &c.ClientSecret, &c.Name, &c.LogoURL,
			&c.RedirectURIs, &c.AllowedScopes, &c.GrantTypes, &c.RequirePKCE, &c.IsConfidential); err != nil {
			continue
		}
		clients = append(clients, c)
	}
	return clients, nil
}

func (s *Store) Delete(ctx context.Context, clientID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth_clients WHERE client_id = $1`, clientID)
	return err
}
