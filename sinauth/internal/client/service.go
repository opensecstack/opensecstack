package client

import (
	"context"
	"errors"
)

var (
	ErrNotFound        = errors.New("client: not found")
	ErrInvalidRedirect = errors.New("client: redirect_uri not allowed")
	ErrInvalidScope    = errors.New("client: scope not allowed")
)

// Client represents a registered OAuth2 application.
type Client struct {
	ID             string
	ClientID       string
	ClientSecret   string // bcrypt hash; empty for public clients
	Name           string
	LogoURL        string
	RedirectURIs   []string
	AllowedScopes  []string
	GrantTypes     []string
	RequirePKCE    bool
	IsConfidential bool
}

// Service handles OAuth client business logic.
type Service struct {
	store *Store
}

func NewService(store *Store) *Service { return &Service{store: store} }

// GetByClientID fetches a client by its client_id.
func (s *Service) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	return s.store.GetByClientID(ctx, clientID)
}

// ValidateRedirectURI checks that uri is in the client's allowed list.
func (s *Service) ValidateRedirectURI(c *Client, uri string) error {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return nil
		}
	}
	return ErrInvalidRedirect
}

// ValidateScopes checks that all requested scopes are allowed.
func (s *Service) ValidateScopes(c *Client, requested []string) error {
	allowed := make(map[string]struct{}, len(c.AllowedScopes))
	for _, s := range c.AllowedScopes {
		allowed[s] = struct{}{}
	}
	for _, r := range requested {
		if _, ok := allowed[r]; !ok {
			return ErrInvalidScope
		}
	}
	return nil
}

func (s *Service) List(ctx context.Context) ([]Client, error) {
	return s.store.List(ctx)
}

func (s *Service) Create(ctx context.Context, c *Client) error {
	return s.store.Create(ctx, c)
}

func (s *Service) Delete(ctx context.Context, clientID string) error {
	return s.store.Delete(ctx, clientID)
}
