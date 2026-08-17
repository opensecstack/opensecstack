//go:build integration

package client

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used elsewhere in sinauth (see
// internal/organization/store_test.go, internal/rbac/store_test.go).
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping client store integration test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testClient(clientID string) *Client {
	return &Client{
		ClientID:       clientID,
		ClientSecret:   "bcrypt-hash-placeholder",
		Name:           "Test Client " + clientID,
		LogoURL:        "https://example.com/logo.png",
		RedirectURIs:   []string{"https://app.example.com/callback"},
		AllowedScopes:  []string{"openid", "profile"},
		GrantTypes:     []string{"authorization_code"},
		RequirePKCE:    true,
		IsConfidential: true,
	}
}

func TestStore_CreateAndGetByClientID(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	c := testClient("store-create-get-1")

	if err := s.Create(context.Background(), c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE client_id=$1`, c.ClientID)
	})

	got, err := s.GetByClientID(context.Background(), c.ClientID)
	if err != nil {
		t.Fatalf("GetByClientID: %v", err)
	}
	if got.ClientID != c.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, c.ClientID)
	}
	if got.Name != c.Name {
		t.Errorf("Name = %q, want %q", got.Name, c.Name)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != c.RedirectURIs[0] {
		t.Errorf("RedirectURIs = %v, want %v", got.RedirectURIs, c.RedirectURIs)
	}
	if !got.RequirePKCE {
		t.Error("expected RequirePKCE=true to round-trip")
	}
}

func TestStore_GetByClientID_NotFound(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	_, err := s.GetByClientID(context.Background(), "no-such-client-id")
	if err != ErrNotFound {
		t.Errorf("GetByClientID error = %v, want ErrNotFound", err)
	}
}

func TestStore_List_IncludesCreatedClients(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	c := testClient("store-list-1")

	if err := s.Create(context.Background(), c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE client_id=$1`, c.ClientID)
	})

	clients, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found bool
	for _, got := range clients {
		if got.ClientID == c.ClientID {
			found = true
		}
	}
	if !found {
		t.Error("List did not include the newly created client")
	}
}

func TestStore_Delete(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	c := testClient("store-delete-1")

	if err := s.Create(context.Background(), c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Delete(context.Background(), c.ClientID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.GetByClientID(context.Background(), c.ClientID); err != ErrNotFound {
		t.Errorf("GetByClientID after Delete: error = %v, want ErrNotFound", err)
	}
}

func TestStore_Create_DuplicateClientIDFails(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	c := testClient("store-dup-1")

	if err := s.Create(context.Background(), c); err != nil {
		t.Fatalf("Create (1st): %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE client_id=$1`, c.ClientID)
	})

	dup := testClient("store-dup-1")
	if err := s.Create(context.Background(), dup); err == nil {
		t.Fatal("Create (2nd, duplicate client_id): expected unique-constraint error, got nil")
	}
}
