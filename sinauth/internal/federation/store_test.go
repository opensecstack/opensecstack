//go:build integration

package federation

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used elsewhere in sinauth (see
// internal/organization/store_test.go, internal/rbac/store_test.go).
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping federation store integration test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// createTestUser inserts a minimal user row and returns its id.
func createTestUser(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id`,
		username, username+"@example.com",
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTestUser: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, id) })
	return id
}

// createTestProvider inserts a minimal identity_providers row and returns its id.
func createTestProvider(t *testing.T, pool *pgxpool.Pool, s *Store, p Provider) string {
	t.Helper()
	id, err := s.CreateProvider(context.Background(), p)
	if err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM identity_providers WHERE id=$1`, id) })
	return id
}

func TestStore_CreateAndGetProviderBySlug(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	id := createTestProvider(t, pool, s, Provider{
		Name:         "Test SAML IdP",
		Slug:         "test-saml-idp",
		Type:         "saml",
		Enabled:      true,
		SAMLEntityID: "https://idp.example.com",
		SAMLSSOURI:   "https://idp.example.com/sso",
		DefaultRole:  "viewer",
	})
	if id == "" {
		t.Fatal("CreateProvider returned empty id")
	}

	p, err := s.GetProviderBySlug(context.Background(), "test-saml-idp")
	if err != nil {
		t.Fatalf("GetProviderBySlug: %v", err)
	}
	if p.ID != id {
		t.Errorf("ID = %q, want %q", p.ID, id)
	}
	if p.Name != "Test SAML IdP" {
		t.Errorf("Name = %q, want Test SAML IdP", p.Name)
	}
	if p.Type != "saml" {
		t.Errorf("Type = %q, want saml", p.Type)
	}
	if !p.Enabled {
		t.Error("expected provider created with Enabled: true to read back enabled=true")
	}
}

func TestStore_GetProviderBySlug_NotFound(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	_, err := s.GetProviderBySlug(context.Background(), "does-not-exist-slug")
	if err == nil {
		t.Fatal("GetProviderBySlug: expected error for unknown slug, got nil")
	}
}

func TestStore_ListProviders_OnlyReturnsEnabled(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	enabledID := createTestProvider(t, pool, s, Provider{
		Name: "Enabled Provider", Slug: "enabled-provider-list-test", Type: "oidc", Enabled: true,
		OIDCIssuer: "https://upstream.example", DefaultRole: "viewer",
	})

	// CreateProvider now honors the Enabled field (previously the INSERT
	// omitted the enabled column entirely, so every provider silently got
	// the DB default of true regardless of what the caller asked for).
	disabledID := createTestProvider(t, pool, s, Provider{
		Name: "Disabled Provider", Slug: "disabled-provider-list-test", Type: "oidc", Enabled: false,
		OIDCIssuer: "https://upstream.example", DefaultRole: "viewer",
	})

	providers, err := s.ListProviders(context.Background())
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}

	var sawEnabled, sawDisabled bool
	for _, p := range providers {
		if p.ID == enabledID {
			sawEnabled = true
		}
		if p.ID == disabledID {
			sawDisabled = true
		}
	}
	if !sawEnabled {
		t.Error("ListProviders did not return the enabled provider")
	}
	if sawDisabled {
		t.Error("ListProviders returned a disabled provider — should be filtered out")
	}
}

// TestStore_CreateProvider_DisabledByDefault proves an admin can provision
// a disabled-by-default federation provider through CreateProvider. The
// INSERT previously omitted the enabled column entirely, so every provider
// silently got the DB default (true) no matter what the caller asked for —
// this reads the row back directly (bypassing ListProviders' enabled=true
// filter) via GetProviderBySlug to confirm the false value survived the
// round trip.
func TestStore_CreateProvider_DisabledByDefault(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	id := createTestProvider(t, pool, s, Provider{
		Name: "Disabled By Default", Slug: "disabled-by-default-test", Type: "oidc", Enabled: false,
		OIDCIssuer: "https://upstream.example", DefaultRole: "viewer",
	})

	p, err := s.GetProviderBySlug(context.Background(), "disabled-by-default-test")
	if err != nil {
		t.Fatalf("GetProviderBySlug: %v", err)
	}
	if p.ID != id {
		t.Errorf("ID = %q, want %q", p.ID, id)
	}
	if p.Enabled {
		t.Error("expected provider created with Enabled: false to read back enabled=false, got true")
	}
}

// TestStore_SAMLCertificateAndMetadataXML_RoundTrip proves a SAML signing
// certificate and metadata XML configured on a provider are not lost on
// read. Both GetProviderBySlug and ListProviders previously selected
// saml_metadata_url/saml_entity_id/saml_sso_url but never
// saml_certificate or saml_metadata_xml, so any admin-configured signing
// certificate was silently dropped on every read — including the reads
// federation.InitiateSAML/SAMLAcs rely on for assertion validation.
func TestStore_SAMLCertificateAndMetadataXML_RoundTrip(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	const cert = "-----BEGIN CERTIFICATE-----\nMIIBtestcertificatedata\n-----END CERTIFICATE-----"
	const metadataXML = `<EntityDescriptor entityID="https://idp.example.com"></EntityDescriptor>`

	id := createTestProvider(t, pool, s, Provider{
		Name: "SAML Cert Provider", Slug: "saml-cert-provider-test", Type: "saml", Enabled: true,
		SAMLEntityID:    "https://idp.example.com",
		SAMLSSOURI:      "https://idp.example.com/sso",
		SAMLCertificate: cert,
		SAMLMetadataXML: metadataXML,
		DefaultRole:     "viewer",
	})

	byslug, err := s.GetProviderBySlug(context.Background(), "saml-cert-provider-test")
	if err != nil {
		t.Fatalf("GetProviderBySlug: %v", err)
	}
	if byslug.SAMLCertificate != cert {
		t.Errorf("GetProviderBySlug: SAMLCertificate = %q, want %q", byslug.SAMLCertificate, cert)
	}
	if byslug.SAMLMetadataXML != metadataXML {
		t.Errorf("GetProviderBySlug: SAMLMetadataXML = %q, want %q", byslug.SAMLMetadataXML, metadataXML)
	}

	providers, err := s.ListProviders(context.Background())
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}
	var found bool
	for _, p := range providers {
		if p.ID != id {
			continue
		}
		found = true
		if p.SAMLCertificate != cert {
			t.Errorf("ListProviders: SAMLCertificate = %q, want %q", p.SAMLCertificate, cert)
		}
		if p.SAMLMetadataXML != metadataXML {
			t.Errorf("ListProviders: SAMLMetadataXML = %q, want %q", p.SAMLMetadataXML, metadataXML)
		}
	}
	if !found {
		t.Fatal("ListProviders did not return the SAML cert provider")
	}
}

func TestStore_DeleteProvider(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	id, err := s.CreateProvider(context.Background(), Provider{
		Name: "To Delete", Slug: "to-delete-provider-test", Type: "ldap", DefaultRole: "viewer",
	})
	if err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}

	if err := s.DeleteProvider(context.Background(), id); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}

	if _, err := s.GetProviderBySlug(context.Background(), "to-delete-provider-test"); err == nil {
		t.Error("expected provider to be gone after DeleteProvider, but GetProviderBySlug succeeded")
	}
}

func TestStore_UpsertAndFindFederatedIdentity(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	userID := createTestUser(t, pool, "fed-upsert-user")
	providerID := createTestProvider(t, pool, s, Provider{
		Name: "Upsert Test Provider", Slug: "upsert-test-provider", Type: "oidc",
		OIDCIssuer: "https://upstream.example", DefaultRole: "viewer",
	})

	if err := s.UpsertFederatedIdentity(context.Background(), providerID, "external-sub-1", "user@example.com", userID); err != nil {
		t.Fatalf("UpsertFederatedIdentity (insert): %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM federated_identities WHERE provider_id=$1 AND external_id=$2`, providerID, "external-sub-1")
	})

	gotUserID, err := s.FindUserByFederatedIdentity(context.Background(), providerID, "external-sub-1")
	if err != nil {
		t.Fatalf("FindUserByFederatedIdentity: %v", err)
	}
	if gotUserID != userID {
		t.Errorf("FindUserByFederatedIdentity = %q, want %q", gotUserID, userID)
	}

	// Upserting again with the same (provider_id, external_id) must update
	// in place, not create a duplicate row or error out — this is what makes
	// repeat SSO logins for the same external identity idempotent.
	if err := s.UpsertFederatedIdentity(context.Background(), providerID, "external-sub-1", "updated@example.com", userID); err != nil {
		t.Fatalf("UpsertFederatedIdentity (update): %v", err)
	}
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM federated_identities WHERE provider_id=$1 AND external_id=$2`,
		providerID, "external-sub-1",
	).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly one federated_identities row after re-upsert, got %d", count)
	}
}

func TestStore_FindUserByFederatedIdentity_NotFound(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	providerID := createTestProvider(t, pool, s, Provider{
		Name: "No Identity Provider", Slug: "no-identity-provider-test", Type: "oidc",
		OIDCIssuer: "https://upstream.example", DefaultRole: "viewer",
	})

	_, err := s.FindUserByFederatedIdentity(context.Background(), providerID, "no-such-external-id")
	if err == nil {
		t.Fatal("FindUserByFederatedIdentity: expected error for unknown external id, got nil")
	}
}

func TestStore_RelayState_StoreAndConsume(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	providerID := createTestProvider(t, pool, s, Provider{
		Name: "Relay State Provider", Slug: "relay-state-provider-test", Type: "saml",
		SAMLEntityID: "https://idp.example.com", SAMLSSOURI: "https://idp.example.com/sso", DefaultRole: "viewer",
	})

	if err := s.StoreRelayState(context.Background(), providerID, "relay-abc123", "https://sin.to/after-login"); err != nil {
		t.Fatalf("StoreRelayState: %v", err)
	}

	gotProviderID, gotRedirect, err := s.ConsumeRelayState(context.Background(), "relay-abc123")
	if err != nil {
		t.Fatalf("ConsumeRelayState: %v", err)
	}
	if gotProviderID != providerID {
		t.Errorf("providerID = %q, want %q", gotProviderID, providerID)
	}
	if gotRedirect != "https://sin.to/after-login" {
		t.Errorf("redirectURI = %q, want https://sin.to/after-login", gotRedirect)
	}
}

// TestStore_RelayState_ConsumeIsOneTimeUse is a replay-protection test: a
// SAML relay state must not be usable twice. If ConsumeRelayState only read
// the row instead of atomically deleting it, an attacker who intercepted or
// guessed a relay state could replay the SSO callback and potentially hijack
// or fixate the flow. The DELETE ... RETURNING in Store.ConsumeRelayState is
// what should make the second call fail.
func TestStore_RelayState_ConsumeIsOneTimeUse(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	providerID := createTestProvider(t, pool, s, Provider{
		Name: "Replay Test Provider", Slug: "replay-test-provider", Type: "saml",
		SAMLEntityID: "https://idp.example.com", SAMLSSOURI: "https://idp.example.com/sso", DefaultRole: "viewer",
	})

	if err := s.StoreRelayState(context.Background(), providerID, "relay-onetime-1", ""); err != nil {
		t.Fatalf("StoreRelayState: %v", err)
	}

	if _, _, err := s.ConsumeRelayState(context.Background(), "relay-onetime-1"); err != nil {
		t.Fatalf("ConsumeRelayState (1st, should succeed): %v", err)
	}

	if _, _, err := s.ConsumeRelayState(context.Background(), "relay-onetime-1"); err == nil {
		t.Fatal("ConsumeRelayState (2nd call): expected error — relay state must be single-use (replay protection)")
	}
}

// TestStore_RelayState_ExpiredIsRejected proves an expired relay state
// cannot be consumed, closing the window for a stale/leaked relay state to
// be replayed long after the login attempt should have timed out.
func TestStore_RelayState_ExpiredIsRejected(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	providerID := createTestProvider(t, pool, s, Provider{
		Name: "Expired Relay Provider", Slug: "expired-relay-provider", Type: "saml",
		SAMLEntityID: "https://idp.example.com", SAMLSSOURI: "https://idp.example.com/sso", DefaultRole: "viewer",
	})

	// Insert directly with an already-past expires_at, since StoreRelayState
	// always uses the table default (+10 minutes from now).
	_, err := pool.Exec(context.Background(), `
		INSERT INTO saml_relay_states (provider_id, relay_state, redirect_uri, expires_at)
		VALUES ($1, $2, '', $3)`,
		providerID, "relay-expired-1", time.Now().Add(-time.Minute),
	)
	if err != nil {
		t.Fatalf("insert expired relay state: %v", err)
	}

	if _, _, err := s.ConsumeRelayState(context.Background(), "relay-expired-1"); err == nil {
		t.Fatal("ConsumeRelayState: expected error for expired relay state, got nil")
	}
}
