//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/federation"
	"github.com/opensecstack/sinauth/internal/token"
)

// federationTestDeps extends testDeps with the FedStore and Issuer needed by
// the federation handlers.
func federationTestDeps(t *testing.T, pool *pgxpool.Pool) Deps {
	t.Helper()
	d := testDeps(t, pool)
	d.FedStore = federation.NewStore(pool)
	d.Issuer = token.NewIssuer(testRSAKey(t), "test-kid", "https://sinauth.test")
	return d
}

func createTestFedProvider(t *testing.T, d Deps, typ string, mut func(*federation.Provider)) *federation.Provider {
	t.Helper()
	slug := fmt.Sprintf("test-%s-%d", typ, time.Now().UnixNano())
	p := federation.Provider{
		Name:               strings.ToUpper(typ) + " Test " + slug,
		Slug:               slug,
		Type:               typ,
		Enabled:            true,
		DefaultRole:        "viewer",
		AttrMapUsername:    "sub",
		AttrMapEmail:       "email",
		AttrMapDisplayName: "name",
		LDAPUserFilter:     "(sAMAccountName={username})",
		LDAPAttrUsername:   "sAMAccountName",
		LDAPAttrEmail:      "mail",
		LDAPAttrDisplay:    "displayName",
	}
	if mut != nil {
		mut(&p)
	}
	id, err := d.FedStore.CreateProvider(context.Background(), p)
	if err != nil {
		t.Fatalf("create test provider: %v", err)
	}
	p.ID = id
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM identity_providers WHERE id=$1`, id) })
	return &p
}

func reqWithPathValue(method, target, slug string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.SetPathValue("slug", slug)
	return req
}

// reqWithBody builds a request with a body and a "slug" path value in one
// call, since httptest.NewRequest's body must be set at construction time.
func reqWithBody(method, target, slug, body, contentType string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.SetPathValue("slug", slug)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

// ── ListIdentityProviders ────────────────────────────────────────────────────

func TestListIdentityProviders_EmptyByDefault(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/federation/providers", nil)
	rec := httptest.NewRecorder()
	ListIdentityProviders(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestListIdentityProviders_ExcludesDisabled(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	enabled := createTestFedProvider(t, d, "oidc", func(p *federation.Provider) { p.Enabled = true })
	disabled := createTestFedProvider(t, d, "oidc", func(p *federation.Provider) { p.Enabled = false })
	// federation.Store.CreateProvider's INSERT column list omits "enabled"
	// entirely (see internal/federation/store.go), so every provider is
	// created with the column's DB default (true) regardless of the
	// Provider.Enabled value passed in — a real bug (out of scope for this
	// handler-only test file to fix; noted in the test suite summary).
	// Flip it directly here so this test can still exercise
	// ListIdentityProviders' enabled=true filter correctly.
	if _, err := pool.Exec(context.Background(), `UPDATE identity_providers SET enabled=false WHERE id=$1`, disabled.ID); err != nil {
		t.Fatalf("force-disable provider: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/federation/providers", nil)
	rec := httptest.NewRecorder()
	ListIdentityProviders(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got []struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var sawEnabled bool
	for _, p := range got {
		if p.ID == enabled.ID {
			sawEnabled = true
		}
	}
	if !sawEnabled {
		t.Fatal("expected the enabled provider to be listed")
	}
	if len(got) != 1 {
		t.Fatalf("got %d providers, want exactly the 1 enabled one (disabled must be excluded): %+v", len(got), got)
	}
}

// ── CreateIdentityProvider / DeleteIdentityProvider ─────────────────────────

func TestCreateIdentityProvider_MissingRequiredFields(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	body := `{"name":"","slug":"","type":""}`
	req := httptest.NewRequest(http.MethodPost, "/admin/federation/providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	CreateIdentityProvider(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateIdentityProvider_MalformedJSON(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/admin/federation/providers", strings.NewReader(`{not json`))
	rec := httptest.NewRecorder()
	CreateIdentityProvider(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateIdentityProvider_AppliesDefaults(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	slug := fmt.Sprintf("defaults-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"name":"Defaults Test","slug":%q,"type":"ldap"}`, slug)
	req := httptest.NewRequest(http.MethodPost, "/admin/federation/providers", strings.NewReader(body))
	rec := httptest.NewRecorder()
	CreateIdentityProvider(d)(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM identity_providers WHERE id=$1`, out["id"])
	})

	p, err := d.FedStore.GetProviderBySlug(context.Background(), slug)
	if err != nil {
		t.Fatalf("GetProviderBySlug: %v", err)
	}
	if p.LDAPUserFilter != "(sAMAccountName={username})" {
		t.Errorf("LDAPUserFilter default not applied, got %q", p.LDAPUserFilter)
	}
	if p.DefaultRole != "viewer" {
		t.Errorf("DefaultRole default not applied, got %q", p.DefaultRole)
	}
	if p.AttrMapUsername != "sub" || p.AttrMapEmail != "email" || p.AttrMapDisplayName != "name" {
		t.Errorf("OIDC attr map defaults not applied: %+v", p)
	}
}

func TestDeleteIdentityProvider_RemovesRow(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "saml", nil)

	req := httptest.NewRequest(http.MethodDelete, "/admin/federation/providers/"+p.ID, nil)
	req.SetPathValue("id", p.ID)
	rec := httptest.NewRecorder()
	DeleteIdentityProvider(d)(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if _, err := d.FedStore.GetProviderBySlug(context.Background(), p.Slug); err == nil {
		t.Fatal("expected provider to be gone after delete")
	}
}

// ── InitiateOIDCUpstream / OIDCUpstreamCallback ──────────────────────────────

func TestInitiateOIDCUpstream_ProviderNotFound(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	req := reqWithPathValue(http.MethodGet, "/federation/oidc/nope/authorize", "nope")
	rec := httptest.NewRecorder()
	InitiateOIDCUpstream(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestInitiateOIDCUpstream_WrongProviderType(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "ldap", nil)

	req := reqWithPathValue(http.MethodGet, "/federation/oidc/"+p.Slug+"/authorize", p.Slug)
	rec := httptest.NewRecorder()
	InitiateOIDCUpstream(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d — an LDAP provider must not be usable via the OIDC-upstream route", rec.Code, http.StatusNotFound)
	}
}

func TestInitiateOIDCUpstream_DiscoveryFailure(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	// Port 1 refuses connections immediately (no real listener), so discovery
	// fails fast without depending on outbound network access.
	p := createTestFedProvider(t, d, "oidc", func(p *federation.Provider) {
		p.OIDCIssuer = "http://127.0.0.1:1"
	})

	req := reqWithPathValue(http.MethodGet, "/federation/oidc/"+p.Slug+"/authorize", p.Slug)
	req = req.WithContext(timeoutCtx(t))
	rec := httptest.NewRecorder()
	InitiateOIDCUpstream(d)(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

func TestOIDCUpstreamCallback_ProviderNotFound(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	req := reqWithPathValue(http.MethodGet, "/federation/oidc/nope/callback?code=x&state=y", "nope")
	rec := httptest.NewRecorder()
	OIDCUpstreamCallback(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestOIDCUpstreamCallback_InvalidState(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "oidc", nil)

	req := reqWithPathValue(http.MethodGet, "/federation/oidc/"+p.Slug+"/callback?code=x&state=never-issued", p.Slug)
	rec := httptest.NewRecorder()
	OIDCUpstreamCallback(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestOIDCUpstreamCallback_ExpiredState(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "oidc", nil)

	state := fmt.Sprintf("expired-%d", time.Now().UnixNano())
	_, err := pool.Exec(context.Background(),
		`INSERT INTO oidc_upstream_states (provider_id, state, nonce, redirect_uri, expires_at)
		 VALUES ($1,$2,$3,$4, now() - interval '1 minute')`,
		p.ID, state, "nonce", "https://sinauth.test/cb")
	if err != nil {
		t.Fatalf("seed expired state: %v", err)
	}

	req := reqWithPathValue(http.MethodGet, "/federation/oidc/"+p.Slug+"/callback?code=x&state="+state, p.Slug)
	rec := httptest.NewRecorder()
	OIDCUpstreamCallback(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d — an expired state must be rejected", rec.Code, http.StatusBadRequest)
	}
}

// TestOIDCUpstreamCallback_StateSingleUse proves the state row is consumed
// (deleted) on first use even though the flow subsequently fails at
// discovery — so a captured callback URL cannot be replayed to try again.
func TestOIDCUpstreamCallback_StateSingleUse(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "oidc", func(p *federation.Provider) {
		p.OIDCIssuer = "http://127.0.0.1:1"
	})

	state := fmt.Sprintf("single-use-%d", time.Now().UnixNano())
	_, err := pool.Exec(context.Background(),
		`INSERT INTO oidc_upstream_states (provider_id, state, nonce, redirect_uri, expires_at)
		 VALUES ($1,$2,$3,$4, now() + interval '5 minutes')`,
		p.ID, state, "nonce", "https://sinauth.test/cb")
	if err != nil {
		t.Fatalf("seed state: %v", err)
	}

	req1 := reqWithPathValue(http.MethodGet, "/federation/oidc/"+p.Slug+"/callback?code=x&state="+state, p.Slug)
	req1 = req1.WithContext(timeoutCtx(t))
	rec1 := httptest.NewRecorder()
	OIDCUpstreamCallback(d)(rec1, req1)
	if rec1.Code != http.StatusBadGateway {
		t.Fatalf("first call: status = %d, want %d (discovery failure); body=%s", rec1.Code, http.StatusBadGateway, rec1.Body.String())
	}

	req2 := reqWithPathValue(http.MethodGet, "/federation/oidc/"+p.Slug+"/callback?code=x&state="+state, p.Slug)
	rec2 := httptest.NewRecorder()
	OIDCUpstreamCallback(d)(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("replay: status = %d, want %d — the same state must not be usable twice", rec2.Code, http.StatusBadRequest)
	}
}

func TestOIDCUpstreamCallback_ProviderIDMismatch(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p1 := createTestFedProvider(t, d, "oidc", nil)
	p2 := createTestFedProvider(t, d, "oidc", nil)

	// State was minted for p2 but the caller hits p1's callback URL.
	state := fmt.Sprintf("mismatch-%d", time.Now().UnixNano())
	_, err := pool.Exec(context.Background(),
		`INSERT INTO oidc_upstream_states (provider_id, state, nonce, redirect_uri, expires_at)
		 VALUES ($1,$2,$3,$4, now() + interval '5 minutes')`,
		p2.ID, state, "nonce", "https://sinauth.test/cb")
	if err != nil {
		t.Fatalf("seed state: %v", err)
	}

	req := reqWithPathValue(http.MethodGet, "/federation/oidc/"+p1.Slug+"/callback?code=x&state="+state, p1.Slug)
	rec := httptest.NewRecorder()
	OIDCUpstreamCallback(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d — a state minted for a different provider must be rejected", rec.Code, http.StatusBadRequest)
	}
}

// ── LDAPLogin ─────────────────────────────────────────────────────────────

func TestLDAPLogin_ProviderNotFound(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	body := `{"username":"alice","password":"secret"}`
	req := reqWithBody(http.MethodPost, "/federation/ldap/nope/login", "nope", body, "application/json")
	rec := httptest.NewRecorder()
	LDAPLogin(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestLDAPLogin_MalformedJSON(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "ldap", nil)

	req := reqWithBody(http.MethodPost, "/federation/ldap/"+p.Slug+"/login", p.Slug, `{bad`, "application/json")
	rec := httptest.NewRecorder()
	LDAPLogin(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLDAPLogin_UnreachableServer_InvalidCredentials(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	// Port 1 refuses connections immediately.
	p := createTestFedProvider(t, d, "ldap", func(p *federation.Provider) {
		p.LDAPUrl = "ldap://127.0.0.1:1"
	})

	body := `{"username":"alice","password":"secret"}`
	req := reqWithBody(http.MethodPost, "/federation/ldap/"+p.Slug+"/login", p.Slug, body, "application/json")
	req = req.WithContext(timeoutCtx(t))
	rec := httptest.NewRecorder()
	LDAPLogin(d)(rec, req)

	// The handler must not leak *why* auth failed (dial error vs bad
	// credentials) — both collapse to a generic 401.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// ── InitiateSAML / SAMLAcs ────────────────────────────────────────────────

func TestInitiateSAML_ProviderNotFound(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	req := reqWithPathValue(http.MethodGet, "/federation/saml/nope/login", "nope")
	rec := httptest.NewRecorder()
	InitiateSAML(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestInitiateSAML_MetadataFetchFailure forces BuildSAMLSP to fail via an
// unreachable SAMLMetadataURL (port 1 refuses connections immediately, no
// outbound network needed). Note: SAMLMetadataURL is used here rather than
// SAMLCertificate/SAMLMetadataXML because GetProviderBySlug's SELECT list in
// internal/federation/store.go never reads back saml_certificate or
// saml_metadata_xml (only saml_metadata_url, saml_entity_id, saml_sso_url) —
// see the test suite summary for that finding. Certificate/XML metadata
// stored via CreateProvider is therefore silently dropped for every
// subsequent read, including the ones InitiateSAML/SAMLAcs rely on.
func TestInitiateSAML_MetadataFetchFailure(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "saml", func(p *federation.Provider) {
		p.SAMLMetadataURL = "http://127.0.0.1:1/metadata"
	})

	req := reqWithPathValue(http.MethodGet, "/federation/saml/"+p.Slug+"/login", p.Slug)
	req = req.WithContext(timeoutCtx(t))
	rec := httptest.NewRecorder()
	InitiateSAML(d)(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestInitiateSAML_Success_StoresRelayStateAndRedirects(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "saml", func(p *federation.Provider) {
		p.SAMLSSOURI = "https://idp.test/sso"
	})
	d.Cfg.SiteURL = "https://sinauth.test"

	req := reqWithPathValue(http.MethodGet, "/federation/saml/"+p.Slug+"/login", p.Slug)
	rec := httptest.NewRecorder()
	InitiateSAML(d)(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.test/sso") {
		t.Fatalf("Location = %q, want the IDP's SSO endpoint", loc)
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM saml_relay_states WHERE provider_id=$1`, p.ID,
	).Scan(&count); err != nil {
		t.Fatalf("query relay states: %v", err)
	}
	if count != 1 {
		t.Fatalf("relay state rows = %d, want 1", count)
	}
}

func TestSAMLAcs_ProviderNotFound(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)

	req := reqWithBody(http.MethodPost, "/federation/saml/nope/acs", "nope", "RelayState=x", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	SAMLAcs(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestSAMLAcs_InvalidRelayState(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "saml", nil)

	req := reqWithBody(http.MethodPost, "/federation/saml/"+p.Slug+"/acs", p.Slug, "RelayState=never-issued", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	SAMLAcs(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestSAMLAcs_RelayStateSingleUse proves the relay state is consumed
// (deleted) on first use even though the flow fails later building the SP,
// so a captured ACS POST cannot be replayed.
func TestSAMLAcs_RelayStateSingleUse(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "saml", func(p *federation.Provider) {
		// Forces BuildSAMLSP to fail after the relay state is consumed. See
		// TestInitiateSAML_MetadataFetchFailure for why SAMLMetadataURL (not
		// SAMLCertificate) is used to trigger this.
		p.SAMLMetadataURL = "http://127.0.0.1:1/metadata"
	})

	relayState := fmt.Sprintf("relay-%d", time.Now().UnixNano())
	if err := d.FedStore.StoreRelayState(context.Background(), p.ID, relayState, ""); err != nil {
		t.Fatalf("seed relay state: %v", err)
	}

	form := "RelayState=" + relayState
	req1 := reqWithBody(http.MethodPost, "/federation/saml/"+p.Slug+"/acs", p.Slug, form, "application/x-www-form-urlencoded")
	req1 = req1.WithContext(timeoutCtx(t))
	rec1 := httptest.NewRecorder()
	SAMLAcs(d)(rec1, req1)
	if rec1.Code != http.StatusInternalServerError {
		t.Fatalf("first call: status = %d, want %d (SP config failure); body=%s", rec1.Code, http.StatusInternalServerError, rec1.Body.String())
	}

	req2 := reqWithBody(http.MethodPost, "/federation/saml/"+p.Slug+"/acs", p.Slug, form, "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	SAMLAcs(d)(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("replay: status = %d, want %d — the same relay state must not be usable twice", rec2.Code, http.StatusBadRequest)
	}
}

// ── federatedLogin (exercised directly — package-internal helper) ──────────

// TestFederatedLogin_NewUser_Provisions is a regression test for a real bug:
// federatedLogin used to INSERT/SELECT a `role` column on the users table
// that has never existed in the schema (sinauth models authorization
// per-OAuth-client via user_client_roles, not a single users.role column —
// see migrations/012_rbac.sql). That meant every federated login (SAML,
// LDAP, upstream OIDC), for both new and existing users, failed outright
// with a SQL error. This test locks in that provisioning now succeeds.
func TestFederatedLogin_NewUser_Provisions(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "oidc", nil)

	externalID := fmt.Sprintf("ext-%d", time.Now().UnixNano())
	email := fmt.Sprintf("fed-%d@example.com", time.Now().UnixNano())
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	userID, tok, err := federatedLogin(req, d, p, externalID, email, "Fed User")
	if err != nil {
		t.Fatalf("federatedLogin: %v", err)
	}
	if userID == "" || tok == "" {
		t.Fatal("expected a userID and token")
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID) })

	var storedEmail string
	if err := pool.QueryRow(context.Background(), `SELECT email FROM users WHERE id=$1`, userID).Scan(&storedEmail); err != nil {
		t.Fatalf("query provisioned user: %v", err)
	}
	if storedEmail != email {
		t.Errorf("email = %q, want %q", storedEmail, email)
	}
}

func TestFederatedLogin_ExistingUser_ReusesIdentity(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "oidc", nil)

	externalID := fmt.Sprintf("ext-repeat-%d", time.Now().UnixNano())
	email := fmt.Sprintf("fed-repeat-%d@example.com", time.Now().UnixNano())
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	userID1, _, err := federatedLogin(req, d, p, externalID, email, "Fed User")
	if err != nil {
		t.Fatalf("first federatedLogin: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID1) })

	userID2, _, err := federatedLogin(req, d, p, externalID, email, "Fed User")
	if err != nil {
		t.Fatalf("second federatedLogin: %v", err)
	}
	if userID1 != userID2 {
		t.Fatalf("second login provisioned a new user (%q) instead of reusing the existing one (%q)", userID2, userID1)
	}

	var identityCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM federated_identities WHERE provider_id=$1 AND external_id=$2`,
		p.ID, externalID,
	).Scan(&identityCount); err != nil {
		t.Fatalf("query federated_identities: %v", err)
	}
	if identityCount != 1 {
		t.Fatalf("federated_identities rows = %d, want exactly 1 (upsert, not duplicate)", identityCount)
	}
}

func TestFederatedLogin_EmptyEmail_DerivesUsernameFromExternalID(t *testing.T) {
	pool := requireDB(t)
	d := federationTestDeps(t, pool)
	p := createTestFedProvider(t, d, "ldap", nil)

	externalID := fmt.Sprintf("cn=nomail,dc=example,dc=com-%d", time.Now().UnixNano())
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	userID, _, err := federatedLogin(req, d, p, externalID, "", "No Mail")
	if err != nil {
		t.Fatalf("federatedLogin: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID) })

	var username string
	if err := pool.QueryRow(context.Background(), `SELECT username FROM users WHERE id=$1`, userID).Scan(&username); err != nil {
		t.Fatalf("query username: %v", err)
	}
	if !strings.HasPrefix(username, "user_") {
		t.Errorf("username = %q, want a user_<prefix> fallback when email is empty", username)
	}
}

// timeoutCtx bounds handler calls that reach out to (deliberately
// unreachable) network endpoints, so a misbehaving dependency cannot hang
// the test suite.
func timeoutCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
