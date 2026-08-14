package federation

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Provider represents a configured external identity provider.
type Provider struct {
	ID      string
	Name    string
	Slug    string
	Type    string // "saml" | "oidc" | "ldap"
	Enabled bool

	// SAML
	SAMLMetadataURL string
	SAMLMetadataXML string
	SAMLEntityID    string
	SAMLSSOURI      string
	SAMLCertificate string

	// OIDC upstream
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCScopes       []string

	// LDAP
	LDAPUrl          string
	LDAPBindDN       string
	LDAPBindPassword string
	LDAPBaseDN       string
	LDAPUserFilter   string
	LDAPAttrUsername string
	LDAPAttrEmail    string
	LDAPAttrDisplay  string
	LDAPTLS          bool

	// Attribute mapping
	AttrMapUsername    string
	AttrMapEmail       string
	AttrMapDisplayName string
	AttrMapRole        string
	DefaultRole        string
}

// FederatedIdentity links a sinauth user to their external identity.
type FederatedIdentity struct {
	ID         string
	UserID     string
	ProviderID string
	ExternalID string
	Email      string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// Store handles DB operations for federation.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) ListProviders(ctx context.Context) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, slug, type, enabled,
		       COALESCE(saml_metadata_url,''), COALESCE(saml_metadata_xml,''), COALESCE(saml_entity_id,''), COALESCE(saml_sso_url,''), COALESCE(saml_certificate,''),
		       COALESCE(oidc_issuer,''), COALESCE(oidc_client_id,''), COALESCE(oidc_client_secret,''), COALESCE(oidc_scopes,'{}'),
		       COALESCE(ldap_url,''), COALESCE(ldap_bind_dn,''), COALESCE(ldap_bind_password,''),
		       COALESCE(ldap_base_dn,''), COALESCE(ldap_user_filter,'(sAMAccountName={username})'),
		       COALESCE(ldap_attr_username,'sAMAccountName'), COALESCE(ldap_attr_email,'mail'),
		       COALESCE(ldap_attr_display,'displayName'), COALESCE(ldap_tls, true),
		       COALESCE(attr_map_username,'sub'), COALESCE(attr_map_email,'email'),
		       COALESCE(attr_map_display_name,'name'), COALESCE(attr_map_role,''), default_role
		FROM identity_providers WHERE enabled=true ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []Provider
	for rows.Next() {
		p, err := scanProviderRow(rows)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, nil
}

func (s *Store) GetProviderBySlug(ctx context.Context, slug string) (*Provider, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, slug, type, enabled,
		       COALESCE(saml_metadata_url,''), COALESCE(saml_metadata_xml,''), COALESCE(saml_entity_id,''), COALESCE(saml_sso_url,''), COALESCE(saml_certificate,''),
		       COALESCE(oidc_issuer,''), COALESCE(oidc_client_id,''), COALESCE(oidc_client_secret,''), COALESCE(oidc_scopes,'{}'),
		       COALESCE(ldap_url,''), COALESCE(ldap_bind_dn,''), COALESCE(ldap_bind_password,''),
		       COALESCE(ldap_base_dn,''), COALESCE(ldap_user_filter,'(sAMAccountName={username})'),
		       COALESCE(ldap_attr_username,'sAMAccountName'), COALESCE(ldap_attr_email,'mail'),
		       COALESCE(ldap_attr_display,'displayName'), COALESCE(ldap_tls, true),
		       COALESCE(attr_map_username,'sub'), COALESCE(attr_map_email,'email'),
		       COALESCE(attr_map_display_name,'name'), COALESCE(attr_map_role,''), default_role
		FROM identity_providers WHERE slug=$1`, slug)
	p, err := scanProviderRow(row)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// pgxRow is the subset of pgx.Rows/pgx.Row satisfied by both rows.Scan and
// row.Scan, letting scanProviderRow serve every SELECT-returning method
// that reads a full Provider row.
type pgxRow interface {
	Scan(dest ...any) error
}

// scanProviderRow is the single place that scans a Provider out of a
// SELECT result. Every method that reads a Provider row (ListProviders,
// GetProviderBySlug, and any future ones) must funnel through this so the
// column list only needs to be kept in sync with the SELECT clauses in one
// place — including saml_certificate and saml_metadata_xml, which handlers
// like federation.InitiateSAML/SAMLAcs rely on for assertion validation.
func scanProviderRow(row pgxRow) (Provider, error) {
	var p Provider
	err := row.Scan(
		&p.ID, &p.Name, &p.Slug, &p.Type, &p.Enabled,
		&p.SAMLMetadataURL, &p.SAMLMetadataXML, &p.SAMLEntityID, &p.SAMLSSOURI, &p.SAMLCertificate,
		&p.OIDCIssuer, &p.OIDCClientID, &p.OIDCClientSecret, &p.OIDCScopes,
		&p.LDAPUrl, &p.LDAPBindDN, &p.LDAPBindPassword,
		&p.LDAPBaseDN, &p.LDAPUserFilter,
		&p.LDAPAttrUsername, &p.LDAPAttrEmail, &p.LDAPAttrDisplay, &p.LDAPTLS,
		&p.AttrMapUsername, &p.AttrMapEmail, &p.AttrMapDisplayName, &p.AttrMapRole, &p.DefaultRole,
	)
	return p, err
}

func (s *Store) UpsertFederatedIdentity(ctx context.Context, providerID, externalID, email, userID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO federated_identities (user_id, provider_id, external_id, email)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (provider_id, external_id) DO UPDATE
		  SET last_seen_at=now(), email=EXCLUDED.email`,
		userID, providerID, externalID, email)
	return err
}

func (s *Store) FindUserByFederatedIdentity(ctx context.Context, providerID, externalID string) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id FROM federated_identities WHERE provider_id=$1 AND external_id=$2`,
		providerID, externalID,
	).Scan(&userID)
	return userID, err
}

func (s *Store) CreateProvider(ctx context.Context, p Provider) (string, error) {
	// oidc_scopes is NOT NULL (with a non-empty default). A nil Go slice
	// binds as SQL NULL, which overrides the column default and violates
	// the constraint — so creating any non-OIDC provider (SAML, LDAP) with
	// OIDCScopes left unset always failed. Substitute an empty (non-nil)
	// slice so non-OIDC providers can be created at all.
	oidcScopes := p.OIDCScopes
	if oidcScopes == nil {
		oidcScopes = []string{}
	}

	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO identity_providers
		(name, slug, type, enabled, saml_metadata_url, saml_metadata_xml, saml_entity_id, saml_sso_url, saml_certificate,
		 oidc_issuer, oidc_client_id, oidc_client_secret, oidc_scopes,
		 ldap_url, ldap_bind_dn, ldap_bind_password, ldap_base_dn,
		 ldap_user_filter, ldap_attr_username, ldap_attr_email, ldap_attr_display, ldap_tls,
		 attr_map_username, attr_map_email, attr_map_display_name, attr_map_role, default_role)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
		RETURNING id`,
		p.Name, p.Slug, p.Type, p.Enabled, p.SAMLMetadataURL, p.SAMLMetadataXML, p.SAMLEntityID, p.SAMLSSOURI, p.SAMLCertificate,
		p.OIDCIssuer, p.OIDCClientID, p.OIDCClientSecret, oidcScopes,
		p.LDAPUrl, p.LDAPBindDN, p.LDAPBindPassword, p.LDAPBaseDN,
		p.LDAPUserFilter, p.LDAPAttrUsername, p.LDAPAttrEmail, p.LDAPAttrDisplay, p.LDAPTLS,
		p.AttrMapUsername, p.AttrMapEmail, p.AttrMapDisplayName, p.AttrMapRole, p.DefaultRole,
	).Scan(&id)
	return id, err
}

func (s *Store) DeleteProvider(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM identity_providers WHERE id=$1`, id)
	return err
}

// StoreRelayState persists a SAML relay state token linked to a provider and optional redirect URI.
func (s *Store) StoreRelayState(ctx context.Context, providerID, relayState, redirectURI string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO saml_relay_states (provider_id, relay_state, redirect_uri) VALUES ($1,$2,$3)`,
		providerID, relayState, redirectURI)
	return err
}

// ConsumeRelayState atomically deletes and returns a non-expired relay state record.
func (s *Store) ConsumeRelayState(ctx context.Context, relayState string) (providerID string, redirectURI string, err error) {
	err = s.pool.QueryRow(ctx,
		`DELETE FROM saml_relay_states WHERE relay_state=$1 AND expires_at > now() RETURNING provider_id, redirect_uri`,
		relayState,
	).Scan(&providerID, &redirectURI)
	return
}
