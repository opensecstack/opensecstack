package handlers

import (
	"net/http"
	"strings"

	"github.com/opensecstack/sinauth/internal/federation"
)

// ListIdentityProviders returns all configured external IDPs.
// GET /api/v1/federation/providers
func ListIdentityProviders(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providers, err := d.FedStore.ListProviders(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		type providerInfo struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Slug    string `json:"slug"`
			Type    string `json:"type"`
			Enabled bool   `json:"enabled"`
		}
		result := make([]providerInfo, len(providers))
		for i, p := range providers {
			result[i] = providerInfo{ID: p.ID, Name: p.Name, Slug: p.Slug, Type: p.Type, Enabled: p.Enabled}
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// CreateIdentityProvider creates a new external IDP configuration (admin only).
// POST /admin/federation/providers
func CreateIdentityProvider(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p federation.Provider
		if err := decodeJSON(r, &p); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if p.Name == "" || p.Slug == "" || p.Type == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name, slug and type are required"})
			return
		}
		// Default attr mappings
		if p.LDAPUserFilter == "" {
			p.LDAPUserFilter = "(sAMAccountName={username})"
		}
		if p.LDAPAttrUsername == "" {
			p.LDAPAttrUsername = "sAMAccountName"
		}
		if p.LDAPAttrEmail == "" {
			p.LDAPAttrEmail = "mail"
		}
		if p.LDAPAttrDisplay == "" {
			p.LDAPAttrDisplay = "displayName"
		}
		if p.DefaultRole == "" {
			p.DefaultRole = "viewer"
		}
		if p.AttrMapUsername == "" {
			p.AttrMapUsername = "sub"
		}
		if p.AttrMapEmail == "" {
			p.AttrMapEmail = "email"
		}
		if p.AttrMapDisplayName == "" {
			p.AttrMapDisplayName = "name"
		}
		if len(p.OIDCScopes) == 0 {
			p.OIDCScopes = []string{"openid", "profile", "email"}
		}

		id, err := d.FedStore.CreateProvider(r.Context(), p)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create provider"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// DeleteIdentityProvider removes an IDP configuration.
// DELETE /admin/federation/providers/{id}
func DeleteIdentityProvider(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.FedStore.DeleteProvider(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// InitiateOIDCUpstream redirects the user to the upstream OIDC provider.
// GET /federation/oidc/{slug}/authorize
func InitiateOIDCUpstream(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		p, err := d.FedStore.GetProviderBySlug(r.Context(), slug)
		if err != nil || p.Type != "oidc" {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}

		discovery, err := federation.DiscoverOIDC(r.Context(), p.OIDCIssuer)
		if err != nil {
			http.Error(w, "upstream discovery failed", http.StatusBadGateway)
			return
		}

		state, _ := federation.GenerateState()
		nonce, _ := federation.GenerateState()
		redirectURI := d.Cfg.SiteURL + "/federation/oidc/" + slug + "/callback"

		// Store state in DB.
		d.Pool.Exec(r.Context(),
			`INSERT INTO oidc_upstream_states (provider_id, state, nonce, redirect_uri) VALUES ($1,$2,$3,$4)`,
			p.ID, state, nonce, redirectURI,
		)

		authURL := federation.BuildAuthURL(discovery, p, state, nonce, redirectURI)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// OIDCUpstreamCallback handles the callback from an upstream OIDC provider.
// GET /federation/oidc/{slug}/callback
func OIDCUpstreamCallback(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		p, err := d.FedStore.GetProviderBySlug(r.Context(), slug)
		if err != nil || p.Type != "oidc" {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}

		// Validate state.
		var providerID, redirectURI string
		err = d.Pool.QueryRow(r.Context(),
			`DELETE FROM oidc_upstream_states WHERE state=$1 AND expires_at > now() RETURNING provider_id, redirect_uri`,
			state,
		).Scan(&providerID, &redirectURI)
		if err != nil || providerID != p.ID {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}

		discovery, err := federation.DiscoverOIDC(r.Context(), p.OIDCIssuer)
		if err != nil {
			http.Error(w, "upstream discovery failed", http.StatusBadGateway)
			return
		}

		claims, err := federation.ExchangeOIDCCode(r.Context(), discovery, p, code, redirectURI)
		if err != nil {
			http.Error(w, "token exchange failed", http.StatusUnauthorized)
			return
		}

		_, sinToken, err := federatedLogin(r, d, p, claims.Sub, claims.Email, claims.Name)
		if err != nil {
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}

		// Redirect to frontend with token.
		http.Redirect(w, r, d.Cfg.SiteURL+"/auth/callback?token="+sinToken, http.StatusFound)
	}
}

// LDAPLogin authenticates a user against a configured LDAP/AD provider.
// POST /federation/ldap/{slug}/login
func LDAPLogin(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		p, err := d.FedStore.GetProviderBySlug(r.Context(), slug)
		if err != nil || p.Type != "ldap" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
			return
		}

		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		ldapUser, err := federation.AuthenticateLDAP(r.Context(), p, req.Username, req.Password)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}

		_, sinToken, err := federatedLogin(r, d, p, ldapUser.ExternalID, ldapUser.Email, ldapUser.DisplayName)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "login failed"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"access_token": sinToken, "token_type": "Bearer"})
	}
}

// InitiateSAML redirects the browser to the SAML IdP for authentication.
// GET /federation/saml/{slug}/login
func InitiateSAML(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		p, err := d.FedStore.GetProviderBySlug(r.Context(), slug)
		if err != nil || p.Type != "saml" {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}

		acsURL := d.Cfg.SiteURL + "/federation/saml/" + slug + "/acs"
		entityID := d.Cfg.SiteURL + "/federation/saml/" + slug

		sp, err := federation.BuildSAMLSP(p, acsURL, entityID)
		if err != nil {
			http.Error(w, "SAML SP configuration error", http.StatusInternalServerError)
			return
		}

		redirectURL, relayState, err := federation.InitiateSAMLLogin(sp)
		if err != nil {
			http.Error(w, "failed to build SAML request", http.StatusInternalServerError)
			return
		}

		if err := d.FedStore.StoreRelayState(r.Context(), p.ID, relayState, ""); err != nil {
			http.Error(w, "failed to store relay state", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// SAMLAcs handles the SAML Assertion Consumer Service callback from the IdP.
// POST /federation/saml/{slug}/acs
func SAMLAcs(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		slug := r.PathValue("slug")
		p, err := d.FedStore.GetProviderBySlug(r.Context(), slug)
		if err != nil || p.Type != "saml" {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}

		relayState := r.FormValue("RelayState")
		_, _, err = d.FedStore.ConsumeRelayState(r.Context(), relayState)
		if err != nil {
			http.Error(w, "invalid or expired relay state", http.StatusBadRequest)
			return
		}

		acsURL := d.Cfg.SiteURL + "/federation/saml/" + slug + "/acs"
		entityID := d.Cfg.SiteURL + "/federation/saml/" + slug

		sp, err := federation.BuildSAMLSP(p, acsURL, entityID)
		if err != nil {
			http.Error(w, "SAML SP configuration error", http.StatusInternalServerError)
			return
		}

		nameID, email, displayName, err := federation.ParseSAMLResponse(sp, r)
		if err != nil {
			http.Error(w, "SAML response validation failed", http.StatusUnauthorized)
			return
		}

		_, sinToken, err := federatedLogin(r, d, p, nameID, email, displayName)
		if err != nil {
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, d.Cfg.SiteURL+"/auth/callback?token="+sinToken, http.StatusFound)
	}
}

// federatedLogin finds or creates a sinauth user for the federated identity and issues a token.
func federatedLogin(r *http.Request, d Deps, p *federation.Provider, externalID, email, displayName string) (string, string, error) {
	userID, err := d.FedStore.FindUserByFederatedIdentity(r.Context(), p.ID, externalID)
	var role string

	if err != nil {
		// First login — provision the user.
		role = p.DefaultRole
		username := strings.Split(email, "@")[0]
		if username == "" {
			username = "user_" + externalID[:8]
		}
		err = d.Pool.QueryRow(r.Context(),
			`INSERT INTO users (username, display_name, email, role)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (username) DO UPDATE SET display_name=EXCLUDED.display_name, email=EXCLUDED.email
			 RETURNING id, role`,
			username, displayName, email, role,
		).Scan(&userID, &role)
		if err != nil {
			return "", "", err
		}
	} else {
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT role FROM users WHERE id=$1`, userID,
		).Scan(&role); err != nil {
			return "", "", err
		}
	}

	if err := d.FedStore.UpsertFederatedIdentity(r.Context(), p.ID, externalID, email, userID); err != nil {
		return "", "", err
	}

	var username string
	d.Pool.QueryRow(r.Context(), `SELECT username FROM users WHERE id=$1`, userID).Scan(&username)

	tok, err := d.Issuer.IssueAccessToken(username, "sinauth-federation", []string{"openid", "profile", "email"}, d.Cfg.AccessTokenTTL)
	if err != nil {
		return "", "", err
	}
	return userID, tok, nil
}
