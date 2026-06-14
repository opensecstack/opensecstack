package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/opensecstack/sinauth/internal/oidc"
)

// AuthorizeGET shows the login/consent screen or redirects directly if session exists.
// GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...&code_challenge=...
func AuthorizeGET(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		clientID    := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		scope       := q.Get("scope")
		state       := q.Get("state")
		challenge   := q.Get("code_challenge")
		method      := q.Get("code_challenge_method")
		nonce       := q.Get("nonce")

		if q.Get("response_type") != "code" {
			http.Error(w, "unsupported_response_type", http.StatusBadRequest)
			return
		}

		// Validate client
		c, err := d.ClientSvc.GetByClientID(r.Context(), clientID)
		if err != nil {
			http.Error(w, "invalid_client", http.StatusBadRequest)
			return
		}
		if err := d.ClientSvc.ValidateRedirectURI(c, redirectURI); err != nil {
			http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
			return
		}

		scopes := strings.Fields(scope)
		if err := d.ClientSvc.ValidateScopes(c, scopes); err != nil {
			redirectWithError(w, r, redirectURI, state, "invalid_scope")
			return
		}

		if c.RequirePKCE && challenge == "" {
			redirectWithError(w, r, redirectURI, state, "invalid_request")
			return
		}

		// Store params in session cookie, redirect to login page
		// Frontend handles login UI; on success it POSTs to /oauth/authorize
		loginURL := d.Cfg.SiteURL + "/oauth/login?" + r.URL.RawQuery
		_ = method
		_ = nonce // used in POST handler
		http.Redirect(w, r, loginURL, http.StatusFound)
	}
}

// AuthorizePOST handles the login form submission and issues an authorization code.
// POST /oauth/authorize
func AuthorizePOST(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}

		username    := r.FormValue("username")
		password    := r.FormValue("password")
		clientID    := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		scope       := r.FormValue("scope")
		state       := r.FormValue("state")
		challenge   := r.FormValue("code_challenge")
		challengeM  := r.FormValue("code_challenge_method")
		nonce       := r.FormValue("nonce")

		// Authenticate user
		u, err := d.UserSvc.Authenticate(r.Context(), username, password)
		if err != nil {
			redirectWithError(w, r, redirectURI, state, "access_denied")
			return
		}

		scopes := strings.Fields(scope)

		// Issue authorization code (store in DB)
		code, err := issueAuthCode(r.Context(), d, clientID, u.ID, redirectURI, scopes, challenge, challengeM, nonce)
		if err != nil {
			redirectWithError(w, r, redirectURI, state, "server_error")
			return
		}

		// Redirect back to client with code
		redirect, _ := url.Parse(redirectURI)
		q := redirect.Query()
		q.Set("code", code)
		if state != "" {
			q.Set("state", state)
		}
		redirect.RawQuery = q.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	}
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, errCode, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// Ensure oidc import is used (VerifyS256 is called in token.go, but authorize.go imports oidc for
// potential future direct use; suppress unused import with a blank reference if needed).
var _ = oidc.VerifyS256
