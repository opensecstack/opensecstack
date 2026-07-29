package handlers

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/opensecstack/sinauth/internal/oidc"
	"github.com/opensecstack/sinauth/internal/user"
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
		organizationID := q.Get("organization_id")

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
		//
		// organization_id (ADR 005 v1.1) survives this round-trip for free:
		// r.URL.RawQuery is forwarded wholesale below, so any unrecognized
		// param (organization_id included) is preserved without extra code.
		loginURL := d.Cfg.SiteURL + "/oauth/login?" + r.URL.RawQuery
		_ = method
		_ = nonce          // used in POST handler
		_ = organizationID // used in POST handler; passed through via RawQuery above
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
		organizationID := r.FormValue("organization_id")

		// Authenticate user
		u, err := d.UserSvc.Authenticate(r.Context(), username, password)
		if err != nil {
			redirectWithError(w, r, redirectURI, state, "access_denied")
			return
		}

		scopes := strings.Fields(scope)

		// Resolve organization context (ADR 005 v1.1). sinauth never guesses
		// which organization a token should represent:
		//   - an explicit organization_id is validated against real
		//     membership (403 if the user isn't a member) and, once
		//     validated, flows into the issued code;
		//   - with no explicit organization_id and more than one
		//     membership, the user is sent to the org-picker instead of
		//     getting a code — silently picking one would be a security bug;
		//   - with no explicit organization_id and 0 or 1 membership, the
		//     flow proceeds exactly as it did before this ADR: no code is
		//     issued, no picker is required. This deliberately does NOT
		//     auto-select the single organization a user belongs to — a
		//     future contributor may be tempted to "helpfully" add that,
		//     but ADR 005 requires an explicit, caller-supplied choice
		//     before any token carries org claims, regardless of how many
		//     organizations are available to pick from.
		validatedOrgID, needsPicker, forbidden, err := resolveOrganizationContext(r.Context(), d, u, organizationID)
		if err != nil {
			redirectWithError(w, r, redirectURI, state, "server_error")
			return
		}
		if forbidden {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":             "forbidden",
				"error_description": "user is not a member of the requested organization",
			})
			return
		}
		if needsPicker {
			// Mirrors the AuthorizeGET → /oauth/login redirect exactly:
			// same wholesale RawQuery passthrough, same 302 status.
			orgPickerURL := d.Cfg.SiteURL + "/oauth/org-picker?" + r.URL.RawQuery
			http.Redirect(w, r, orgPickerURL, http.StatusFound)
			return
		}

		// Issue authorization code (store in DB)
		code, err := issueAuthCode(r.Context(), d, clientID, u.ID, redirectURI, scopes, challenge, challengeM, nonce, validatedOrgID)
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

// resolveOrganizationContext implements the ADR 005 v1.1 "never guess"
// resolution rule for /oauth/authorize:
//
//   - organizationID != "": validated against the user's real memberships.
//     Returns forbidden=true (no orgID) if the user isn't actually a member —
//     the caller-supplied value is never trusted blindly.
//   - organizationID == "" and the user belongs to more than one
//     organization: returns needsPicker=true so the caller can redirect to
//     the org-picker instead of issuing a code.
//   - organizationID == "" and the user belongs to 0 or 1 organizations:
//     returns no org and no picker — the pre-ADR-005 individual flow,
//     unchanged. See the comment in AuthorizePOST for why the 1-membership
//     case is not auto-selected.
//
// If d.OrgSvc is nil (e.g. not wired in a given deployment/test), organization
// context is simply unavailable and the flow proceeds as pure-individual.
func resolveOrganizationContext(ctx context.Context, d Deps, u *user.User, organizationID string) (orgID *string, needsPicker bool, forbidden bool, err error) {
	if d.OrgSvc == nil {
		return nil, false, false, nil
	}

	memberships, err := d.OrgSvc.MembershipsForUser(ctx, u.ID)
	if err != nil {
		return nil, false, false, err
	}

	if organizationID != "" {
		for _, m := range memberships {
			if m.OrganizationID == organizationID {
				id := m.OrganizationID
				return &id, false, false, nil
			}
		}
		return nil, false, true, nil
	}

	if len(memberships) > 1 {
		return nil, true, false, nil
	}

	// 0 or exactly 1 membership with no explicit organization_id: proceed
	// unchanged, intentionally not auto-selecting the single membership.
	return nil, false, false, nil
}

// Ensure oidc import is used (VerifyS256 is called in token.go, but authorize.go imports oidc for
// potential future direct use; suppress unused import with a blank reference if needed).
var _ = oidc.VerifyS256
