package handlers

import "net/http"

// EndSession implements OIDC RP-Initiated Logout. post_logout_redirect_uri
// is attacker-controlled query input, so it is only honoured when the
// caller also identifies the client via client_id and that client has the
// exact URI registered in its redirect_uris allowlist — the same allowlist
// /oauth/authorize already enforces for the authorization-code flow.
// Without a matching client_id/registered URI, the redirect target falls
// back to the configured SiteURL rather than following the request
// unconditionally, which would otherwise be an open redirect.
func EndSession(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		postLogout := r.URL.Query().Get("post_logout_redirect_uri")
		clientID := r.URL.Query().Get("client_id")
		// Clear SSO session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "sinauth_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   !d.Cfg.DevMode,
		})

		target := d.Cfg.SiteURL
		if postLogout != "" && clientID != "" && d.ClientSvc != nil {
			if c, err := d.ClientSvc.GetByClientID(r.Context(), clientID); err == nil {
				if verr := d.ClientSvc.ValidateRedirectURI(c, postLogout); verr == nil {
					target = postLogout
				}
			}
		}
		http.Redirect(w, r, target, http.StatusFound)
	}
}
