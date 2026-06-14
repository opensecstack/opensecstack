package handlers

import "net/http"

// authMethods describes which sign-in options the frontend should render.
// sinauth is the primary, recommended path; native email/password is an
// optional fallback that can be disabled in integrated SIN deployments.
type authMethods struct {
	Sinauth        bool `json:"sinauth"`
	SinauthPrimary bool `json:"sinauth_primary"`
	Native         bool `json:"native"`
	GitHub         bool `json:"github"`
	Google         bool `json:"google"`
}

// AuthMethods reports the enabled authentication methods so the login/register
// UI is driven by server config rather than hardcoded provider buttons.
// GET /api/v1/auth/methods (public, unauthenticated)
func AuthMethods(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sinauthOn := d.Cfg.SinauthClientID != ""
		writeJSON(w, http.StatusOK, authMethods{
			Sinauth:        sinauthOn,
			SinauthPrimary: sinauthOn,
			Native:         d.Cfg.NativeAuthEnabled,
			GitHub:         d.Cfg.GitHubClientID != "",
			Google:         d.Cfg.GoogleClientID != "",
		})
	}
}
