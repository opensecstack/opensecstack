package handlers

import "net/http"

func EndSession(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		postLogout := r.URL.Query().Get("post_logout_redirect_uri")
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
		if postLogout != "" {
			http.Redirect(w, r, postLogout, http.StatusFound)
			return
		}
		http.Redirect(w, r, d.Cfg.SiteURL, http.StatusFound)
	}
}
