package handlers

import (
	"net/http"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/organization"
)

func ListUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := d.UserSvc.List(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		type userView struct {
			ID            string  `json:"id"`
			Username      string  `json:"username"`
			Email         string  `json:"email"`
			EmailVerified bool    `json:"email_verified"`
			DisplayName   string  `json:"display_name"`
			DeactivatedAt *string `json:"deactivated_at"`
		}

		out := make([]userView, 0, len(users))
		for _, u := range users {
			out = append(out, userView{
				ID:            u.ID,
				Username:      u.Username,
				Email:         u.Email,
				EmailVerified: u.EmailVerified,
				DisplayName:   u.DisplayName,
				DeactivatedAt: u.DeactivatedAt,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}

// MyOrganizations handles GET /api/v1/users/me/organizations — returns the
// authenticated user's organization memberships (ADR 005 v1.1). Used by the
// org-picker UI to render the choices for the organization_id param it will
// re-submit to /oauth/authorize.
func MyOrganizations(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		// Access token "sub" is the username (see Token issuance), not the
		// user id — resolve the id the same way UserInfo does.
		u, err := d.UserSvc.GetByUsername(r.Context(), claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		if d.OrgSvc == nil {
			writeJSON(w, http.StatusOK, []organization.Membership{})
			return
		}
		memberships, err := d.OrgSvc.MembershipsForUser(r.Context(), u.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		writeJSON(w, http.StatusOK, memberships)
	}
}

func DeactivateUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.UserSvc.Deactivate(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		if d.Audit != nil {
			d.Audit.Log("user.deactivated", id, "", r.RemoteAddr, r.UserAgent(), nil)
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "user deactivated"})
	}
}
