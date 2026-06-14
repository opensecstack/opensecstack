package handlers

import (
	"net/http"
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
