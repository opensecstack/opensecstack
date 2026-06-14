package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

// notificationPrefs holds the canonical set of user notification preferences.
// The legacy comment_email / reaction_email / follow_email columns have been
// consolidated into email_comments / email_reactions / email_follows via migration.
type notificationPrefs struct {
	MentionEmail    bool   `json:"mention_email"`
	DigestEnabled   bool   `json:"digest_enabled"`
	DigestFrequency string `json:"digest_frequency"`
	EmailFollows    bool   `json:"email_follows"`
	EmailComments   bool   `json:"email_comments"`
	EmailReactions  bool   `json:"email_reactions"`
}

func GetNotificationPrefs(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var prefs notificationPrefs
		err := d.Pool.QueryRow(r.Context(), `
			SELECT mention_email, digest_enabled, digest_frequency,
			       email_follows, email_comments, email_reactions
			FROM notification_preferences np
			JOIN users u ON u.id = np.user_id
			WHERE u.username = $1`, claims.Sub).
			Scan(&prefs.MentionEmail, &prefs.DigestEnabled, &prefs.DigestFrequency,
				&prefs.EmailFollows, &prefs.EmailComments, &prefs.EmailReactions)
		if err != nil {
			prefs = notificationPrefs{
				MentionEmail:    true,
				DigestEnabled:   false,
				DigestFrequency: "weekly",
				EmailFollows:    true,
				EmailComments:   true,
				EmailReactions:  false,
			}
		}
		writeJSON(w, http.StatusOK, prefs)
	}
}

func UpdateNotificationPrefs(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req notificationPrefs
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req.DigestFrequency != "weekly" && req.DigestFrequency != "daily" {
			req.DigestFrequency = "weekly"
		}
		_, err := d.Pool.Exec(r.Context(), `
			INSERT INTO notification_preferences
			    (user_id, mention_email, digest_enabled, digest_frequency,
			     email_follows, email_comments, email_reactions, updated_at)
			SELECT u.id, $2, $3, $4, $5, $6, $7, now()
			FROM users u WHERE u.username = $1
			ON CONFLICT (user_id) DO UPDATE SET
			    mention_email    = EXCLUDED.mention_email,
			    digest_enabled   = EXCLUDED.digest_enabled,
			    digest_frequency = EXCLUDED.digest_frequency,
			    email_follows    = EXCLUDED.email_follows,
			    email_comments   = EXCLUDED.email_comments,
			    email_reactions  = EXCLUDED.email_reactions,
			    updated_at       = now()`,
			claims.Sub, req.MentionEmail, req.DigestEnabled, req.DigestFrequency,
			req.EmailFollows, req.EmailComments, req.EmailReactions)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
