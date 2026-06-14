package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

type pushSubscribeRequest struct {
	Endpoint string `json:"endpoint"`
	P256dh   string `json:"p256dh"`
	Auth     string `json:"auth"`
}

type pushUnsubscribeRequest struct {
	Endpoint string `json:"endpoint"`
}

// SubscribePush handles POST /api/v1/me/push-subscription.
// It upserts a push subscription for the authenticated user.
func SubscribePush(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var body pushSubscribeRequest
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if body.Endpoint == "" || body.P256dh == "" || body.Auth == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "endpoint, p256dh and auth are required"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO push_subscriptions(user_id, endpoint, p256dh, auth)
			 VALUES($1, $2, $3, $4)
			 ON CONFLICT(endpoint) DO UPDATE SET p256dh=$3, auth=$4`,
			userID, body.Endpoint, body.P256dh, body.Auth,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save subscription"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// UnsubscribePush handles DELETE /api/v1/me/push-subscription.
// It removes the given push subscription for the authenticated user.
func UnsubscribePush(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var body pushUnsubscribeRequest
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if body.Endpoint == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "endpoint is required"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM push_subscriptions WHERE user_id=$1 AND endpoint=$2`,
			userID, body.Endpoint,
		)

		w.WriteHeader(http.StatusNoContent)
	}
}
