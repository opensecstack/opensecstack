package handlers

import (
	"context"
	"log"
	"net/http"

	"github.com/opensecstack/community/internal/digest"
)

// TriggerDigest handles POST /api/v1/admin/digest/send.
// It fires the weekly digest in the background and returns immediately.
// The caller must have the "admin" role.
func TriggerDigest(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		go func() {
			if err := digest.Run(context.Background(), d.Pool, d.Mailer, d.Cfg); err != nil {
				log.Printf("[digest] background run error: %v", err)
			}
		}()

		writeJSON(w, http.StatusAccepted, map[string]string{
			"status": "digest sending in background",
		})
	}
}
