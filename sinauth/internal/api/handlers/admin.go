package handlers

import (
	"net/http"
	"strconv"

	"github.com/opensecstack/sinauth/internal/audit"
	"github.com/opensecstack/sinauth/internal/session"
)

func ListAuditLog(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil {
				limit = n
			}
		}
		entries, err := d.Audit.List(r.Context(), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		if entries == nil {
			entries = []audit.Entry{}
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

func ListSessions(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := d.SessionSvc.ListAll(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		if sessions == nil {
			sessions = []session.Session{}
		}
		writeJSON(w, http.StatusOK, sessions)
	}
}

func RevokeSession(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.SessionSvc.Revoke(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		if d.Audit != nil {
			d.Audit.Log("session.revoked", id, "", r.RemoteAddr, r.UserAgent(), nil)
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "session revoked"})
	}
}
