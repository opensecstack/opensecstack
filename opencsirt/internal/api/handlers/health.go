package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Health struct {
	Pool      *pgxpool.Pool
	Advisory  func(context.Context) error // Python advisory health probe
	StartedAt time.Time
}

func (h *Health) Get(w http.ResponseWriter, r *http.Request) {
	dbOK := h.dbPing(r.Context())
	advOK := true
	if h.Advisory != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()
		if err := h.Advisory(ctx); err != nil {
			advOK = false
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"db":               dbOK,
		"advisory_service": advOK,
		"uptime_seconds":   int(time.Since(h.StartedAt).Seconds()),
	})
}

func (h *Health) dbPing(ctx context.Context) bool {
	if h.Pool == nil {
		return false
	}
	c, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	return h.Pool.Ping(c) == nil
}
