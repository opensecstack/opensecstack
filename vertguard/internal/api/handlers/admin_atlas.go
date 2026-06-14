package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/threatfeed/atlas"
)

// AtlasSyncer is the narrow interface AdminAtlasHandler depends on so
// tests can inject a fake without HTTP plumbing. atlas.Syncer satisfies it.
type AtlasSyncer interface {
	Sync(ctx context.Context) (atlas.Report, error)
}

// AdminMetrics is the metric surface admin handlers touch — kept narrow
// so handlers don't import the metrics package.
type AdminMetrics interface {
	IncAdminSync(kind, result string)
}

// AdminAtlasHandler triggers an on-demand ATLAS sync. Operators use
// this to recover from a stale cache without restarting pods.
type AdminAtlasHandler struct {
	Syncer  AtlasSyncer
	Sink    audit.Sink
	Logger  *zerolog.Logger
	Metrics AdminMetrics
}

// NewAdminAtlasHandler is a convenience constructor.
func NewAdminAtlasHandler(s AtlasSyncer, sink audit.Sink, logger *zerolog.Logger, m AdminMetrics) *AdminAtlasHandler {
	return &AdminAtlasHandler{Syncer: s, Sink: sink, Logger: logger, Metrics: m}
}

// Sync handles POST /api/v1/admin/atlas/sync.
func (h *AdminAtlasHandler) Sync(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Syncer == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "atlas_unavailable",
			"ATLAS syncer not configured")
		return
	}

	actor, role := callerIdentity(r)

	rep, err := h.Syncer.Sync(r.Context())
	if err != nil {
		h.recordSync(r, actor, role, http.StatusBadGateway, "fail", map[string]any{
			"error": err.Error(),
		})
		if h.Metrics != nil {
			h.Metrics.IncAdminSync("atlas", "fail")
		}
		if h.Logger != nil {
			h.Logger.Warn().Err(err).Str("actor", actor).Msg("admin atlas sync failed")
		}
		writeJSONError(w, http.StatusBadGateway, "atlas_sync_failed", err.Error())
		return
	}

	body := map[string]any{
		"added":       rep.Added,
		"updated":     rep.Updated,
		"removed":     rep.Removed,
		"unchanged":   rep.Unchanged,
		"duration_ms": float64(rep.Duration.Microseconds()) / 1000.0,
	}
	h.recordSync(r, actor, role, http.StatusOK, "ok", body)
	if h.Metrics != nil {
		h.Metrics.IncAdminSync("atlas", "ok")
	}
	if h.Logger != nil {
		h.Logger.Info().
			Str("actor", actor).
			Int("added", rep.Added).
			Int("updated", rep.Updated).
			Int("removed", rep.Removed).
			Dur("duration", rep.Duration).
			Msg("admin atlas sync ok")
	}
	writeJSON(w, http.StatusOK, body)
}

// recordSync emits an explicit ADMIN_ATLAS_SYNC audit event with the
// sync counters in metadata. The generic audit middleware also fires
// at the request boundary; this one carries the structured payload.
func (h *AdminAtlasHandler) recordSync(r *http.Request, actor, role string, status int, outcome string, meta map[string]any) {
	if h == nil || h.Sink == nil {
		return
	}
	metaJSON, _ := json.Marshal(meta)
	auditOutcome := audit.OutcomeSuccess
	switch outcome {
	case "fail":
		auditOutcome = audit.OutcomeError
	}
	ev := audit.Event{
		ID:         uuid.New(),
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Role:       role,
		Action:     "ADMIN_ATLAS_SYNC",
		Outcome:    auditOutcome,
		StatusCode: status,
		RemoteIP:   audit.ParseRemoteIP(r.RemoteAddr),
		Metadata:   metaJSON,
	}
	_ = h.Sink.Record(r.Context(), ev)
}

// callerIdentity pulls actor/role from the verified claims; returns
// "anonymous"/"" when claims are missing (dev-mode requests).
func callerIdentity(r *http.Request) (string, string) {
	if c, ok := auth.ClaimsFromContext(r.Context()); ok && c != nil {
		return c.Sub, c.Role
	}
	return "anonymous", ""
}
