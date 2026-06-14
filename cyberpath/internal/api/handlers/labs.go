// Lab session handlers.
//
// v0.0.1 stub funcs (StartLab, StopLab, LabStatus) are retained at the
// bottom as nil-safe fallbacks. v1.0.0 adds LabsHandler which is wired
// to LabStore for real DB-backed sessions.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/cyberpath/internal/db"
)

// DockerProvisioner is the subset of docker.Provisioner that LabsHandler uses.
type DockerProvisioner interface {
	StartContainer(ctx context.Context, def *db.LabDefinition, sessionID string) (string, error)
	StopContainer(ctx context.Context, containerID string) error
}

// ── Interface ─────────────────────────────────────────────────────────────────

// LabSessionManager is the slice of LabStore the handler depends on.
type LabSessionManager interface {
	GetDefinition(ctx context.Context, id string) (*db.LabDefinition, error)
	StartSession(ctx context.Context, labID string, userID uuid.UUID, cohortID *uuid.UUID, tenantID uuid.UUID) (*db.LabSession, error)
	EndSession(ctx context.Context, sessionID uuid.UUID, status string, result json.RawMessage, score *int, auditURL, auditHash string) error
	GetSession(ctx context.Context, id uuid.UUID) (*db.LabSession, error)
	UpdateMetadata(ctx context.Context, sessionID uuid.UUID, metadata json.RawMessage) error
}

// ── Handler struct ────────────────────────────────────────────────────────────

// LabsHandler serves /labs routes backed by LabStore.
type LabsHandler struct {
	Labs   LabSessionManager
	Audit  *db.AuditEventStore
	Docker DockerProvisioner // nil disables container provisioning
	Logger *zerolog.Logger
}

// NewLabsHandler wires a LabsHandler.
func NewLabsHandler(labs LabSessionManager, audit *db.AuditEventStore, logger *zerolog.Logger) *LabsHandler {
	return &LabsHandler{Labs: labs, Audit: audit, Logger: logger}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// Start handles POST /labs/{id}/start.
// {id} is the lab slug (string), NOT a UUID.
func (h *LabsHandler) Start(w http.ResponseWriter, r *http.Request) {
	labSlug := chi.URLParam(r, "id")

	uid, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
		return
	}

	def, err := h.Labs.GetDefinition(r.Context(), labSlug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "lab_not_found", "no lab with id "+labSlug)
			return
		}
		h.log().Error().Err(err).Str("lab_id", labSlug).Msg("labs.start: get definition")
		writeError(w, http.StatusInternalServerError, "internal_error", "lab lookup failed")
		return
	}

	session, err := h.Labs.StartSession(r.Context(), def.ID, uid, nil, uuid.Nil)
	if err != nil {
		h.log().Error().Err(err).Str("lab_id", labSlug).Msg("labs.start: start session")
		writeError(w, http.StatusInternalServerError, "internal_error", "could not start lab session")
		return
	}

	// Spin up a container when Docker provisioning is enabled and the lab
	// runtime is "docker". Store the container ID in session metadata so the
	// terminal relay and Stop handler can reference it.
	if h.Docker != nil && def.Runtime == "docker" {
		containerID, err := h.Docker.StartContainer(r.Context(), def, session.ID.String())
		if err != nil {
			h.log().Error().Err(err).Str("session_id", session.ID.String()).Msg("labs.start: start container")
			_ = h.Labs.EndSession(r.Context(), session.ID, "failed", nil, nil, "", "")
			writeError(w, http.StatusInternalServerError, "container_error", "could not start lab container")
			return
		}

		meta, _ := json.Marshal(map[string]string{"container_id": containerID})
		if err := h.Labs.UpdateMetadata(r.Context(), session.ID, meta); err != nil {
			h.log().Warn().Err(err).Str("session_id", session.ID.String()).Msg("labs.start: update metadata")
			// Non-fatal: the container is running; metadata will just be missing.
		}
	}

	// Best-effort audit emit.
	if h.Audit != nil {
		uidCopy := uid
		_ = h.Audit.Append(r.Context(), &db.AuditEvent{
			ActorUserID: &uidCopy,
			Action:      "lab.start",
			TargetType:  "lab_session",
			TargetID:    session.ID.String(),
			Outcome:     "success",
		})
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"lab_id":             session.LabID,
		"session_id":         session.ID.String(),
		"status":             session.Status,
		"runtime":            session.Runtime,
		"time_limit_seconds": def.TimeLimitSeconds,
	})
}

// Stop handles POST /labs/{id}/stop.
// {id} is the session UUID.
func (h *LabsHandler) Stop(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	sessionID, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "session id must be a UUID")
		return
	}

	// Stop the container before ending the DB session so we don't lose the
	// container ID reference.
	if h.Docker != nil {
		session, err := h.Labs.GetSession(r.Context(), sessionID)
		if err == nil && len(session.Metadata) > 0 {
			var meta struct {
				ContainerID string `json:"container_id"`
			}
			if jsonErr := json.Unmarshal(session.Metadata, &meta); jsonErr == nil && meta.ContainerID != "" {
				if stopErr := h.Docker.StopContainer(r.Context(), meta.ContainerID); stopErr != nil {
					h.log().Warn().Err(stopErr).Str("container_id", meta.ContainerID).Msg("labs.stop: stop container")
					// Non-fatal: continue to end the session.
				}
			}
		}
	}

	if err := h.Labs.EndSession(r.Context(), sessionID, "cancelled", nil, nil, "", ""); err != nil {
		h.log().Error().Err(err).Str("session_id", raw).Msg("labs.stop: end session")
		writeError(w, http.StatusInternalServerError, "internal_error", "could not stop lab session")
		return
	}

	// Best-effort audit emit.
	if h.Audit != nil {
		if uid, ok := userIDFromContext(r.Context()); ok {
			uidCopy := uid
			_ = h.Audit.Append(r.Context(), &db.AuditEvent{
				ActorUserID: &uidCopy,
				Action:      "lab.stop",
				TargetType:  "lab_session",
				TargetID:    raw,
				Outcome:     "success",
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": raw,
		"status":     "cancelled",
	})
}

// Status handles GET /labs/{id}/status.
// {id} is the session UUID.
func (h *LabsHandler) Status(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	sessionID, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "session id must be a UUID")
		return
	}

	session, err := h.Labs.GetSession(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "session_not_found", "no session with id "+raw)
			return
		}
		h.log().Error().Err(err).Str("session_id", raw).Msg("labs.status: get session")
		writeError(w, http.StatusInternalServerError, "internal_error", "session lookup failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": session.ID.String(),
		"lab_id":     session.LabID,
		"status":     session.Status,
		"started_at": session.StartedAt,
		"ended_at":   session.EndedAt,
	})
}

func (h *LabsHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

// ── v0.0.1 stub fallbacks ─────────────────────────────────────────────────────

// StartLab returns a fake session ID; the real runtime ships in v1.0.0.
func StartLab() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		sessionID := "lab_" + uuid.NewString()
		log.Info().Str("event", "labs.start").Str("lab_id", id).Str("session_id", sessionID).Msg("start lab")
		writeJSON(w, http.StatusAccepted, map[string]any{
			"lab_id":     id,
			"session_id": sessionID,
			"status":     "starting",
		})
	}
}

// StopLab marks a lab session as stopped.
func StopLab() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "labs.stop").Str("lab_id", id).Msg("stop lab")
		writeJSON(w, http.StatusOK, map[string]any{
			"lab_id": id,
			"status": "stopped",
		})
	}
}

// LabStatus returns a placeholder running status.
func LabStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "labs.status").Str("lab_id", id).Msg("lab status")
		writeJSON(w, http.StatusOK, map[string]any{
			"lab_id":     id,
			"status":     "running",
			"session_id": "lab_stub_" + id,
		})
	}
}
