// Package handlers carries the HTTP handlers for the OpenScrub control
// plane API. Routes are registered in internal/api/server.go.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/auth"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
	"github.com/opensecstack/openscrub/internal/version"
)

// Pinger is the minimum DB-health surface /api/v1/health needs.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Health is the handler set for /api/v1/health.
type Health struct {
	DB                 Pinger
	Plane              dataplane.Client
	DataplaneAttached  func() bool
}

// Get returns the liveness document. /health answers "the process
// is up and able to serve traffic" — it must NOT fail just because
// the dataplane has detached or the DB is being failed over, so
// Kubernetes does not kill a node that could otherwise recover.
// For "ready to receive traffic" semantics use /readyz instead.
func (h *Health) Get(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":  "ok",
		"version": version.Version,
	}
	if h.DB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2_000_000_000)
		defer cancel()
		if err := h.DB.Ping(ctx); err != nil {
			resp["db_ping"] = false
			resp["status"] = "degraded"
		} else {
			resp["db_ping"] = true
		}
	} else {
		resp["db_ping"] = false
	}
	if h.DataplaneAttached != nil {
		resp["dataplane_attached"] = h.DataplaneAttached()
	} else {
		resp["dataplane_attached"] = false
	}
	writeJSON(w, http.StatusOK, resp)
}

// Ready answers Kubernetes' readinessProbe. It returns 503 unless
// every hard dependency is healthy:
//   - DB reachable (when configured)
//   - Dataplane attached (when transport != noop)
//
// Liveness (/health) keeps returning 200 with status="degraded" so
// the pod is not restarted; readiness pulls the pod out of the
// service's endpoints until the dependency recovers. Splitting the
// two probes is a Kubernetes best practice — the prior single
// /health endpoint conflated the two and caused unnecessary pod
// restarts during transient DB failovers.
func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":  "ready",
		"version": version.Version,
	}
	ready := true

	if h.DB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2_000_000_000)
		defer cancel()
		if err := h.DB.Ping(ctx); err != nil {
			resp["db_ping"] = false
			resp["status"] = "not_ready"
			resp["reason"] = "db ping failed: " + err.Error()
			ready = false
		} else {
			resp["db_ping"] = true
		}
	}

	if ready && h.DataplaneAttached != nil {
		attached := h.DataplaneAttached()
		resp["dataplane_attached"] = attached
		if !attached {
			resp["status"] = "not_ready"
			resp["reason"] = "dataplane not attached"
			ready = false
		}
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, resp)
}

// Rules carries the dependencies of the /api/v1/rules handler set.
type Rules struct {
	Service *rules.Service
	Logger  zerolog.Logger
}

// List handles GET /api/v1/rules.
//
// Pagination — `offset + limit` with stable order
// `(created_at DESC, id DESC)`. The OpenAPI spec advertised these query
// params but earlier revisions silently dropped `offset`, returning the
// first page over and over for every page > 1. The handler now reads
// both, clamps `offset` to >= 0, and lets the service layer honor them.
func (h *Rules) List(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	kind := rules.Type(r.URL.Query().Get("type"))
	out, err := h.Service.List(r.Context(), kind, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	if out == nil {
		out = []rules.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "count": len(out)})
}

// Create handles POST /api/v1/rules.
func (h *Rules) Create(w http.ResponseWriter, r *http.Request) {
	var req rules.CreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	// Reject trailing JSON (e.g. an array of bodies smuggled past the
	// first-element decode) — DisallowUnknownFields handles per-object
	// surface area; this guards the document-level shape.
	if dec.More() {
		writeError(w, http.StatusBadRequest, "bad_json", "trailing data after json object")
		return
	}
	principal, createdBy := principalFromCtx(r.Context())
	if req.Source == "" {
		req.Source = rules.SourceOperator
	}
	out, err := h.Service.Create(r.Context(), req, principal, createdBy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// Delete handles DELETE /api/v1/rules/{id}.
func (h *Rules) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", err.Error())
		return
	}
	principal, _ := principalFromCtx(r.Context())
	reason := r.URL.Query().Get("reason")
	// Reason flows verbatim into the CITADEL rule_change event and the
	// audit log. Cap the size so a 10MB query string doesn't show up in
	// the WORM stream, and refuse control characters that would break
	// log parsers downstream.
	const maxReason = 512
	if len(reason) > maxReason {
		writeError(w, http.StatusBadRequest, "bad_reason",
			fmt.Sprintf("reason exceeds %d bytes", maxReason))
		return
	}
	for _, c := range reason {
		if c < 0x20 && c != '\t' {
			writeError(w, http.StatusBadRequest, "bad_reason",
				"reason contains control characters")
			return
		}
	}
	if err := h.Service.Delete(r.Context(), id, principal, reason); err != nil {
		if errors.Is(err, rules.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Get handles GET /api/v1/rules/{id}.
func (h *Rules) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", err.Error())
		return
	}
	out, err := h.Service.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, rules.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// principalFromCtx returns the JWT subject string and the parsed UUID
// (if Sub is a UUID) for the current request. In dev mode (no claims)
// returns ("anonymous", nil).
func principalFromCtx(ctx context.Context) (string, *uuid.UUID) {
	c, ok := auth.FromContext(ctx)
	if !ok || c == nil {
		return "anonymous", nil
	}
	principal := c.Sub
	if principal == "" {
		principal = "anonymous"
	}
	if id, err := uuid.Parse(c.Sub); err == nil {
		return principal, &id
	}
	return principal, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
