package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/opencsirt/internal/db"
	"github.com/opensecstack/opencsirt/internal/incident"
	"github.com/opensecstack/opencsirt/internal/integrations"
)

type Incident struct {
	Service *incident.Service
	NIS2    *integrations.NIS2Client
}

type incidentRequest struct {
	ConstituencyID *uuid.UUID     `json:"constituency_id,omitempty"`
	Source         string         `json:"source"`
	Severity       string         `json:"severity"`
	Title          string         `json:"title"`
	Description    string         `json:"description,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

func (h *Incident) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parseLimitOffset(r, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f := db.IncidentFilter{
		Status:   r.URL.Query().Get("status"),
		Severity: r.URL.Query().Get("severity"),
		Limit:    limit,
		Offset:   offset,
	}
	items, total, err := h.Service.List(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incidents": items,
		"count":     total,
	})
}

func (h *Incident) Create(w http.ResponseWriter, r *http.Request) {
	var req incidentRequest
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if req.Source == "" {
		req.Source = "manual"
	}
	inc, err := h.Service.Create(r.Context(), incident.CreateInput{
		ConstituencyID: req.ConstituencyID,
		Source:         req.Source,
		Severity:       req.Severity,
		Title:          req.Title,
		Description:    req.Description,
		Metadata:       req.Metadata,
	}, actor, role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Article 23 NIS2 notification (best-effort, never fails the API call).
	if h.NIS2 != nil && (req.Severity == "high" || req.Severity == "critical") {
		go func(snap *db.Incident) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = h.NIS2.Notify(ctx, integrations.NIS2Notification{
				IncidentID:     snap.ID,
				ConstituencyID: snap.ConstituencyID,
				Severity:       snap.Severity,
				Title:          snap.Title,
				OpenedAt:       snap.OpenedAt,
				Source:         snap.Source,
			})
		}(inc)
	}

	writeJSON(w, http.StatusCreated, inc)
}

func (h *Incident) Get(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	inc, err := h.Service.Get(r.Context(), id)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (h *Incident) Escalate(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := h.Service.UpdateStatus(r.Context(), id, "triaged", actor, role); err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	inc, err := h.Service.Get(r.Context(), id)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (h *Incident) Close(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	inc, err := h.Service.Close(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}
