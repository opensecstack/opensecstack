package handlers

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/opensecstack/opencsirt/internal/advisory"
	"github.com/opensecstack/opencsirt/internal/auth"
	"github.com/opensecstack/opencsirt/internal/db"
)

type Advisory struct {
	Service *advisory.Service
}

type advisoryRequest struct {
	IncidentID *uuid.UUID     `json:"incident_id,omitempty"`
	Title      string         `json:"title"`
	Summary    string         `json:"summary,omitempty"`
	TLP        string         `json:"tlp"`
	IOCs       []advisory.IOC `json:"iocs,omitempty"`
	Vuln       map[string]any `json:"vulnerability,omitempty"`
}

func (h *Advisory) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parseLimitOffset(r, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f := db.AdvisoryFilter{
		State:  r.URL.Query().Get("state"),
		TLP:    r.URL.Query().Get("tlp"),
		Limit:  limit,
		Offset: offset,
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	items, _, err := h.Service.List(r.Context(), f, actor, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// B8: filter AMBER/RED advisories for users below operator rank (rank < 4).
	userRole := auth.Role(role)
	filtered := items[:0]
	for _, a := range items {
		if (a.TLP == "amber" || a.TLP == "red") && auth.Rank(userRole) < 4 {
			continue
		}
		filtered = append(filtered, a)
	}
	items = filtered
	count := len(filtered)

	writeJSON(w, http.StatusOK, map[string]any{
		"advisories": items,
		"count":      count,
	})
}

func (h *Advisory) Create(w http.ResponseWriter, r *http.Request) {
	var req advisoryRequest
	if err := decodeJSON(r, &req, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a, err := h.Service.Create(r.Context(), advisory.CreateInput{
		IncidentID: req.IncidentID,
		Title:      req.Title,
		Summary:    req.Summary,
		TLP:        req.TLP,
		IOCs:       req.IOCs,
		Vuln:       req.Vuln,
	}, actor, role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *Advisory) Get(w http.ResponseWriter, r *http.Request) {
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
	a, err := h.Service.Get(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}

	// B8: block AMBER/RED access for users below operator rank (rank < 4).
	userRole := auth.Role(role)
	if (a.TLP == "amber" || a.TLP == "red") && auth.Rank(userRole) < 4 {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	writeJSON(w, http.StatusOK, a)
}

func (h *Advisory) GetCSAF(w http.ResponseWriter, r *http.Request) {
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
	a, err := h.Service.Get(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	if (a.TLP == "amber" || a.TLP == "red") && auth.Rank(auth.Role(role)) < 4 {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, a.CSAFDoc)
}

func (h *Advisory) Publish(w http.ResponseWriter, r *http.Request) {
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
	a, err := h.Service.Publish(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *Advisory) Withdraw(w http.ResponseWriter, r *http.Request) {
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
	a, err := h.Service.Withdraw(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, a)
}
