package handlers

import (
	"errors"
	"net/http"

	"github.com/opensecstack/opencsirt/internal/constituency"
	"github.com/opensecstack/opencsirt/internal/db"
)

type Constituency struct {
	Service *constituency.Service
}

type constituencyRequest struct {
	Name             string `json:"name"`
	Sector           string `json:"sector"`
	Country          string `json:"country,omitempty"`
	Kind             string `json:"kind"`
	TLPDefault       string `json:"tlp_default"`
	PrimaryContact   string `json:"primary_contact"`
	SecondaryContact string `json:"secondary_contact_email,omitempty"`
}

// kindToNIS2 maps the web's "kind" enum to the DB nis2_status values.
func kindToNIS2(kind string) string {
	if kind == "sector" {
		return "out_of_scope"
	}
	return kind // essential|important pass through unchanged
}

func (h *Constituency) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parseLimitOffset(r, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, total, err := h.Service.List(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"constituencies": items,
		"count":          total,
	})
}

func (h *Constituency) Create(w http.ResponseWriter, r *http.Request) {
	var req constituencyRequest
	if err := decodeJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	c, err := h.Service.Create(r.Context(), constituency.CreateInput{
		Name:                  req.Name,
		Sector:                req.Sector,
		Country:               req.Country,
		NIS2Status:            kindToNIS2(req.Kind),
		TLPDefault:            req.TLPDefault,
		PrimaryContactEmail:   req.PrimaryContact,
		SecondaryContactEmail: req.SecondaryContact,
	}, actor, role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *Constituency) Get(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := h.Service.Get(r.Context(), id)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *Constituency) Update(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req constituencyRequest
	if err := decodeJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	c, err := h.Service.Update(r.Context(), id, constituency.CreateInput{
		Name:                  req.Name,
		Sector:                req.Sector,
		Country:               req.Country,
		NIS2Status:            kindToNIS2(req.Kind),
		TLPDefault:            req.TLPDefault,
		PrimaryContactEmail:   req.PrimaryContact,
		SecondaryContactEmail: req.SecondaryContact,
	}, actor, role)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}
