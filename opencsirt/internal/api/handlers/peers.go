package handlers

import (
	"net/http"
	"time"

	"github.com/opensecstack/opencsirt/internal/db"
)

type Peers struct {
	Store *db.PeerStore
}

// peerResponse maps db.PeerCSIRT to the shape the web frontend expects.
// country is mapped from Jurisdiction; all other fields are direct.
type peerResponse struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Country            string     `json:"country"`
	Registry           string     `json:"registry"`
	Trust              string     `json:"trust"`
	LastHandshakeAt    *time.Time `json:"last_handshake_at"`
	Ed25519Fingerprint string     `json:"ed25519_fingerprint"`
}

func toPeerResponse(p *db.PeerCSIRT) peerResponse {
	return peerResponse{
		ID:                 p.ID.String(),
		Name:               p.Name,
		Country:            p.Jurisdiction,
		Registry:           p.Registry,
		Trust:              p.Trust,
		LastHandshakeAt:    p.LastHandshakeAt,
		Ed25519Fingerprint: p.Ed25519Fingerprint,
	}
}

func (h *Peers) List(w http.ResponseWriter, r *http.Request) {
	peers, err := h.Store.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]peerResponse, len(peers))
	for i, p := range peers {
		resp[i] = toPeerResponse(p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"peers": resp, "count": len(resp)})
}

func (h *Peers) Handshake(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.Store.UpdateHandshakeAt(r.Context(), id); err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	p, err := h.Store.Get(r.Context(), id)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, toPeerResponse(p))
}
