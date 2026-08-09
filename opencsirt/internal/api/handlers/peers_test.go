package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/opencsirt/internal/db"
)

func TestToPeerResponse_MapsJurisdictionToCountryAndPreservesFields(t *testing.T) {
	id := uuid.New()
	now := time.Now().UTC()
	p := &db.PeerCSIRT{
		ID:                 id,
		Name:               "Peer A",
		Jurisdiction:       "AL",
		Registry:           "trusted-introducer",
		Trust:              "verified",
		LastHandshakeAt:    &now,
		Ed25519Fingerprint: "abcd1234",
	}
	resp := toPeerResponse(p)

	if resp.ID != id.String() {
		t.Errorf("ID = %q, want %q", resp.ID, id.String())
	}
	if resp.Country != "AL" {
		t.Errorf("Country = %q, want %q (mapped from Jurisdiction)", resp.Country, "AL")
	}
	if resp.Name != "Peer A" {
		t.Errorf("Name = %q, want Peer A", resp.Name)
	}
	if resp.Registry != "trusted-introducer" {
		t.Errorf("Registry = %q, want trusted-introducer", resp.Registry)
	}
	if resp.Trust != "verified" {
		t.Errorf("Trust = %q, want verified", resp.Trust)
	}
	if resp.LastHandshakeAt == nil || !resp.LastHandshakeAt.Equal(now) {
		t.Errorf("LastHandshakeAt = %v, want %v", resp.LastHandshakeAt, now)
	}
	if resp.Ed25519Fingerprint != "abcd1234" {
		t.Errorf("Ed25519Fingerprint = %q, want abcd1234", resp.Ed25519Fingerprint)
	}
}

func TestPeersHandshake_InvalidUUIDReturns400WithoutTouchingStore(t *testing.T) {
	h := &Peers{Store: nil}
	req := httptest.NewRequest(http.MethodPost, "/peers/not-a-uuid/handshake", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Handshake(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
