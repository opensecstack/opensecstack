package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

// fakeKeysStore is an in-memory keysStore for handler unit tests — no
// Postgres required. A real end-to-end proof (register a key → sign a
// Kerkese → POST /marshal/evaluate → confirm sig_operator/sig_verifier land
// in worm_entries) requires a live database and sinauth instance and is
// exercised at the gate level instead by marshal_test.go's
// TestGate5_PersistsSignatures / TestEvaluate_Execute_AllGatesPass, which
// cover the same sign→verify→persist path without either dependency.
type fakeKeysStore struct {
	keys map[string]struct {
		keyID        string
		registeredAt time.Time
	}
	registerErr error
}

func newFakeKeysStore() *fakeKeysStore {
	return &fakeKeysStore{
		keys: make(map[string]struct {
			keyID        string
			registeredAt time.Time
		}),
	}
}

func (f *fakeKeysStore) RegisterKey(_ context.Context, userID, keyID, _ string) error {
	if f.registerErr != nil {
		return f.registerErr
	}
	f.keys[userID] = struct {
		keyID        string
		registeredAt time.Time
	}{keyID: keyID, registeredAt: time.Now().UTC()}
	return nil
}

func (f *fakeKeysStore) GetActiveKeyID(_ context.Context, userID string) (string, time.Time, bool, error) {
	k, ok := f.keys[userID]
	if !ok {
		return "", time.Time{}, false, nil
	}
	return k.keyID, k.registeredAt, true, nil
}

// fakeVerifier is an in-memory TokenVerifier for handler unit tests.
type fakeVerifier struct {
	tokens map[string]string // token -> userID
}

func newFakeVerifier() *fakeVerifier {
	return &fakeVerifier{tokens: make(map[string]string)}
}

func (v *fakeVerifier) Verify(_ context.Context, token string) (string, string, error) {
	uid, ok := v.tokens[token]
	if !ok {
		return "", "", errors.New("fakeVerifier: unknown token")
	}
	return uid, "user", nil
}

func TestKeys_Register_Success(t *testing.T) {
	store := newFakeKeysStore()
	verifier := newFakeVerifier()
	verifier.tokens["tok-101"] = "101"
	h := NewKeys(zerolog.Nop(), store, verifier)

	body, _ := json.Marshal(registerKeyRequest{UserID: "101", Token: "tok-101", KeyID: "cli-1", PublicKey: "abcd"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/register", bytes.NewReader(body))
	rw := httptest.NewRecorder()
	h.Register(rw, req)

	if rw.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rw.Code, rw.Body.String())
	}
	if _, ok := store.keys["101"]; !ok {
		t.Error("expected key to be registered for user 101")
	}
}

func TestKeys_Register_RejectsMismatchedToken(t *testing.T) {
	store := newFakeKeysStore()
	verifier := newFakeVerifier()
	verifier.tokens["tok-101"] = "101" // token belongs to user 101
	h := NewKeys(zerolog.Nop(), store, verifier)

	// Attempt to register a key for user 999 using user 101's token.
	body, _ := json.Marshal(registerKeyRequest{UserID: "999", Token: "tok-101", KeyID: "cli-1", PublicKey: "abcd"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/register", bytes.NewReader(body))
	rw := httptest.NewRecorder()
	h.Register(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for mismatched token/user_id, got %d: %s", rw.Code, rw.Body.String())
	}
	if _, ok := store.keys["999"]; ok {
		t.Error("key must not be registered when token does not belong to user_id")
	}
}

func TestKeys_Register_RejectsUnknownToken(t *testing.T) {
	store := newFakeKeysStore()
	verifier := newFakeVerifier()
	h := NewKeys(zerolog.Nop(), store, verifier)

	body, _ := json.Marshal(registerKeyRequest{UserID: "101", Token: "does-not-exist", KeyID: "cli-1", PublicKey: "abcd"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/register", bytes.NewReader(body))
	rw := httptest.NewRecorder()
	h.Register(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown token, got %d", rw.Code)
	}
}

func TestKeys_Register_MissingFields(t *testing.T) {
	store := newFakeKeysStore()
	verifier := newFakeVerifier()
	h := NewKeys(zerolog.Nop(), store, verifier)

	body, _ := json.Marshal(registerKeyRequest{UserID: "101"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/register", bytes.NewReader(body))
	rw := httptest.NewRecorder()
	h.Register(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing fields, got %d", rw.Code)
	}
}

func TestKeys_Get_Found(t *testing.T) {
	store := newFakeKeysStore()
	verifier := newFakeVerifier()
	h := NewKeys(zerolog.Nop(), store, verifier)
	_ = store.RegisterKey(context.Background(), "101", "cli-1", "abcd")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/101", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("user_id", "101")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	rw := httptest.NewRecorder()
	h.Get(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestKeys_Get_NotFound(t *testing.T) {
	store := newFakeKeysStore()
	verifier := newFakeVerifier()
	h := NewKeys(zerolog.Nop(), store, verifier)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/999", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("user_id", "999")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	rw := httptest.NewRecorder()
	h.Get(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rw.Code)
	}
}
