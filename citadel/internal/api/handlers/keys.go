package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

// keysStore is the subset of *db.DB required by Keys.
type keysStore interface {
	RegisterKey(ctx context.Context, userID, keyID, publicKeyHex string) error
	GetActiveKeyID(ctx context.Context, userID string) (keyID string, registeredAt time.Time, exists bool, err error)
}

// keysTokenVerifier is the subset of marshal.TokenVerifier required by Keys
// (duplicated here rather than importing marshal, to avoid a needless
// package coupling for a one-method interface).
type keysTokenVerifier interface {
	Verify(ctx context.Context, token string) (userID, role string, err error)
}

// Keys handles POST /api/v1/keys/register and GET /api/v1/keys/{user_id} —
// the Ed25519 signing-key registry used by MARSHAL Gate 1/Gate 3 to verify
// Operator/Verifier signatures. See adrs/004-operator-verifier-ed25519-signatures.md
// and adrs/005-sinauth-identity-bridge.md.
type Keys struct {
	logger   zerolog.Logger
	store    keysStore
	verifier keysTokenVerifier
}

// NewKeys creates a Keys handler backed by the given store and token verifier.
func NewKeys(logger zerolog.Logger, store keysStore, verifier keysTokenVerifier) *Keys {
	return &Keys{logger: logger, store: store, verifier: verifier}
}

type registerKeyRequest struct {
	UserID string `json:"user_id"`
	Token  string `json:"token"`
	KeyID  string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type registerKeyResponse struct {
	KeyID        string    `json:"key_id"`
	RegisteredAt time.Time `json:"registered_at"`
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Register handles POST /api/v1/keys/register.
//
// The request must carry a live sinauth bearer token whose verified subject
// matches user_id — this is the only thing standing between "anyone can
// register a public key for anyone" and an actual identity binding, since
// CITADEL has no other HTTP-level auth middleware today. Same verification
// path as Gate 1/Gate 3 — see adrs/005-sinauth-identity-bridge.md.
func (k *Keys) Register(w http.ResponseWriter, r *http.Request) {
	var req registerKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserID == "" || req.Token == "" || req.KeyID == "" || req.PublicKey == "" {
		writeJSONError(w, http.StatusBadRequest, "user_id, token, key_id, and public_key are required")
		return
	}

	sub, _, err := k.verifier.Verify(r.Context(), req.Token)
	if err != nil || sub != req.UserID {
		writeJSONError(w, http.StatusForbidden, "token does not belong to user_id")
		return
	}

	if err := k.store.RegisterKey(r.Context(), req.UserID, req.KeyID, req.PublicKey); err != nil {
		k.logger.Error().Err(err).Str("user_id", req.UserID).Msg("keys: register failed")
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	k.logger.Info().Str("user_id", req.UserID).Str("key_id", req.KeyID).Msg("signing key registered")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(registerKeyResponse{KeyID: req.KeyID, RegisteredAt: time.Now().UTC()})
}

// Get handles GET /api/v1/keys/{user_id} — returns active key metadata.
// Public keys are not secret, so this endpoint requires no auth.
func (k *Keys) Get(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		writeJSONError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	keyID, registeredAt, exists, err := k.store.GetActiveKeyID(r.Context(), userID)
	if err != nil {
		k.logger.Error().Err(err).Str("user_id", userID).Msg("keys: lookup failed")
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !exists {
		writeJSONError(w, http.StatusNotFound, "no active signing key for user_id")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(registerKeyResponse{KeyID: keyID, RegisteredAt: registeredAt})
}
