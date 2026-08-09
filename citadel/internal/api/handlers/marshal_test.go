package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/marshal"
)

// fakeMarshalStoreOK is a minimal in-memory marshal.Store for handler unit
// tests — no Postgres required. It always succeeds so evaluation can reach
// a final outcome without needing gate-level enforcement details, which are
// covered exhaustively by internal/marshal/marshal_test.go.
type fakeMarshalStoreOK struct{}

func (f *fakeMarshalStoreOK) ActionCount(_ context.Context, _ string, _ time.Duration) (int, error) {
	return 0, nil
}

func (f *fakeMarshalStoreOK) AppendWORM(_ context.Context, _, _, _ string, _ []byte, sigOperator, sigVerifier string) (*marshal.WORMEntry, error) {
	return &marshal.WORMEntry{
		ID:          uuid.New(),
		SequenceNum: 1,
		ChainHash:   "test_chain_hash",
		SigOperator: sigOperator,
		SigVerifier: sigVerifier,
	}, nil
}

func (f *fakeMarshalStoreOK) GetSigningKey(_ context.Context, _ string) (ed25519.PublicKey, bool, error) {
	return nil, false, nil
}

// fakeMarshalVerifier is a no-op TokenVerifier that rejects everything —
// sufficient here because the handler tests below only exercise the soft
// (non-enforced) engine, where a rejected token WARNs rather than REFUSEs.
type fakeMarshalVerifier struct{}

func (f *fakeMarshalVerifier) Verify(_ context.Context, _ string) (string, string, error) {
	return "", "", nil
}

func TestMarshal_ServeHTTP_InvalidBody(t *testing.T) {
	h := NewMarshal(zerolog.Nop(), nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/marshal/evaluate", bytes.NewBufferString("not-json"))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rw.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid request body" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestMarshal_ServeHTTP_FillsDefaultsAndReturnsDecision(t *testing.T) {
	engine := marshal.New(&fakeMarshalStoreOK{}, &fakeMarshalVerifier{})
	h := NewMarshal(zerolog.Nop(), engine)

	body := []byte(`{
		"kerkese_version": "1.0",
		"project_id": "test",
		"action": {"type": "API_SCAN_INITIATE"},
		"actor": {"user_id": "u1", "role": "operator"},
		"verifier": {"user_id": "u2", "role": "analyst"},
		"sod": {"operator_user_id": "u1", "verifier_user_id": "u2"}
	}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/marshal/evaluate", bytes.NewReader(body))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	var decision marshal.Decision
	if err := json.Unmarshal(rw.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// ExecutionID and TsUTC must be auto-filled since the request body omitted them.
	if decision.ExecutionID == (uuid.UUID{}) {
		t.Error("expected ExecutionID to be auto-filled, got zero UUID")
	}
	if decision.TsUTC.IsZero() {
		t.Error("expected TsUTC to be auto-filled, got zero time")
	}
	if len(decision.Gates) != 5 {
		t.Errorf("expected 5 gate results, got %d", len(decision.Gates))
	}

	// Status code must reflect the decision outcome.
	switch decision.Outcome {
	case marshal.OutcomeHardStop, marshal.OutcomeRefuse:
		if rw.Code != http.StatusForbidden {
			t.Errorf("outcome %s: expected 403, got %d", decision.Outcome, rw.Code)
		}
	case marshal.OutcomeExecute:
		if rw.Code != http.StatusOK {
			t.Errorf("outcome EXECUTE: expected 200, got %d", rw.Code)
		}
	}
}

func TestMarshal_ServeHTTP_PreservesProvidedExecutionID(t *testing.T) {
	engine := marshal.New(&fakeMarshalStoreOK{}, &fakeMarshalVerifier{})
	h := NewMarshal(zerolog.Nop(), engine)

	fixedID := uuid.New()
	k := marshal.Kerkese{
		KerkeseVersion: "1.0",
		ProjectID:      "test",
		ExecutionID:    fixedID,
		Action:         marshal.KerkeseAction{Type: "API_SCAN_INITIATE"},
		Actor:          marshal.KerkeseActor{UserID: "u1", Role: "operator"},
		Verifier:       marshal.KerkeseVerifier{UserID: "u2", Role: "analyst"},
		SoD:            marshal.KerkeseSoD{OperatorUserID: "u1", VerifierUserID: "u2"},
	}
	body, _ := json.Marshal(k)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/marshal/evaluate", bytes.NewReader(body))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	var decision marshal.Decision
	if err := json.Unmarshal(rw.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decision.ExecutionID != fixedID {
		t.Errorf("expected provided ExecutionID %s to be preserved, got %s", fixedID, decision.ExecutionID)
	}
}
