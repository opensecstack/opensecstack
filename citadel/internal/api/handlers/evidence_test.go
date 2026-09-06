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
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/db"
)

// fakeEvidenceStore is an in-memory evidenceStore for handler unit tests —
// no Postgres required. Live-Postgres round-trip coverage (real WORM append
// + real compliance_evidence insert) lives in
// internal/db/evidence_test.go.
type fakeEvidenceStore struct {
	byID           map[uuid.UUID]*db.ComplianceEvidence
	appendWormErr  error
	insertErr      error
	nextWormSeq    int64
	wormEntriesLen int
}

func newFakeEvidenceStore() *fakeEvidenceStore {
	return &fakeEvidenceStore{byID: make(map[uuid.UUID]*db.ComplianceEvidence)}
}

func (f *fakeEvidenceStore) AppendWORM(_ context.Context, source, eventType, projectID string, payload []byte, _, _ string) (*db.WORMEntry, error) {
	if f.appendWormErr != nil {
		return nil, f.appendWormErr
	}
	f.nextWormSeq++
	f.wormEntriesLen++
	return &db.WORMEntry{
		ID:          uuid.New(),
		SequenceNum: f.nextWormSeq,
		Source:      source,
		EventType:   eventType,
		ProjectID:   projectID,
		Payload:     payload,
		ChainHash:   "fake-chain-hash",
	}, nil
}

func (f *fakeEvidenceStore) InsertComplianceEvidence(_ context.Context, organisationID, assessmentID, schemaVersion, reportHash string, report []byte, submittedBy string, wormEntryID uuid.UUID) (*db.ComplianceEvidence, error) {
	if f.insertErr != nil {
		return nil, f.insertErr
	}
	e := &db.ComplianceEvidence{
		ID:             uuid.New(),
		OrganisationID: organisationID,
		AssessmentID:   assessmentID,
		SchemaVersion:  schemaVersion,
		ReportHash:     reportHash,
		Report:         report,
		SubmittedBy:    submittedBy,
		WORMEntryID:    wormEntryID,
		SubmittedAt:    time.Now().UTC(),
	}
	f.byID[e.ID] = e
	return e, nil
}

func (f *fakeEvidenceStore) GetComplianceEvidence(_ context.Context, id uuid.UUID) (*db.ComplianceEvidence, bool, error) {
	e, ok := f.byID[id]
	return e, ok, nil
}

func (f *fakeEvidenceStore) ListComplianceEvidence(_ context.Context, organisationID, assessmentID string) ([]*db.ComplianceEvidence, error) {
	var out []*db.ComplianceEvidence
	for _, e := range f.byID {
		if organisationID != "" && e.OrganisationID != organisationID {
			continue
		}
		if assessmentID != "" && e.AssessmentID != assessmentID {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// fakeEvidenceVerifier is an in-memory TokenVerifier with configurable roles.
type fakeEvidenceVerifier struct {
	tokens map[string][2]string // token -> [userID, role]
}

func newFakeEvidenceVerifier() *fakeEvidenceVerifier {
	return &fakeEvidenceVerifier{tokens: make(map[string][2]string)}
}

func (v *fakeEvidenceVerifier) grant(token, userID, role string) {
	v.tokens[token] = [2]string{userID, role}
}

func (v *fakeEvidenceVerifier) Verify(_ context.Context, token string) (string, string, error) {
	pair, ok := v.tokens[token]
	if !ok {
		return "", "", errors.New("fakeEvidenceVerifier: unknown token")
	}
	return pair[0], pair[1], nil
}

func postSubmit(t *testing.T, h *Evidence, body submitEvidenceRequest) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/evidence/submit", bytes.NewReader(b))
	rw := httptest.NewRecorder()
	h.Submit(rw, req)
	return rw
}

func TestEvidence_Submit_Success(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	verifier.grant("tok-op", "user-1", "operator")
	h := NewEvidence(zerolog.Nop(), store, verifier)

	rw := postSubmit(t, h, submitEvidenceRequest{
		ActorToken:     "tok-op",
		OrganisationID: "org-1",
		AssessmentID:   "assessment-1",
		SchemaVersion:  "1.0",
		Report:         json.RawMessage(`{"schema_version":"1.0"}`),
	})

	if rw.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rw.Code, rw.Body.String())
	}
	var resp submitEvidenceResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ID == "" || resp.WORMEntryID == "" || resp.ChainHash == "" {
		t.Errorf("expected non-empty id/worm_entry_id/chain_hash, got %+v", resp)
	}
	if len(store.byID) != 1 {
		t.Fatalf("expected 1 evidence row stored, got %d", len(store.byID))
	}
}

func TestEvidence_Submit_RejectsUnknownToken(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	h := NewEvidence(zerolog.Nop(), store, verifier)

	rw := postSubmit(t, h, submitEvidenceRequest{
		ActorToken:     "no-such-token",
		OrganisationID: "org-1",
		AssessmentID:   "assessment-1",
		SchemaVersion:  "1.0",
		Report:         json.RawMessage(`{}`),
	})

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unverifiable actor_token, got %d: %s", rw.Code, rw.Body.String())
	}
	if len(store.byID) != 0 {
		t.Error("no evidence should be stored when the actor_token cannot be verified")
	}
}

func TestEvidence_Submit_RejectsDisallowedRole(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	verifier.grant("tok-viewer", "user-2", "viewer")
	h := NewEvidence(zerolog.Nop(), store, verifier)

	rw := postSubmit(t, h, submitEvidenceRequest{
		ActorToken:     "tok-viewer",
		OrganisationID: "org-1",
		AssessmentID:   "assessment-1",
		SchemaVersion:  "1.0",
		Report:         json.RawMessage(`{}`),
	})

	if rw.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a viewer role submitting evidence, got %d: %s", rw.Code, rw.Body.String())
	}
	if len(store.byID) != 0 {
		t.Error("no evidence should be stored when the role is not permitted to submit")
	}
}

func TestEvidence_Submit_MissingFields(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	verifier.grant("tok-op", "user-1", "operator")
	h := NewEvidence(zerolog.Nop(), store, verifier)

	rw := postSubmit(t, h, submitEvidenceRequest{ActorToken: "tok-op"})

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing fields, got %d", rw.Code)
	}
}

func TestEvidence_Submit_InvalidJSONBody(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	h := NewEvidence(zerolog.Nop(), store, verifier)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/evidence/submit", bytes.NewBufferString("not-json"))
	rw := httptest.NewRecorder()
	h.Submit(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON body, got %d", rw.Code)
	}
}

func TestEvidence_Submit_AppendWORMFailureIsSurfaced(t *testing.T) {
	store := newFakeEvidenceStore()
	store.appendWormErr = errors.New("db unreachable")
	verifier := newFakeEvidenceVerifier()
	verifier.grant("tok-op", "user-1", "operator")
	h := NewEvidence(zerolog.Nop(), store, verifier)

	rw := postSubmit(t, h, submitEvidenceRequest{
		ActorToken:     "tok-op",
		OrganisationID: "org-1",
		AssessmentID:   "assessment-1",
		SchemaVersion:  "1.0",
		Report:         json.RawMessage(`{}`),
	})

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when AppendWORM fails, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestEvidence_Submit_InsertFailureAfterWORMSucceedsIsSurfaced(t *testing.T) {
	// Confirms the handler reports a real error (not a false "success") when
	// the WORM append succeeds but the evidence-table insert then fails —
	// the event is durably in the WORM chain, but not yet retrievable via
	// GET, and the caller must know that to safely retry.
	store := newFakeEvidenceStore()
	store.insertErr = errors.New("connection dropped")
	verifier := newFakeEvidenceVerifier()
	verifier.grant("tok-op", "user-1", "operator")
	h := NewEvidence(zerolog.Nop(), store, verifier)

	rw := postSubmit(t, h, submitEvidenceRequest{
		ActorToken:     "tok-op",
		OrganisationID: "org-1",
		AssessmentID:   "assessment-1",
		SchemaVersion:  "1.0",
		Report:         json.RawMessage(`{}`),
	})

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the evidence insert fails, got %d: %s", rw.Code, rw.Body.String())
	}
	if store.wormEntriesLen != 1 {
		t.Errorf("expected the WORM append to have happened (durable audit trail) despite the insert failure, wormEntriesLen=%d", store.wormEntriesLen)
	}
}

func TestEvidence_Get_Found(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	h := NewEvidence(zerolog.Nop(), store, verifier)

	entry, err := store.InsertComplianceEvidence(context.Background(), "org-1", "assessment-1", "1.0", "hash", []byte(`{"a":1}`), "user-1", uuid.New())
	if err != nil {
		t.Fatalf("seed InsertComplianceEvidence: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/evidence/"+entry.ID.String(), nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", entry.ID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	rw := httptest.NewRecorder()
	h.Get(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	var resp evidenceResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OrganisationID != "org-1" || resp.AssessmentID != "assessment-1" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestEvidence_Get_NotFound(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	h := NewEvidence(zerolog.Nop(), store, verifier)

	missing := uuid.New()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/evidence/"+missing.String(), nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", missing.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	rw := httptest.NewRecorder()
	h.Get(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rw.Code)
	}
}

func TestEvidence_Get_InvalidUUID(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	h := NewEvidence(zerolog.Nop(), store, verifier)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/evidence/not-a-uuid", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	rw := httptest.NewRecorder()
	h.Get(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a malformed id, got %d", rw.Code)
	}
}

func TestEvidence_List_RequiresAtLeastOneFilter(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	h := NewEvidence(zerolog.Nop(), store, verifier)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/evidence", nil)
	rw := httptest.NewRecorder()
	h.List(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when no filter is given, got %d", rw.Code)
	}
}

func TestEvidence_List_FiltersByOrganisationID(t *testing.T) {
	store := newFakeEvidenceStore()
	verifier := newFakeEvidenceVerifier()
	h := NewEvidence(zerolog.Nop(), store, verifier)

	_, err := store.InsertComplianceEvidence(context.Background(), "org-a", "assessment-1", "1.0", "hash", []byte(`{}`), "user-1", uuid.New())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err = store.InsertComplianceEvidence(context.Background(), "org-b", "assessment-1", "1.0", "hash", []byte(`{}`), "user-1", uuid.New())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/evidence?organisation_id=org-a", nil)
	rw := httptest.NewRecorder()
	h.List(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	var resp listEvidenceResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 result for organisation_id=org-a, got %d", len(resp.Data))
	}
	if resp.Data[0].OrganisationID != "org-a" {
		t.Errorf("got organisation_id %q, want org-a", resp.Data[0].OrganisationID)
	}
}
