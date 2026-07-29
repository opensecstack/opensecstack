// Integration tests for CertificationsHandler.
// White-box style: same package as the handlers under test.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/cert"
	"github.com/opensecstack/cyberpath/internal/citadel"
	"github.com/opensecstack/cyberpath/internal/db"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"
)

// ── context helpers ───────────────────────────────────────────────────────────

// withAdminCtx returns r with auth.Claims{Sub: userID.String(), Role: "admin",
// Roles: []string{"admin"}} in the request context.
// withUserCtx is defined in quizzes_test.go (same package).
func withAdminCtx(r *http.Request, userID uuid.UUID) *http.Request {
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{
		Sub:   userID.String(),
		Role:  "admin",
		Roles: []string{"admin"},
	}))
}

// ── fake stores ───────────────────────────────────────────────────────────────

// fakeCertStore implements CertStore entirely in memory.
type fakeCertStore struct {
	mu         sync.Mutex
	certs      map[uuid.UUID]*db.Certification // keyed by cert ID
	sigs       map[uuid.UUID]string            // cert ID -> signature
	revoked    map[uuid.UUID]bool
	userTrack  map[string]*db.Certification // key: userID+"|"+trackID
	listResult []db.Certification

	issueErr        error
	setSignatureErr error
	listByUserErr   error
	revokeErr       error
	getByUserTrackErr error
}

func newFakeCertStore() *fakeCertStore {
	return &fakeCertStore{
		certs:     make(map[uuid.UUID]*db.Certification),
		sigs:      make(map[uuid.UUID]string),
		revoked:   make(map[uuid.UUID]bool),
		userTrack: make(map[string]*db.Certification),
	}
}

func (s *fakeCertStore) Issue(_ context.Context, userID, trackID uuid.UUID, serial string, expiresAt *time.Time) (*db.Certification, error) {
	if s.issueErr != nil {
		return nil, s.issueErr
	}
	c := &db.Certification{
		ID:       uuid.New(),
		UserID:   userID,
		TrackID:  trackID,
		Serial:   serial,
		IssuedAt: time.Now(),
	}
	s.mu.Lock()
	s.certs[c.ID] = c
	key := userID.String() + "|" + trackID.String()
	s.userTrack[key] = c
	s.mu.Unlock()
	return c, nil
}

func (s *fakeCertStore) SetSignature(_ context.Context, certID uuid.UUID, sig, _ string) error {
	if s.setSignatureErr != nil {
		return s.setSignatureErr
	}
	s.mu.Lock()
	s.sigs[certID] = sig
	if c, ok := s.certs[certID]; ok {
		c.Signature = sig
	}
	s.mu.Unlock()
	return nil
}

func (s *fakeCertStore) ListByUser(_ context.Context, _ uuid.UUID, _ bool) ([]db.Certification, error) {
	if s.listByUserErr != nil {
		return nil, s.listByUserErr
	}
	return s.listResult, nil
}

func (s *fakeCertStore) Revoke(_ context.Context, certID uuid.UUID) error {
	if s.revokeErr != nil {
		return s.revokeErr
	}
	s.mu.Lock()
	s.revoked[certID] = true
	if c, ok := s.certs[certID]; ok {
		c.Revoked = true
	}
	s.mu.Unlock()
	return nil
}

func (s *fakeCertStore) GetByUserTrack(_ context.Context, userID, trackID uuid.UUID) (*db.Certification, error) {
	if s.getByUserTrackErr != nil {
		return nil, s.getByUserTrackErr
	}
	key := userID.String() + "|" + trackID.String()
	s.mu.Lock()
	c, ok := s.userTrack[key]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("GetByUserTrack: %w", pgx.ErrNoRows)
	}
	return c, nil
}

// fakeCertTrackReader implements CertTrackReader.
type fakeCertTrackReader struct {
	err error
}

func (r *fakeCertTrackReader) Get(_ context.Context, id uuid.UUID) (*db.Track, error) {
	if r.err != nil {
		return nil, r.err
	}
	return &db.Track{ID: id, Slug: "test-track"}, nil
}

// fakeCertCompletionChecker implements CertCompletionChecker.
type fakeCertCompletionChecker struct {
	done bool
	err  error
}

func (c *fakeCertCompletionChecker) AllLessonsCompletedForTrack(_ context.Context, _, _ uuid.UUID) (bool, error) {
	return c.done, c.err
}

// fakeCertOutbox implements citadel.OutboxEnqueuer.
type fakeCertOutbox struct {
	mu      sync.Mutex
	entries []citadel.EnqueueRequest
	err     error
}

func (o *fakeCertOutbox) Enqueue(_ context.Context, req citadel.EnqueueRequest) (int64, error) {
	if o.err != nil {
		return 0, o.err
	}
	o.mu.Lock()
	o.entries = append(o.entries, req)
	o.mu.Unlock()
	return 1, nil
}

// fakeMarshalEvaluator implements MarshalEvaluator for tests. It records
// every Kerkese it was called with and returns a canned Decision/error.
type fakeMarshalEvaluator struct {
	mu       sync.Mutex
	calls    []sdkcitadel.Kerkese
	decision *sdkcitadel.Decision
	err      error
}

func (f *fakeMarshalEvaluator) Evaluate(_ context.Context, k sdkcitadel.Kerkese) (*sdkcitadel.Decision, error) {
	f.mu.Lock()
	f.calls = append(f.calls, k)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.decision != nil {
		return f.decision, nil
	}
	return &sdkcitadel.Decision{Outcome: sdkcitadel.OutcomeExecute}, nil
}

func (f *fakeMarshalEvaluator) lastCall() (sdkcitadel.Kerkese, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return sdkcitadel.Kerkese{}, false
	}
	return f.calls[len(f.calls)-1], true
}

// ── test handler constructor ──────────────────────────────────────────────────

func newTestCertHandler(t *testing.T, certStore CertStore, completions CertCompletionChecker) *CertificationsHandler {
	t.Helper()
	signer, err := cert.NewSigner("") // ephemeral key — safe for tests
	if err != nil {
		t.Fatalf("cert.NewSigner: %v", err)
	}
	return &CertificationsHandler{
		Certs:       certStore,
		Tracks:      &fakeCertTrackReader{},
		Completions: completions,
		Signer:      signer,
		Outbox:      &fakeCertOutbox{},
	}
}

// newTestCertHandlerWithGovernance builds a CertificationsHandler wired
// with the given outbox and MarshalEvaluator, for tests exercising
// Revoke()'s CITADEL wiring specifically.
func newTestCertHandlerWithGovernance(t *testing.T, certStore CertStore, outbox citadel.OutboxEnqueuer, marshal MarshalEvaluator) *CertificationsHandler {
	t.Helper()
	signer, err := cert.NewSigner("")
	if err != nil {
		t.Fatalf("cert.NewSigner: %v", err)
	}
	return &CertificationsHandler{
		Certs:            certStore,
		Tracks:           &fakeCertTrackReader{},
		Signer:           signer,
		Outbox:           outbox,
		Marshal:          marshal,
		CitadelProjectID: "cyberpath-test",
	}
}

// ── JSON decode helper for tests ──────────────────────────────────────────────

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode response body: %v\nbody: %s", err, w.Body.String())
	}
	return m
}

// ── Issue tests ───────────────────────────────────────────────────────────────

func TestCertificationsIssue_Success(t *testing.T) {
	trackID := uuid.New()
	userID := uuid.New()
	store := newFakeCertStore()
	h := newTestCertHandler(t, store, nil) // nil completions = skip eligibility check

	r := chi.NewRouter()
	r.Post("/certifications/issue", h.Issue)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/certifications/issue",
			strings.NewReader(`{"track_id":"`+trackID.String()+`"}`)),
		userID,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["id"] == "" || body["id"] == nil {
		t.Errorf("missing 'id' in response: %v", body)
	}
	sig, _ := body["signature"].(string)
	if sig == "" {
		t.Errorf("expected non-empty 'signature', got: %v", body)
	}
}

func TestCertificationsIssue_Unauthorized(t *testing.T) {
	h := newTestCertHandler(t, newFakeCertStore(), nil)
	r := chi.NewRouter()
	r.Post("/certifications/issue", h.Issue)

	// No user context — request has no auth claims.
	req := httptest.NewRequest(http.MethodPost, "/certifications/issue",
		strings.NewReader(`{"track_id":"`+uuid.New().String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
}

func TestCertificationsIssue_InvalidTrackID(t *testing.T) {
	userID := uuid.New()
	h := newTestCertHandler(t, newFakeCertStore(), nil)
	r := chi.NewRouter()
	r.Post("/certifications/issue", h.Issue)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/certifications/issue",
			strings.NewReader(`{"track_id":"not-a-uuid"}`)),
		userID,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestCertificationsIssue_NotEligible(t *testing.T) {
	trackID := uuid.New()
	userID := uuid.New()
	completions := &fakeCertCompletionChecker{done: false}
	h := newTestCertHandler(t, newFakeCertStore(), completions)
	r := chi.NewRouter()
	r.Post("/certifications/issue", h.Issue)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/certifications/issue",
			strings.NewReader(`{"track_id":"`+trackID.String()+`"}`)),
		userID,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	errBlock, _ := body["error"].(map[string]any)
	if errBlock["code"] != "not_eligible" {
		t.Errorf("error.code = %v, want 'not_eligible'", errBlock["code"])
	}
}

func TestCertificationsIssue_StoreError(t *testing.T) {
	trackID := uuid.New()
	userID := uuid.New()
	store := newFakeCertStore()
	store.issueErr = fmt.Errorf("db unavailable")
	h := newTestCertHandler(t, store, nil)
	r := chi.NewRouter()
	r.Post("/certifications/issue", h.Issue)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/certifications/issue",
			strings.NewReader(`{"track_id":"`+trackID.String()+`"}`)),
		userID,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

// ── ListMine tests ────────────────────────────────────────────────────────────

func TestCertificationsListMine_Success(t *testing.T) {
	userID := uuid.New()
	store := newFakeCertStore()
	store.listResult = []db.Certification{
		{ID: uuid.New(), UserID: userID, TrackID: uuid.New(), Serial: "CP-aaa-1", IssuedAt: time.Now()},
		{ID: uuid.New(), UserID: userID, TrackID: uuid.New(), Serial: "CP-bbb-2", IssuedAt: time.Now()},
	}
	h := newTestCertHandler(t, store, nil)
	r := chi.NewRouter()
	r.Get("/me/certifications", h.ListMine)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/me/certifications", nil), userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	certs, _ := body["certifications"].([]any)
	if len(certs) != 2 {
		t.Errorf("certifications count = %d, want 2", len(certs))
	}
}

func TestCertificationsListMine_Unauthorized(t *testing.T) {
	h := newTestCertHandler(t, newFakeCertStore(), nil)
	r := chi.NewRouter()
	r.Get("/me/certifications", h.ListMine)

	req := httptest.NewRequest(http.MethodGet, "/me/certifications", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
}

// ── Revoke tests ──────────────────────────────────────────────────────────────

func TestCertificationsRevoke_Success(t *testing.T) {
	adminID := uuid.New()
	certID := uuid.New()
	store := newFakeCertStore()
	// Pre-seed a cert so Revoke operates on an existing record.
	store.certs[certID] = &db.Certification{ID: certID, IssuedAt: time.Now()}

	h := newTestCertHandler(t, store, nil)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	req := withAdminCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/"+certID.String()+"/revoke", nil),
		adminID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["revoked"] != true {
		t.Errorf("revoked = %v, want true", body["revoked"])
	}
}

func TestCertificationsRevoke_Forbidden(t *testing.T) {
	learnerID := uuid.New()
	certID := uuid.New()
	h := newTestCertHandler(t, newFakeCertStore(), nil)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	// Learner role — not admin.
	req := withUserCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/"+certID.String()+"/revoke", nil),
		learnerID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
}

func TestCertificationsRevoke_InvalidID(t *testing.T) {
	adminID := uuid.New()
	h := newTestCertHandler(t, newFakeCertStore(), nil)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	req := withAdminCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/not-a-uuid/revoke", nil),
		adminID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

// ── Revoke / CITADEL governance tests ─────────────────────────────────────────

// TestCertificationsRevoke_EmitsWORM verifies that a successful revocation
// enqueues a cyberpath.certification.revoked WORM event via the outbox,
// mirroring how Issue() already enqueues cyberpath.certification.issued.
func TestCertificationsRevoke_EmitsWORM(t *testing.T) {
	adminID := uuid.New()
	certID := uuid.New()
	store := newFakeCertStore()
	store.certs[certID] = &db.Certification{ID: certID, IssuedAt: time.Now()}
	outbox := &fakeCertOutbox{}
	marshal := &fakeMarshalEvaluator{}

	h := newTestCertHandlerWithGovernance(t, store, outbox, marshal)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	req := withAdminCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/"+certID.String()+"/revoke", nil),
		adminID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	found := false
	for _, e := range outbox.entries {
		if e.EventType == "cyberpath.certification.revoked" {
			found = true
			var payload map[string]any
			if err := json.Unmarshal(e.Payload, &payload); err != nil {
				t.Fatalf("decode WORM payload: %v", err)
			}
			cb, _ := payload["cyberpath"].(map[string]any)
			if cb["certificate_id"] != certID.String() {
				t.Errorf("certificate_id = %v, want %s", cb["certificate_id"], certID.String())
			}
			if cb["revoked_by"] != adminID.String() {
				t.Errorf("revoked_by = %v, want %s", cb["revoked_by"], adminID.String())
			}
		}
	}
	if !found {
		t.Errorf("no cyberpath.certification.revoked event enqueued; entries: %+v", outbox.entries)
	}
}

// TestCertificationsRevoke_RealActorIdentity verifies that the Kerkese
// submitted to MARSHAL carries the real authenticated admin's identity
// and bearer token — never a placeholder — as Actor/ActorToken.
func TestCertificationsRevoke_RealActorIdentity(t *testing.T) {
	adminID := uuid.New()
	certID := uuid.New()
	store := newFakeCertStore()
	store.certs[certID] = &db.Certification{ID: certID, IssuedAt: time.Now()}
	marshal := &fakeMarshalEvaluator{}

	h := newTestCertHandlerWithGovernance(t, store, &fakeCertOutbox{}, marshal)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	req := withAdminCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/"+certID.String()+"/revoke", nil),
		adminID,
	)
	req.Header.Set("Authorization", "Bearer real-admin-bearer-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	k, ok := marshal.lastCall()
	if !ok {
		t.Fatal("MarshalEvaluator.Evaluate was not called")
	}
	if k.Actor.UserID != adminID.String() {
		t.Errorf("Actor.UserID = %q, want real admin id %q (must not be a placeholder)", k.Actor.UserID, adminID.String())
	}
	if k.Actor.UserID == "" || k.Actor.UserID == "cyberpath-system-verifier" {
		t.Errorf("Actor.UserID = %q, must not be empty or a placeholder", k.Actor.UserID)
	}
	if k.ActorToken != "real-admin-bearer-token" {
		t.Errorf("ActorToken = %q, want the forwarded bearer token", k.ActorToken)
	}
	if k.SoD.OperatorUserID != adminID.String() {
		t.Errorf("SoD.OperatorUserID = %q, want %q", k.SoD.OperatorUserID, adminID.String())
	}
	// Verifier is a documented, deliberate placeholder (no dual-control
	// concept exists in CyberPath) — assert it stays a fixed system
	// identity distinct from the Actor, not that it's "real".
	if k.Verifier.UserID == "" || k.Verifier.UserID == k.Actor.UserID {
		t.Errorf("Verifier.UserID = %q, must be a non-empty placeholder distinct from Actor", k.Verifier.UserID)
	}
	if k.SigOperator != "" || k.SigVerifier != "" {
		t.Errorf("SigOperator/SigVerifier must stay empty, got %q / %q", k.SigOperator, k.SigVerifier)
	}
}

// TestCertificationsRevoke_RefuseBlocks verifies a REFUSE outcome blocks
// the revocation (403) and surfaces MARSHAL's reason, without touching
// the DB or emitting a WORM event.
func TestCertificationsRevoke_RefuseBlocks(t *testing.T) {
	adminID := uuid.New()
	certID := uuid.New()
	store := newFakeCertStore()
	store.certs[certID] = &db.Certification{ID: certID, IssuedAt: time.Now()}
	outbox := &fakeCertOutbox{}
	marshal := &fakeMarshalEvaluator{
		decision: &sdkcitadel.Decision{
			Outcome: sdkcitadel.OutcomeRefuse,
			Reasons: []string{"AUTHZ_FAIL: role not permitted"},
		},
	}

	h := newTestCertHandlerWithGovernance(t, store, outbox, marshal)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	req := withAdminCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/"+certID.String()+"/revoke", nil),
		adminID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	errBlock, _ := body["error"].(map[string]any)
	msg, _ := errBlock["message"].(string)
	if !strings.Contains(msg, "AUTHZ_FAIL") {
		t.Errorf("error.message = %q, want it to contain the MARSHAL reason", msg)
	}
	if store.revoked[certID] {
		t.Error("certification was revoked despite REFUSE outcome")
	}
	outbox.mu.Lock()
	n := len(outbox.entries)
	outbox.mu.Unlock()
	if n != 0 {
		t.Errorf("outbox has %d entries, want 0 — no WORM event should be emitted when governance blocks the revocation", n)
	}
}

// TestCertificationsRevoke_HardStopBlocks mirrors the REFUSE test for
// HARD_STOP, MARSHAL's more severe blocking outcome.
func TestCertificationsRevoke_HardStopBlocks(t *testing.T) {
	adminID := uuid.New()
	certID := uuid.New()
	store := newFakeCertStore()
	store.certs[certID] = &db.Certification{ID: certID, IssuedAt: time.Now()}
	marshal := &fakeMarshalEvaluator{
		decision: &sdkcitadel.Decision{
			Outcome: sdkcitadel.OutcomeHardStop,
			Reasons: []string{"NDS_SAME_IDENTITY: operator and verifier are the same user"},
		},
	}

	h := newTestCertHandlerWithGovernance(t, store, &fakeCertOutbox{}, marshal)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	req := withAdminCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/"+certID.String()+"/revoke", nil),
		adminID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if store.revoked[certID] {
		t.Error("certification was revoked despite HARD_STOP outcome")
	}
}

// TestCertificationsRevoke_EvaluateErrorFailsOpen verifies that a
// transport/evaluation error (CITADEL unreachable) does not itself block
// revocation — only an explicit REFUSE/HARD_STOP decision blocks. This
// matches apiguard's scan-initiation pattern (scans.go: "proceeding with
// scan" on evalErr).
func TestCertificationsRevoke_EvaluateErrorFailsOpen(t *testing.T) {
	adminID := uuid.New()
	certID := uuid.New()
	store := newFakeCertStore()
	store.certs[certID] = &db.Certification{ID: certID, IssuedAt: time.Now()}
	marshal := &fakeMarshalEvaluator{err: fmt.Errorf("citadel: connection refused")}

	h := newTestCertHandlerWithGovernance(t, store, &fakeCertOutbox{}, marshal)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	req := withAdminCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/"+certID.String()+"/revoke", nil),
		adminID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open on evaluate error); body: %s", w.Code, w.Body.String())
	}
	if !store.revoked[certID] {
		t.Error("certification was not revoked despite fail-open evaluate error")
	}
}

// TestCertificationsRevoke_NoMarshalConfigured verifies Revoke() still
// works when h.Marshal is nil (CITADEL not configured) — the existing
// unmodified issuance behaviour for "CITADEL absent" should be preserved.
func TestCertificationsRevoke_NoMarshalConfigured(t *testing.T) {
	adminID := uuid.New()
	certID := uuid.New()
	store := newFakeCertStore()
	store.certs[certID] = &db.Certification{ID: certID, IssuedAt: time.Now()}

	h := newTestCertHandlerWithGovernance(t, store, &fakeCertOutbox{}, nil)
	r := chi.NewRouter()
	r.Delete("/certifications/{id}/revoke", h.Revoke)

	req := withAdminCtx(
		httptest.NewRequest(http.MethodDelete, "/certifications/"+certID.String()+"/revoke", nil),
		adminID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !store.revoked[certID] {
		t.Error("certification was not revoked")
	}
}

// ── TryAutoIssue tests ────────────────────────────────────────────────────────

func TestTryAutoIssue_Idempotent(t *testing.T) {
	userID := uuid.New()
	trackID := uuid.New()
	store := newFakeCertStore()

	// Pre-seed an existing cert for this user+track pair.
	existing := &db.Certification{
		ID:       uuid.New(),
		UserID:   userID,
		TrackID:  trackID,
		Serial:   "CP-existing-1",
		IssuedAt: time.Now(),
	}
	store.certs[existing.ID] = existing
	store.userTrack[userID.String()+"|"+trackID.String()] = existing

	h := newTestCertHandler(t, store, nil)
	initialCount := len(store.certs)

	err := h.TryAutoIssue(context.Background(), userID, trackID)
	if err != nil {
		t.Fatalf("TryAutoIssue returned error: %v", err)
	}
	// Issue must NOT have been called — cert count stays the same.
	if len(store.certs) != initialCount {
		t.Errorf("certs count = %d, want %d (Issue should not have been called)", len(store.certs), initialCount)
	}
}

func TestTryAutoIssue_Issues(t *testing.T) {
	userID := uuid.New()
	trackID := uuid.New()
	store := newFakeCertStore()
	// No pre-existing cert — GetByUserTrack will return pgx.ErrNoRows.

	h := newTestCertHandler(t, store, nil)

	err := h.TryAutoIssue(context.Background(), userID, trackID)
	if err != nil {
		t.Fatalf("TryAutoIssue returned error: %v", err)
	}
	// Issue should have been called — exactly one cert in the store.
	if len(store.certs) != 1 {
		t.Errorf("certs count = %d, want 1 (Issue should have been called)", len(store.certs))
	}
}
