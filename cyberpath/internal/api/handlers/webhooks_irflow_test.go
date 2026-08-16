package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

// fakeCohortStore is an in-memory CohortStore for tests.
type fakeCohortStore struct {
	mu      sync.Mutex
	cohorts map[string]string // tenant|name -> cohortID
	enroll  map[string]int    // cohortID -> count
	nextID  int
}

func newFakeStore() *fakeCohortStore {
	return &fakeCohortStore{cohorts: map[string]string{}, enroll: map[string]int{}}
}

func (f *fakeCohortStore) key(tenant, name string) string { return tenant + "|" + name }

func (f *fakeCohortStore) FindByName(_ context.Context, tenant, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cohorts[f.key(tenant, name)], nil
}

func (f *fakeCohortStore) Create(_ context.Context, tenant, name string, _ []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := "cohort_" + strconv.Itoa(f.nextID)
	f.cohorts[f.key(tenant, name)] = id
	return id, nil
}

func (f *fakeCohortStore) Enroll(_ context.Context, cohortID string, userIDs []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enroll[cohortID] += len(userIDs)
	return len(userIDs), nil
}

type fakeIRFlowAudit struct {
	mu     sync.Mutex
	events []string
}

func (a *fakeIRFlowAudit) Emit(_ context.Context, evType string, _ map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, evType)
	return nil
}

type fakeOutbox struct {
	mu     sync.Mutex
	events []string
}

func (o *fakeOutbox) Enqueue(_ context.Context, evType string, _ map[string]any) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, evType)
	return nil
}

const testSecret = "irflow-test-secret"

func makeSignedRequest(t *testing.T, body []byte, ts int64, secret string) *http.Request {
	t.Helper()
	tsStr := strconv.FormatInt(ts, 10)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(tsStr))
	h.Write([]byte("."))
	h.Write(body)
	sig := hex.EncodeToString(h.Sum(nil))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/irflow/incident_trigger", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IRFlow-Timestamp", tsStr)
	req.Header.Set("X-IRFlow-Signature", "sha256="+sig)
	return req
}

func newRouter(t *testing.T, store CohortStore, audit AuditEmitter, outbox OutboxEnqueuer, now func() time.Time) *chi.Mux {
	t.Helper()
	h := NewIRFlowWebhookHandler(IRFlowWebhookOptions{
		HMACSecret: testSecret,
		Tenant:     "tenant-x",
		Cohorts:    store,
		Audit:      audit,
		Outbox:     outbox,
		Logger:     zerolog.Nop(),
		Now:        now,
	})
	r := chi.NewRouter()
	h.Register(r)
	return r
}

func TestIncidentTrigger_HappyPath(t *testing.T) {
	store := newFakeStore()
	audit := &fakeIRFlowAudit{}
	outbox := &fakeOutbox{}
	now := time.Now()
	r := newRouter(t, store, audit, outbox, func() time.Time { return now })

	body, _ := json.Marshal(incidentTriggerBody{
		IncidentID:    "inc_001",
		Type:          "phishing",
		Severity:      "P2",
		AffectedUsers: []string{"u1", "u2", "u3"},
		OccurredAt:    now,
	})
	req := makeSignedRequest(t, body, now.Unix(), testSecret)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["cohort_id"] == "" {
		t.Errorf("missing cohort_id: %v", resp)
	}
	if got := resp["enrolled_user_count"]; got != float64(3) {
		t.Errorf("enrolled_user_count = %v, want 3", got)
	}
	if len(audit.events) != 1 || audit.events[0] != "cyberpath.incident_triggered_enrollment" {
		t.Errorf("audit events = %v", audit.events)
	}
	if len(outbox.events) != 1 {
		t.Errorf("outbox events = %v", outbox.events)
	}
}

func TestIncidentTrigger_BadSignature(t *testing.T) {
	store := newFakeStore()
	now := time.Now()
	r := newRouter(t, store, &fakeIRFlowAudit{}, &fakeOutbox{}, func() time.Time { return now })

	body, _ := json.Marshal(incidentTriggerBody{IncidentID: "i", Type: "phishing", AffectedUsers: []string{"u1"}})
	req := makeSignedRequest(t, body, now.Unix(), "wrong-secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIncidentTrigger_StaleTimestamp(t *testing.T) {
	store := newFakeStore()
	now := time.Now()
	r := newRouter(t, store, &fakeIRFlowAudit{}, &fakeOutbox{}, func() time.Time { return now })

	body, _ := json.Marshal(incidentTriggerBody{IncidentID: "i", Type: "phishing", AffectedUsers: []string{"u1"}})
	stale := now.Add(-10 * time.Minute).Unix()
	req := makeSignedRequest(t, body, stale, testSecret)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIncidentTrigger_ReplayReturnsSameCohort(t *testing.T) {
	store := newFakeStore()
	now := time.Now()
	r := newRouter(t, store, &fakeIRFlowAudit{}, &fakeOutbox{}, func() time.Time { return now })

	body, _ := json.Marshal(incidentTriggerBody{
		IncidentID:    "inc_replay",
		Type:          "phishing",
		AffectedUsers: []string{"u1", "u2"},
	})

	// First call.
	req1 := makeSignedRequest(t, body, now.Unix(), testSecret)
	rec1 := httptest.NewRecorder()
	r.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first call status = %d", rec1.Code)
	}
	var resp1 map[string]any
	_ = json.Unmarshal(rec1.Body.Bytes(), &resp1)
	firstID := resp1["cohort_id"]

	// Replay.
	req2 := makeSignedRequest(t, body, now.Unix(), testSecret)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("replay status = %d", rec2.Code)
	}
	var resp2 map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	if resp2["cohort_id"] != firstID {
		t.Errorf("cohort changed: %v vs %v", firstID, resp2["cohort_id"])
	}
}

func TestIncidentTrigger_MissingAffectedUsers(t *testing.T) {
	store := newFakeStore()
	now := time.Now()
	r := newRouter(t, store, &fakeIRFlowAudit{}, &fakeOutbox{}, func() time.Time { return now })

	body, _ := json.Marshal(incidentTriggerBody{IncidentID: "i", Type: "phishing"})
	req := makeSignedRequest(t, body, now.Unix(), testSecret)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestIncidentTrigger_DisabledWhenSecretEmpty(t *testing.T) {
	h := NewIRFlowWebhookHandler(IRFlowWebhookOptions{
		HMACSecret: "",
		Cohorts:    newFakeStore(),
		Logger:     zerolog.Nop(),
	})
	r := chi.NewRouter()
	h.Register(r)

	body, _ := json.Marshal(incidentTriggerBody{IncidentID: "i", Type: "phishing", AffectedUsers: []string{"u1"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/irflow/incident_trigger", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
