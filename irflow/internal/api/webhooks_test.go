package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"github.com/opensecstack/opensecstack/irflow/internal/webhook"
)

const webhookTestSecret = "test-webhook-secret"

// newWebhookServer builds a Server wired to the apiMockStore and configured
// with a shared secret across all three webhook sources — enough for handler
// smoke tests.
func newWebhookServer(t *testing.T) (*Server, *apiMockStore) {
	t.Helper()
	store := newAPIMockStore()
	svc := incident.NewService(store)
	srv := NewServer(Options{
		Logger:    zap.NewNop(),
		Incidents: svc,
		Webhooks: WebhookSecrets{
			APIGuard:   webhookTestSecret,
			CITADEL:    webhookTestSecret,
			ThreatFlow: webhookTestSecret,
			CyberPath:  webhookTestSecret,
		},
	})
	return srv, store
}

func signedRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	ts := time.Now().Unix()
	sig := webhook.Sign(webhookTestSecret, ts, body)
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhook.HeaderSignature, sig)
	req.Header.Set(webhook.HeaderTimestamp, strconv.FormatInt(ts, 10))
	return req
}

func TestAPIGuardWebhook_CriticalCreatesIncident(t *testing.T) {
	srv, store := newWebhookServer(t)

	payload, _ := json.Marshal(webhook.APIGuardEvent{
		EventID:   "evt-1",
		EventType: "finding",
		ScanID:    "scan-123",
		Target:    "https://api.example.com/users",
		Finding: webhook.APIGuardFinding{
			ID:          "find-1",
			Title:       "SQL injection",
			Description: "User input reaches query",
			Severity:    "critical",
			RuleID:      "A03",
		},
	})

	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/apiguard", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201. body: %s", rec.Code, rec.Body.String())
	}
	if len(store.incidents) != 1 {
		t.Fatalf("got %d incidents, want 1", len(store.incidents))
	}
	for _, inc := range store.incidents {
		if inc.Severity != incident.SeverityP1 {
			t.Errorf("severity = %s, want P1", inc.Severity)
		}
		if inc.Source != incident.SourceAPIGuard {
			t.Errorf("source = %s, want apiguard", inc.Source)
		}
		if inc.SourceRef != "scan-123" {
			t.Errorf("source_ref = %s, want scan-123", inc.SourceRef)
		}
	}
}

func TestAPIGuardWebhook_MediumAcknowledgedWithoutIncident(t *testing.T) {
	srv, store := newWebhookServer(t)

	payload, _ := json.Marshal(webhook.APIGuardEvent{
		EventID:   "evt-2",
		EventType: "finding",
		ScanID:    "scan-200",
		Finding:   webhook.APIGuardFinding{Severity: "medium", Title: "missing rate limit"},
	})

	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/apiguard", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if len(store.incidents) != 0 {
		t.Errorf("got %d incidents, want 0 (medium severity should not auto-create)", len(store.incidents))
	}
}

func TestAPIGuardWebhook_RejectsInvalidSignature(t *testing.T) {
	srv, store := newWebhookServer(t)

	body := []byte(`{"event_id":"x","finding":{"severity":"critical"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/apiguard", bytes.NewReader(body))
	req.Header.Set(webhook.HeaderSignature, "sha256=deadbeef")
	req.Header.Set(webhook.HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if len(store.incidents) != 0 {
		t.Errorf("unauthorized request created an incident")
	}
}

func TestAPIGuardWebhook_RejectsStaleTimestamp(t *testing.T) {
	srv, _ := newWebhookServer(t)

	body := []byte(`{}`)
	oldTS := time.Now().Add(-30 * time.Minute).Unix()
	sig := webhook.Sign(webhookTestSecret, oldTS, body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/apiguard", bytes.NewReader(body))
	req.Header.Set(webhook.HeaderSignature, sig)
	req.Header.Set(webhook.HeaderTimestamp, strconv.FormatInt(oldTS, 10))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCITADELWebhook_HardStopCreatesP1(t *testing.T) {
	srv, store := newWebhookServer(t)

	payload, _ := json.Marshal(webhook.CITADELEvent{
		EventID:     "evt-3",
		EventType:   "hard_stop",
		Trigger:     "unauthorized prod deploy",
		ProjectID:   "proj-9",
		ExecutionID: "exec-42",
		Description: "Deployment blocked pending human review",
	})

	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/citadel", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201. body: %s", rec.Code, rec.Body.String())
	}
	if len(store.incidents) != 1 {
		t.Fatalf("got %d incidents, want 1", len(store.incidents))
	}
	for _, inc := range store.incidents {
		if inc.Severity != incident.SeverityP1 {
			t.Errorf("severity = %s, want P1", inc.Severity)
		}
		if inc.Source != incident.SourceCitadel {
			t.Errorf("source = %s, want citadel", inc.Source)
		}
		if inc.SourceRef != "exec-42" {
			t.Errorf("source_ref = %s, want exec-42", inc.SourceRef)
		}
	}
}

func TestCITADELWebhook_MarshalDeniedAcknowledged(t *testing.T) {
	srv, store := newWebhookServer(t)

	payload, _ := json.Marshal(webhook.CITADELEvent{
		EventID:   "evt-4",
		EventType: "marshal_denied",
	})
	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/citadel", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	if len(store.incidents) != 0 {
		t.Errorf("non-hard_stop event should not create incident; got %d", len(store.incidents))
	}
}

func TestThreatFlowWebhook_EnrichesNamedIncident(t *testing.T) {
	srv, store := newWebhookServer(t)

	// Seed an incident to enrich.
	inc := &incident.Incident{
		ID:        "inc-999",
		Title:     "ongoing",
		Severity:  incident.SeverityP2,
		Status:    incident.StatusInvestigating,
		Source:    incident.SourceManual,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.incidents[inc.ID] = inc

	payload, _ := json.Marshal(webhook.ThreatFlowEvent{
		EventID:    "evt-5",
		EventType:  "ioc_bundle",
		IncidentID: inc.ID,
		IOCs: []webhook.ThreatFlowIOC{
			{Type: "ip", Value: "198.51.100.7", Confidence: 0.9, Source: "threatflow"},
			{Type: "domain", Value: "evil.example", Confidence: 0.8, Source: "threatflow"},
		},
	})

	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/threatflow", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rec.Code, rec.Body.String())
	}
	iocs := store.iocs[inc.ID]
	if len(iocs) != 2 {
		t.Fatalf("got %d IOCs attached, want 2", len(iocs))
	}
}

func TestThreatFlowWebhook_NoIncidentIDQueuesForCorrelation(t *testing.T) {
	srv, store := newWebhookServer(t)

	payload, _ := json.Marshal(webhook.ThreatFlowEvent{
		EventID:   "evt-6",
		EventType: "ioc_bundle",
		IOCs: []webhook.ThreatFlowIOC{
			{Type: "hash", Value: "abc123", Confidence: 0.7, Source: "threatflow"},
		},
	})
	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/threatflow", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	for _, list := range store.iocs {
		if len(list) != 0 {
			t.Errorf("IOC should not be attached to any incident without incident_id")
		}
	}
}

func TestCyberPathWebhook_RemediationCompletedUpdatesTimeline(t *testing.T) {
	srv, store := newWebhookServer(t)

	// Seed an incident for the remediation event to reference.
	inc := &incident.Incident{
		ID:        "inc-cp-1",
		Title:     "phishing follow-up",
		Severity:  incident.SeverityP3,
		Status:    incident.StatusInvestigating,
		Source:    incident.SourceManual,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.incidents[inc.ID] = inc

	payload, _ := json.Marshal(webhook.CyberPathEvent{
		EventID:     "evt-cp-1",
		EventType:   "cyberpath.incident_remediation_completed",
		IncidentID:  inc.ID,
		CohortID:    "cohort-42",
		CompletedAt: time.Now(),
		OccurredAt:  time.Now(),
	})

	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/cyberpath/remediation", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rec.Code, rec.Body.String())
	}
	entries := store.timeline[inc.ID]
	if len(entries) != 1 {
		t.Fatalf("got %d timeline entries, want 1", len(entries))
	}
	if entries[0].EntryType != "cyberpath_remediation_completed" {
		t.Errorf("entry_type = %q, want cyberpath_remediation_completed", entries[0].EntryType)
	}
	if entries[0].ActorID != "cyberpath" {
		t.Errorf("actor_id = %q, want cyberpath", entries[0].ActorID)
	}
}

func TestCyberPathWebhook_UnknownIncidentAcknowledgedNoUpdate(t *testing.T) {
	srv, store := newWebhookServer(t)

	payload, _ := json.Marshal(webhook.CyberPathEvent{
		EventID:     "evt-cp-2",
		EventType:   "cyberpath.incident_remediation_completed",
		IncidentID:  "inc-does-not-exist",
		CohortID:    "cohort-7",
		CompletedAt: time.Now(),
	})

	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/cyberpath/remediation", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202. body: %s", rec.Code, rec.Body.String())
	}
	if len(store.timeline["inc-does-not-exist"]) != 0 {
		t.Errorf("timeline entry created for unknown incident")
	}
}

func TestCyberPathWebhook_NoIncidentIDAcknowledged(t *testing.T) {
	srv, _ := newWebhookServer(t)

	payload, _ := json.Marshal(webhook.CyberPathEvent{
		EventID:   "evt-cp-3",
		EventType: "cyberpath.incident_remediation_completed",
		CohortID:  "cohort-8",
	})

	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/cyberpath/remediation", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
}

func TestCyberPathWebhook_UnrecognisedEventTypeAcknowledged(t *testing.T) {
	srv, store := newWebhookServer(t)

	payload, _ := json.Marshal(webhook.CyberPathEvent{
		EventID:    "evt-cp-4",
		EventType:  "cyberpath.cohort_started",
		IncidentID: "inc-cp-1",
		CohortID:   "cohort-9",
	})

	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/cyberpath/remediation", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202. body: %s", rec.Code, rec.Body.String())
	}
	if len(store.timeline["inc-cp-1"]) != 0 {
		t.Errorf("timeline entry created for non-remediation event type")
	}
}

func TestCyberPathWebhook_RejectsInvalidSignature(t *testing.T) {
	srv, store := newWebhookServer(t)

	body := []byte(`{"event_id":"x","event_type":"cyberpath.incident_remediation_completed"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/cyberpath/remediation", bytes.NewReader(body))
	req.Header.Set(webhook.HeaderSignature, "sha256=deadbeef")
	req.Header.Set(webhook.HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if len(store.timeline) != 0 {
		t.Errorf("unauthorized request updated a timeline")
	}
}

func TestWebhook_RejectsMalformedJSON(t *testing.T) {
	srv, _ := newWebhookServer(t)

	body := []byte(`{not valid json`)
	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/apiguard", body)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestWebhook_RejectsOversizedBody(t *testing.T) {
	store := newAPIMockStore()
	svc := incident.NewService(store)
	srv := NewServer(Options{
		Logger:    zap.NewNop(),
		Incidents: svc,
		Webhooks: WebhookSecrets{
			APIGuard:    webhookTestSecret,
			MaxBodySize: 64, // tiny limit
		},
	})

	body := bytes.Repeat([]byte("x"), 128)
	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/apiguard", body)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}
