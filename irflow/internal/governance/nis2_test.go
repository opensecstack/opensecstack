package governance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

// testNIS2Server emulates NIS2 Compass. tokenTTL controls when the mock token
// expires; set a short TTL to exercise the refresh path.
type testNIS2Server struct {
	server    *httptest.Server
	tokenHits atomic.Int32
	patchHits atomic.Int32
	lastPatch patchControlRequest
	tokenTTL  time.Duration
}

func newTestNIS2Server(ttl time.Duration) *testNIS2Server {
	ts := &testNIS2Server{tokenTTL: ttl}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		ts.tokenHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		resp := authTokenResponse{
			Token:     "jwt-token-xyz",
			ExpiresAt: time.Now().Add(ts.tokenTTL),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/v1/assessments/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &ts.lastPatch)
		ts.patchHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ctl-1","status":"non_compliant"}`))
	})
	ts.server = httptest.NewServer(mux)
	return ts
}

func (ts *testNIS2Server) Close() { ts.server.Close() }

func TestNIS2_NotifyIncidentSendsExpectedPayload(t *testing.T) {
	ts := newTestNIS2Server(1 * time.Hour)
	defer ts.Close()

	c := NewNIS2Client(NIS2ClientConfig{
		BaseURL:      ts.server.URL,
		APIKey:       "key",
		AssessmentID: "asmt-1",
		MeasureRef:   "b",
	})

	inc := &incident.Incident{
		ID:        "inc-7",
		Title:     "ransomware detected",
		Severity:  incident.SeverityP1,
		Source:    incident.SourceAPIGuard,
		SourceRef: "scan-42",
		CreatedAt: time.Now(),
	}
	if err := c.NotifyIncident(context.Background(), inc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts.patchHits.Load() != 1 {
		t.Fatalf("patch called %d times, want 1", ts.patchHits.Load())
	}
	if ts.lastPatch.Status != "non_compliant" {
		t.Errorf("status = %s, want non_compliant", ts.lastPatch.Status)
	}
	if ts.lastPatch.RiskScore == nil || *ts.lastPatch.RiskScore < 9.0 {
		t.Errorf("risk_score for P1 should be >= 9.0, got %v", ts.lastPatch.RiskScore)
	}
	if ts.lastPatch.Evidence["incident_id"] != "inc-7" {
		t.Errorf("evidence.incident_id = %v, want inc-7", ts.lastPatch.Evidence["incident_id"])
	}
}

func TestNIS2_NotifyIncidentIsNoOpWhenNotConfigured(t *testing.T) {
	// Missing assessment ID should make the client a no-op rather than an error
	// — lets the incident Service call it unconditionally.
	c := NewNIS2Client(NIS2ClientConfig{BaseURL: "http://example.invalid", APIKey: "k"})
	err := c.NotifyIncident(context.Background(), &incident.Incident{ID: "x", Severity: incident.SeverityP1, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestNIS2_TokenCachedBetweenCalls(t *testing.T) {
	ts := newTestNIS2Server(1 * time.Hour)
	defer ts.Close()

	c := NewNIS2Client(NIS2ClientConfig{
		BaseURL:      ts.server.URL,
		APIKey:       "key",
		AssessmentID: "asmt-1",
	})

	inc := &incident.Incident{ID: "inc-1", Severity: incident.SeverityP2, CreatedAt: time.Now()}
	for i := 0; i < 3; i++ {
		if err := c.NotifyIncident(context.Background(), inc); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
	if got := ts.tokenHits.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (token should be cached)", got)
	}
	if got := ts.patchHits.Load(); got != 3 {
		t.Errorf("patch endpoint hit %d times, want 3", got)
	}
}

func TestNIS2_TokenRefreshedWhenNearlyExpired(t *testing.T) {
	// Short TTL forces refresh on the next call (the client refreshes when
	// less than 60s remains; a 1s TTL is always "near expiry").
	ts := newTestNIS2Server(1 * time.Second)
	defer ts.Close()

	c := NewNIS2Client(NIS2ClientConfig{
		BaseURL:      ts.server.URL,
		APIKey:       "key",
		AssessmentID: "asmt-1",
	})

	inc := &incident.Incident{ID: "inc-1", Severity: incident.SeverityP2, CreatedAt: time.Now()}
	if err := c.NotifyIncident(context.Background(), inc); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := c.NotifyIncident(context.Background(), inc); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := ts.tokenHits.Load(); got != 2 {
		t.Errorf("token endpoint hit %d times, want 2 (should refresh near expiry)", got)
	}
}

func TestSeverityToRiskScore_Monotonic(t *testing.T) {
	p1 := severityToRiskScore(incident.SeverityP1)
	p2 := severityToRiskScore(incident.SeverityP2)
	p3 := severityToRiskScore(incident.SeverityP3)
	p4 := severityToRiskScore(incident.SeverityP4)
	if !(p1 > p2 && p2 > p3 && p3 > p4) {
		t.Errorf("risk scores not monotonically decreasing: P1=%f P2=%f P3=%f P4=%f", p1, p2, p3, p4)
	}
}
