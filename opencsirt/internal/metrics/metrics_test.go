package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandler_ExposesRegisteredCounters proves the /metrics handler actually
// serves the Prometheus registry this package builds, not just "some" HTTP
// response: every counter/gauge registered in init() must appear in the
// exposition output by name.
func TestHandler_ExposesRegisteredCounters(t *testing.T) {
	IncidentsCreated.WithLabelValues("irflow", "high").Inc()
	IncidentsClosed.WithLabelValues("high").Inc()
	AdvisoriesPublished.WithLabelValues("clear").Inc()
	EscalationsSent.Inc()
	CitadelEvents.WithLabelValues("emitted").Inc()
	CitadelQueueDepth.Set(3)
	IOCsIngested.WithLabelValues("taranis").Inc()

	req := httptest.NewRequest("GET", "/api/v1/metrics", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()

	for _, name := range []string{
		"opencsirt_incidents_created_total",
		"opencsirt_incidents_closed_total",
		"opencsirt_advisories_published_total",
		"opencsirt_escalations_sent_total",
		"opencsirt_citadel_events_total",
		"opencsirt_citadel_queue_depth",
		"opencsirt_iocs_ingested_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("metrics output missing %q", name)
		}
	}

	if !strings.Contains(body, `opencsirt_citadel_queue_depth 3`) {
		t.Errorf("expected gauge value 3 in output, got:\n%s", body)
	}
}
