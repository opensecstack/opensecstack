package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func TestNIS2Client_Notify_EmptyAPIURLSuppresses(t *testing.T) {
	c := NewNIS2Client("", zerolog.Nop())
	err := c.Notify(context.Background(), NIS2Notification{Severity: "critical"})
	if err != nil {
		t.Fatalf("expected nil error when API URL is empty, got %v", err)
	}
}

func TestNIS2Client_Notify_BelowThresholdRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server must not be contacted for a below-threshold severity")
	}))
	defer srv.Close()

	c := NewNIS2Client(srv.URL, zerolog.Nop())
	err := c.Notify(context.Background(), NIS2Notification{Severity: "low"})
	if err == nil {
		t.Fatal("expected error for severity below notification threshold")
	}
}

func TestNIS2Client_Notify_HighSeveritySucceeds(t *testing.T) {
	var gotPath string
	var gotBody NIS2Notification
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	incidentID := uuid.New()
	c := NewNIS2Client(srv.URL, zerolog.Nop())
	err := c.Notify(context.Background(), NIS2Notification{
		IncidentID: incidentID,
		Severity:   "high",
		Title:      "test incident",
		OpenedAt:   time.Now().UTC(),
		Source:     "manual",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotPath != "/api/v1/notifications/article23" {
		t.Errorf("path = %q, want /api/v1/notifications/article23", gotPath)
	}
	if gotBody.IncidentID != incidentID {
		t.Errorf("IncidentID = %v, want %v", gotBody.IncidentID, incidentID)
	}
}

func TestNIS2Client_Notify_ServerErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewNIS2Client(srv.URL, zerolog.Nop())
	err := c.Notify(context.Background(), NIS2Notification{Severity: "critical"})
	if err == nil {
		t.Fatal("expected error for a 5xx response")
	}
}
