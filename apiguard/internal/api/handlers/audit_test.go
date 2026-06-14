package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

// TestAuditList_InvalidAction verifies that an unrecognised action query param
// causes the handler to return 400 before touching the database.
func TestAuditList_InvalidAction(t *testing.T) {
	logger := zerolog.Nop()
	h := NewAudit(logger, nil) // nil db — validation fires before any DB call

	req := httptest.NewRequest(http.MethodGet, "/audit?action=invalid_action", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode error body: %v", err)
	}
	if _, ok := body["message"]; !ok {
		if _, ok2 := body["error"]; !ok2 {
			t.Error("response body should contain an error description")
		}
	}
}

// TestAuditList_InvalidResourceID verifies that a non-UUID resource_id value
// causes the handler to return 400 before touching the database.
func TestAuditList_InvalidResourceID(t *testing.T) {
	logger := zerolog.Nop()
	h := NewAudit(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit?resource_id=not-a-uuid", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode error body: %v", err)
	}
	if _, ok := body["message"]; !ok {
		if _, ok2 := body["error"]; !ok2 {
			t.Error("response body should contain an error description")
		}
	}
}

// TestAuditList_ValidAction verifies that a recognised action value passes
// validation (the handler does not return 400). Because the DB is nil the call
// will panic after passing validation; we recover from the panic so the test
// can assert only on the validation outcome.
func TestAuditList_ValidAction(t *testing.T) {
	logger := zerolog.Nop()
	h := NewAudit(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit?action=scan_created", nil)
	rec := httptest.NewRecorder()

	// Recover from the nil-pointer dereference that occurs when the handler
	// tries to call h.db.ListAuditLog after passing validation.
	func() {
		defer func() { recover() }() //nolint:errcheck
		h.List(rec, req)
	}()

	// The handler must NOT have written 400 before reaching the DB call.
	if rec.Code == http.StatusBadRequest {
		t.Errorf("valid action should not return 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAuditList_NoParams verifies that an empty query string passes validation
// and does not produce a 400 response.
func TestAuditList_NoParams(t *testing.T) {
	logger := zerolog.Nop()
	h := NewAudit(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()

	func() {
		defer func() { recover() }() //nolint:errcheck
		h.List(rec, req)
	}()

	if rec.Code == http.StatusBadRequest {
		t.Errorf("request with no params should not return 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAuditList_AllValidActions checks every defined AuditAction constant and
// asserts that none of them are rejected with 400.
func TestAuditList_AllValidActions(t *testing.T) {
	validActions := []string{
		"scan_created",
		"scan_started",
		"scan_completed",
		"scan_failed",
		"scan_deleted",
		"finding_triaged",
		"finding_status_changed",
		"spec_uploaded",
		"spec_parsed",
		"report_generated",
		"report_exported",
		"api_key_created",
		"api_key_revoked",
	}

	logger := zerolog.Nop()

	for _, action := range validActions {
		action := action
		t.Run(action, func(t *testing.T) {
			h := NewAudit(logger, nil)

			req := httptest.NewRequest(http.MethodGet, "/audit?action="+action, nil)
			rec := httptest.NewRecorder()

			func() {
				defer func() { recover() }() //nolint:errcheck
				h.List(rec, req)
			}()

			if rec.Code == http.StatusBadRequest {
				t.Errorf("action %q should be accepted, but got 400; body: %s", action, rec.Body.String())
			}
		})
	}
}

// TestAuditList_ValidUUIDResourceID verifies that a well-formed UUID passes
// validation and does not trigger a 400 response.
func TestAuditList_ValidUUIDResourceID(t *testing.T) {
	logger := zerolog.Nop()
	h := NewAudit(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit?resource_id=550e8400-e29b-41d4-a716-446655440000", nil)
	rec := httptest.NewRecorder()

	func() {
		defer func() { recover() }() //nolint:errcheck
		h.List(rec, req)
	}()

	if rec.Code == http.StatusBadRequest {
		t.Errorf("valid UUID resource_id should not return 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
