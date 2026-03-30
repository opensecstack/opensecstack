package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

// injectChiID returns a copy of r with the chi route param "id" set to value.
func injectChiID(r *http.Request, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// ---- List validation --------------------------------------------------------

func TestFindingsList_InvalidSeverity(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/findings?severity=invalid", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestFindingsList_InvalidStatus(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/findings?status=invalid_status", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestFindingsList_InvalidScanID(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/findings?scan_id=not-a-uuid", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestFindingsList_ValidSeverities checks every accepted severity value and
// asserts that none produce a 400 response (validation passes before DB hit).
func TestFindingsList_ValidSeverities(t *testing.T) {
	valid := []string{"critical", "high", "medium", "low", "info"}
	logger := zerolog.Nop()

	for _, sev := range valid {
		sev := sev
		t.Run(sev, func(t *testing.T) {
			h := NewFindings(logger, nil)

			req := httptest.NewRequest(http.MethodGet, "/findings?severity="+sev, nil)
			rec := httptest.NewRecorder()

			func() {
				defer func() { recover() }() //nolint:errcheck
				h.List(rec, req)
			}()

			if rec.Code == http.StatusBadRequest {
				t.Errorf("severity %q should be accepted, got 400; body: %s", sev, rec.Body.String())
			}
		})
	}
}

// TestFindingsList_ValidStatuses checks every accepted status value.
func TestFindingsList_ValidStatuses(t *testing.T) {
	valid := []string{"open", "confirmed", "false_positive", "accepted", "fixed"}
	logger := zerolog.Nop()

	for _, st := range valid {
		st := st
		t.Run(st, func(t *testing.T) {
			h := NewFindings(logger, nil)

			req := httptest.NewRequest(http.MethodGet, "/findings?status="+st, nil)
			rec := httptest.NewRecorder()

			func() {
				defer func() { recover() }() //nolint:errcheck
				h.List(rec, req)
			}()

			if rec.Code == http.StatusBadRequest {
				t.Errorf("status %q should be accepted, got 400; body: %s", st, rec.Body.String())
			}
		})
	}
}

// ---- Get validation ---------------------------------------------------------

func TestFindingsGet_InvalidUUID(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/findings/not-a-uuid", nil)
	req = injectChiID(req, "not-a-uuid")
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestFindingsGet_MissingID(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	// No chi route context injected — URLParam returns "".
	req := httptest.NewRequest(http.MethodGet, "/findings/", nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing id, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---- Update validation ------------------------------------------------------

// validFindingID is a well-formed UUID used to pass parseUUID in Update tests.
const validFindingID = "550e8400-e29b-41d4-a716-446655440000"

func TestFindingsUpdate_EmptyBody_Returns400WithCode(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPatch, "/findings/"+validFindingID, body)
	req.Header.Set("Content-Type", "application/json")
	req = injectChiID(req, validFindingID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var respBody map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&respBody); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if code, ok := respBody["code"]; !ok || code != "INVALID_INPUT" {
		t.Errorf("want error code INVALID_INPUT, got %v (full body: %v)", code, respBody)
	}
}

func TestFindingsUpdate_InvalidStatus_Returns422(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	payload := `{"status":"not_a_real_status"}`
	req := httptest.NewRequest(http.MethodPatch, "/findings/"+validFindingID, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = injectChiID(req, validFindingID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("want 422, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestFindingsUpdate_NoteTooLong_Returns400 verifies that a note exceeding
// 4096 characters is rejected with 400. A valid "status" is included so the
// handler does not need to reach the DB before checking the note length.
func TestFindingsUpdate_NoteTooLong_Returns400(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	longNote := strings.Repeat("x", 4097) // one character over the 4096-char limit
	// Include status so the handler skips the DB fetch for current status and
	// reaches the note length check before any DB access.
	payload, _ := json.Marshal(map[string]string{
		"status": "open",
		"note":   longNote,
	})

	req := httptest.NewRequest(http.MethodPatch, "/findings/"+validFindingID, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = injectChiID(req, validFindingID)
	rec := httptest.NewRecorder()

	func() {
		defer func() { recover() }() //nolint:errcheck
		h.Update(rec, req)
	}()

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for oversized note, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestFindingsUpdate_MalformedJSON_Returns400(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	req := httptest.NewRequest(http.MethodPatch, "/findings/"+validFindingID, strings.NewReader(`{not valid json`))
	req.Header.Set("Content-Type", "application/json")
	req = injectChiID(req, validFindingID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for malformed JSON, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestFindingsUpdate_InvalidUUID_Returns400(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	req := httptest.NewRequest(http.MethodPatch, "/findings/bad-id", strings.NewReader(`{"status":"open"}`))
	req.Header.Set("Content-Type", "application/json")
	req = injectChiID(req, "bad-id")
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid UUID path param, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestFindingsUpdate_ExactlyMaxNoteLength verifies that a note of exactly 4096
// characters is accepted (does not return 400 from note validation). The
// handler will panic on the nil DB call after validation; we recover and check
// only that 400 was NOT written by the validation guard.
func TestFindingsUpdate_ExactlyMaxNoteLength(t *testing.T) {
	logger := zerolog.Nop()
	h := NewFindings(logger, nil)

	note := strings.Repeat("z", 4096)
	payload, _ := json.Marshal(map[string]string{
		"status": "open",
		"note":   note,
	})

	req := httptest.NewRequest(http.MethodPatch, "/findings/"+validFindingID, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = injectChiID(req, validFindingID)
	rec := httptest.NewRecorder()

	func() {
		defer func() { recover() }() //nolint:errcheck
		h.Update(rec, req)
	}()

	if rec.Code == http.StatusBadRequest {
		t.Errorf("note of exactly 4096 chars should not return 400; body: %s", rec.Body.String())
	}
}
