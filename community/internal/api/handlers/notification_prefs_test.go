package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestGetNotificationPrefs_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/notifications", nil)
	w := httptest.NewRecorder()

	handlers.GetNotificationPrefs(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestGetNotificationPrefs_DBError_FallsBackToDefaults verifies that a
// failed lookup (e.g. no preferences row yet, or here a DB error) yields
// the documented default preferences rather than an error response.
func TestGetNotificationPrefs_DBError_FallsBackToDefaults(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/notifications", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetNotificationPrefs(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with default prefs on db error, got %d — body: %s", w.Code, w.Body.String())
	}

	var got struct {
		MentionEmail    bool   `json:"mention_email"`
		DigestEnabled   bool   `json:"digest_enabled"`
		DigestFrequency string `json:"digest_frequency"`
		EmailFollows    bool   `json:"email_follows"`
		EmailComments   bool   `json:"email_comments"`
		EmailReactions  bool   `json:"email_reactions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.MentionEmail || got.DigestEnabled || got.DigestFrequency != "weekly" ||
		!got.EmailFollows || !got.EmailComments || got.EmailReactions {
		t.Errorf("unexpected default prefs: %+v", got)
	}
}

func TestUpdateNotificationPrefs_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/notifications", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()

	handlers.UpdateNotificationPrefs(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestUpdateNotificationPrefs_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/notifications", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdateNotificationPrefs(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestUpdateNotificationPrefs_InvalidFrequency_DefaultsToWeekly(t *testing.T) {
	// The handler silently normalizes an invalid digest_frequency to "weekly"
	// rather than rejecting the request; the DB write still fails here
	// because of the bad pool, proving the request reached the Exec step
	// (i.e. validation didn't reject it).
	d := newDepsWithBadDB(t)
	body := []byte(`{"digest_frequency":"monthly"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/notifications", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdateNotificationPrefs(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected request to pass validation and hit db error (500), got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUpdateNotificationPrefs_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	body := []byte(`{"digest_frequency":"daily"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/notifications", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdateNotificationPrefs(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}
