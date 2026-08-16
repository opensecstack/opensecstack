package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestListAuditLog_Success_ReturnsEntries(t *testing.T) {
	d := dbDeps(t)
	actorID, actorUsername := createTestUser(t, d.Pool, "admin")

	var entryID string
	if err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO audit_log (actor_id, action, target_type, target_id, note) VALUES ($1,'pin_post','post','some-post-id','') RETURNING id`,
		actorID).Scan(&entryID); err != nil {
		t.Fatalf("insert audit_log row: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM audit_log WHERE id=$1`, entryID) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log?limit=100&offset=0", nil)
	req = withClaims(req, &auth.Claims{Sub: actorUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.ListAuditLog(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Entries []map[string]any `json:"entries"`
		Count   int              `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, e := range resp.Entries {
		if e["id"] == entryID {
			found = true
			if e["actor_username"] != actorUsername {
				t.Errorf("expected actor_username %q, got %v", actorUsername, e["actor_username"])
			}
			if e["action"] != "pin_post" {
				t.Errorf("expected action=pin_post, got %v", e["action"])
			}
		}
	}
	if !found {
		t.Errorf("expected inserted audit_log entry %q in response", entryID)
	}
}

func TestListAuditLog_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.ListAuditLog(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin (moderator), got %d", w.Code)
	}
}

func TestListAuditLog_NoClaims_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log", nil)
	w := httptest.NewRecorder()

	handlers.ListAuditLog(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without claims, got %d", w.Code)
	}
}

func TestListAuditLog_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log", nil)
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.ListAuditLog(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}
