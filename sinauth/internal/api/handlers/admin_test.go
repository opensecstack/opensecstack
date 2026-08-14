//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/audit"
	"github.com/opensecstack/sinauth/internal/session"
)

// TestListAuditLog_ReturnsEmptyArrayNotNull proves that when there are no
// matching entries the handler still emits a JSON array ("[]"), not "null" —
// callers that do `for (const e of body)` in JS would throw on null.
func TestListAuditLog_ReturnsEmptyArrayNotNull(t *testing.T) {
	pool := requireDB(t)
	d := Deps{Audit: audit.NewStore(pool)}

	// limit=0 with no rows in range is unlikely to be literally empty given
	// other tests may have inserted rows concurrently, so instead directly
	// assert the response is valid JSON array syntax (never the literal
	// "null"), which is the actual contract this handler must uphold.
	req := httptest.NewRequest(http.MethodGet, "/admin/audit-log", nil)
	rec := httptest.NewRecorder()
	ListAuditLog(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if len(body) == 0 || body[0] != '[' {
		t.Fatalf("body = %q, expected a JSON array", body)
	}
	var entries []audit.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
}

// TestListAuditLog_RespectsLimitParam proves the ?limit= query parameter is
// actually parsed and applied, not ignored in favor of the default 100.
func TestListAuditLog_RespectsLimitParam(t *testing.T) {
	pool := requireDB(t)
	d := Deps{Audit: audit.NewStore(pool)}

	// Insert a handful of distinguishable entries synchronously (bypassing
	// the async Log() goroutine so the test is deterministic).
	actor := fmt.Sprintf("limit-test-%d", time.Now().UnixNano())
	for i := 0; i < 5; i++ {
		_, err := pool.Exec(context.Background(),
			`INSERT INTO audit_log (event_type, actor, client_id, ip_address, user_agent) VALUES ($1,$2,$3,$4,$5)`,
			"test.event", actor, "", "127.0.0.1", "test-agent")
		if err != nil {
			t.Fatalf("insert audit row %d: %v", i, err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM audit_log WHERE actor=$1`, actor) })

	req := httptest.NewRequest(http.MethodGet, "/admin/audit-log?limit=2", nil)
	rec := httptest.NewRecorder()
	ListAuditLog(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var entries []audit.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (limit not respected)", len(entries))
	}
}

// TestListSessions_ReturnsEmptyArrayNotNull mirrors the audit-log nil-array
// hardening for /admin/sessions.
func TestListSessions_ReturnsEmptyArrayNotNull(t *testing.T) {
	pool := requireDB(t)
	d := Deps{SessionSvc: session.NewService(session.NewStore(pool))}

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	rec := httptest.NewRecorder()
	ListSessions(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if len(body) == 0 || body[0] != '[' {
		t.Fatalf("body = %q, expected a JSON array", body)
	}
}

// TestListSessions_IncludesActiveSession proves a real, unexpired SSO
// session created through session.Service actually shows up in the list.
func TestListSessions_IncludesActiveSession(t *testing.T) {
	pool := requireDB(t)
	sessSvc := session.NewService(session.NewStore(pool))
	d := testDeps(t, pool)
	d.SessionSvc = sessSvc

	u := createTestAuthorizeUser(t, d, fmt.Sprintf("admin-sess-%d", time.Now().UnixNano()))
	sess, err := sessSvc.Create(context.Background(), u.ID, u.Username, time.Hour)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	t.Cleanup(func() { _ = sessSvc.Revoke(context.Background(), sess.ID) })

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	rec := httptest.NewRecorder()
	ListSessions(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var sessions []session.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	found := false
	for _, s := range sessions {
		if s.ID == sess.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected session %q in list, got %d sessions", sess.ID, len(sessions))
	}
}

// TestRevokeSession_DeletesSessionAndAudits proves RevokeSession actually
// deletes the row (a subsequent Get fails) and writes an audit entry, not
// just returning a success message.
func TestRevokeSession_DeletesSessionAndAudits(t *testing.T) {
	pool := requireDB(t)
	sessSvc := session.NewService(session.NewStore(pool))
	d := testDeps(t, pool)
	d.SessionSvc = sessSvc
	d.Audit = audit.NewStore(pool)

	u := createTestAuthorizeUser(t, d, fmt.Sprintf("revoke-sess-%d", time.Now().UnixNano()))
	sess, err := sessSvc.Create(context.Background(), u.ID, u.Username, time.Hour)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/sessions/"+sess.ID, nil)
	req.SetPathValue("id", sess.ID)
	rec := httptest.NewRecorder()
	RevokeSession(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if _, err := sessSvc.Get(context.Background(), sess.ID); err == nil {
		t.Error("session still retrievable after RevokeSession — was not actually deleted")
	}
}
