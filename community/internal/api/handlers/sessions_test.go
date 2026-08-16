package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestListSessions_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/sessions", nil)
	w := httptest.NewRecorder()

	handlers.ListSessions(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestListSessions_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/sessions", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListSessions(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRevokeSession_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/sessions/1", nil)
	w := httptest.NewRecorder()

	handlers.RevokeSession(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRevokeSession_EmptyID_Returns400(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/sessions/", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeSession(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty session id, got %d", w.Code)
	}
}

func TestRevokeSession_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/sessions/1", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeSession(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRevokeAllSessions_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/sessions", nil)
	w := httptest.NewRecorder()

	handlers.RevokeAllSessions(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRevokeAllSessions_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/sessions", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeAllSessions(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestSessionExists_DBError_ReturnsFalse(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	defer pool.Close()

	exists := handlers.SessionExists(context.Background(), pool, "some-hash")
	if exists {
		t.Error("expected false when the DB query fails")
	}
}

func TestUpdateLastSeen_DBError_DoesNotPanic(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	defer pool.Close()

	handlers.UpdateLastSeen(pool, "some-hash")
}

// ---------------------------------------------------------------------------
// Live-DB success paths and authz (IDOR) checks.
// ---------------------------------------------------------------------------

// insertTestSession inserts a user_sessions row directly and returns its id.
func insertTestSession(t *testing.T, pool *pgxpool.Pool, userID, tokenHash string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO user_sessions (user_id, token_hash, device_info, ip_address, expires_at)
		 VALUES ($1,$2,'test-device','127.0.0.1', now() + interval '1 hour')
		 RETURNING id`,
		userID, tokenHash,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestSession: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM user_sessions WHERE id=$1`, id)
	})
	return id
}

func bearerReq(method, target, rawToken string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if rawToken != "" {
		req.Header.Set("Authorization", "Bearer "+rawToken)
	}
	return req
}

func TestListSessions_Success_MarksCurrentSession(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")

	currentRaw := "raw-token-" + handlers.RandomSuffix()
	otherRaw := "raw-token-" + handlers.RandomSuffix()
	insertTestSession(t, d.Pool, userID, handlers.TokenHashForTest(currentRaw))
	insertTestSession(t, d.Pool, userID, handlers.TokenHashForTest(otherRaw))

	req := bearerReq(http.MethodGet, "/api/v1/me/sessions", currentRaw)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListSessions(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var sessions []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	currentCount := 0
	for _, s := range sessions {
		if isCurrent, _ := s["is_current"].(bool); isCurrent {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Errorf("expected exactly one session marked is_current, got %d", currentCount)
	}
}

func TestRevokeSession_Success_DeletesOtherSession(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")

	currentRaw := "raw-token-" + handlers.RandomSuffix()
	otherRaw := "raw-token-" + handlers.RandomSuffix()
	insertTestSession(t, d.Pool, userID, handlers.TokenHashForTest(currentRaw))
	otherSessionID := insertTestSession(t, d.Pool, userID, handlers.TokenHashForTest(otherRaw))

	req := bearerReq(http.MethodDelete, "/api/v1/me/sessions/"+otherSessionID, currentRaw)
	req.SetPathValue("id", otherSessionID)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeSession(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM user_sessions WHERE id=$1`, otherSessionID).Scan(&count)
	if count != 0 {
		t.Error("expected the revoked session row to be deleted")
	}
}

func TestRevokeSession_CurrentSession_Returns400(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")

	currentRaw := "raw-token-" + handlers.RandomSuffix()
	currentSessionID := insertTestSession(t, d.Pool, userID, handlers.TokenHashForTest(currentRaw))

	req := bearerReq(http.MethodDelete, "/api/v1/me/sessions/"+currentSessionID, currentRaw)
	req.SetPathValue("id", currentSessionID)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeSession(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when revoking the current session, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM user_sessions WHERE id=$1`, currentSessionID).Scan(&count)
	if count != 1 {
		t.Error("expected the current session to remain after a rejected self-revoke")
	}
}

// TestRevokeSession_OtherUsersSession_Returns404_IDOR proves a user cannot
// revoke a session belonging to a different user by guessing/enumerating its
// ID — the DELETE is scoped by `user_id = $2`, so it should affect zero rows
// and the victim's session must remain intact.
func TestRevokeSession_OtherUsersSession_Returns404_IDOR(t *testing.T) {
	d := dbDeps(t)
	victimID, _ := createTestUser(t, d.Pool, "author")
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	victimRaw := "raw-token-" + handlers.RandomSuffix()
	victimSessionID := insertTestSession(t, d.Pool, victimID, handlers.TokenHashForTest(victimRaw))

	attackerRaw := "raw-token-" + handlers.RandomSuffix()
	req := bearerReq(http.MethodDelete, "/api/v1/me/sessions/"+victimSessionID, attackerRaw)
	req.SetPathValue("id", victimSessionID)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeSession(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when attacker targets another user's session, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM user_sessions WHERE id=$1`, victimSessionID).Scan(&count)
	if count != 1 {
		t.Error("IDOR: victim's session must not be deleted by another user's request")
	}
}

func TestRevokeAllSessions_Success_KeepsCurrentDeletesOthers(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")

	currentRaw := "raw-token-" + handlers.RandomSuffix()
	currentSessionID := insertTestSession(t, d.Pool, userID, handlers.TokenHashForTest(currentRaw))
	otherSessionID := insertTestSession(t, d.Pool, userID, handlers.TokenHashForTest("raw-token-"+handlers.RandomSuffix()))

	req := bearerReq(http.MethodDelete, "/api/v1/me/sessions", currentRaw)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeAllSessions(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var currentCount, otherCount int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM user_sessions WHERE id=$1`, currentSessionID).Scan(&currentCount)
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM user_sessions WHERE id=$1`, otherSessionID).Scan(&otherCount)
	if currentCount != 1 {
		t.Error("expected current session to survive RevokeAllSessions")
	}
	if otherCount != 0 {
		t.Error("expected other session to be deleted by RevokeAllSessions")
	}
}

// TestRevokeAllSessions_NoMatchingCurrentSession_StillSucceeds covers the
// edge case where the caller's bearer token has no matching user_sessions
// row (e.g. it was already reaped/expired while the JWT itself is still
// valid). currentSessionID resolves to "" in that case, and the handler
// must not try to bind that empty string as a UUID exclusion param.
func TestRevokeAllSessions_NoMatchingCurrentSession_StillSucceeds(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")
	otherSessionID := insertTestSession(t, d.Pool, userID, handlers.TokenHashForTest("raw-token-"+handlers.RandomSuffix()))

	// Bearer token with no corresponding user_sessions row.
	req := bearerReq(http.MethodDelete, "/api/v1/me/sessions", "raw-token-"+handlers.RandomSuffix())
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeAllSessions(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 even with no matching current session, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM user_sessions WHERE id=$1`, otherSessionID).Scan(&count)
	if count != 0 {
		t.Error("expected the user's other session to be deleted when there is no current session to preserve")
	}
}

// TestRevokeAllSessions_DoesNotTouchOtherUsersSessions_IDOR proves the bulk
// revoke is scoped to the caller's own user_id and cannot be used to wipe
// out another user's sessions.
func TestRevokeAllSessions_DoesNotTouchOtherUsersSessions_IDOR(t *testing.T) {
	d := dbDeps(t)
	attackerID, attackerUsername := createTestUser(t, d.Pool, "author")
	victimID, _ := createTestUser(t, d.Pool, "author")
	victimSessionID := insertTestSession(t, d.Pool, victimID, handlers.TokenHashForTest("raw-token-"+handlers.RandomSuffix()))

	// The attacker needs their own session row for their bearer token to
	// resolve to a "current session" — otherwise RevokeAllSessions attempts
	// to bind an empty string as the UUID exclusion param and the DB call
	// errors out before we can observe the IDOR behaviour.
	attackerRaw := "raw-token-" + handlers.RandomSuffix()
	insertTestSession(t, d.Pool, attackerID, handlers.TokenHashForTest(attackerRaw))

	req := bearerReq(http.MethodDelete, "/api/v1/me/sessions", attackerRaw)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RevokeAllSessions(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM user_sessions WHERE id=$1`, victimSessionID).Scan(&count)
	if count != 1 {
		t.Error("IDOR: another user's session must survive a caller's RevokeAllSessions")
	}
}
