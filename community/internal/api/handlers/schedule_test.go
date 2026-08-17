package handlers_test

// Tests for schedule.go — SchedulePost and UnschedulePost had zero coverage
// prior to this file. They cover: the auth guard, request validation
// (RFC3339 parsing, future-time requirement), the "post not found" branch,
// the author/moderator authorization check (IDOR), and the real DB state
// transition on success.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestSchedulePost_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/schedule", nil)
	w := httptest.NewRecorder()

	handlers.SchedulePost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestSchedulePost_InvalidBody_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/schedule", bytes.NewReader([]byte("not json")))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.SchedulePost(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed body, got %d", w.Code)
	}
}

func TestSchedulePost_NonRFC3339Time_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	body, _ := json.Marshal(map[string]string{"scheduled_at": "not-a-date"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/schedule", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.SchedulePost(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unparseable time, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid scheduled_at, use RFC3339" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestSchedulePost_TimeInPast_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	past := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	body, _ := json.Marshal(map[string]string{"scheduled_at": past})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/schedule", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.SchedulePost(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a past scheduled_at, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "scheduled_at must be in the future" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestSchedulePost_PostNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	body, _ := json.Marshal(map[string]string{"scheduled_at": future})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/does-not-exist/schedule", bytes.NewReader(body))
	req.SetPathValue("id", "does-not-exist")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.SchedulePost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for a nonexistent post, got %d", w.Code)
	}
}

// TestSchedulePost_NotAuthorNorModerator_Returns403 proves the IDOR guard:
// a non-author, non-moderator user cannot schedule someone else's post.
func TestSchedulePost_NotAuthorNorModerator_Returns403(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, attackerUsername := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "draft")

	future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	body, _ := json.Marshal(map[string]string{"scheduled_at": future})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/schedule", bytes.NewReader(body))
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.SchedulePost(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when a non-author schedules another user's post, got %d — body: %s", w.Code, w.Body.String())
	}

	var state string
	if err := d.Pool.QueryRow(context.Background(), `SELECT state FROM posts WHERE id=$1`, postID).Scan(&state); err != nil {
		t.Fatalf("select state: %v", err)
	}
	if state != "draft" {
		t.Errorf("post state must be unchanged after a forbidden attempt, got %q", state)
	}
}

// TestSchedulePost_HappyPath_TransitionsPostToScheduled proves a successful
// call by the post's own author actually moves the row to state=scheduled
// with the requested scheduled_at, against a real DB.
func TestSchedulePost_HappyPath_TransitionsPostToScheduled(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "draft")

	future := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	body, _ := json.Marshal(map[string]string{"scheduled_at": future.Format(time.RFC3339)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/schedule", bytes.NewReader(body))
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.SchedulePost(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var state string
	var scheduledAt time.Time
	if err := d.Pool.QueryRow(context.Background(),
		`SELECT state, scheduled_at FROM posts WHERE id=$1`, postID,
	).Scan(&state, &scheduledAt); err != nil {
		t.Fatalf("select: %v", err)
	}
	if state != "scheduled" {
		t.Errorf("expected state=scheduled, got %q", state)
	}
	if !scheduledAt.Equal(future) {
		t.Errorf("expected scheduled_at=%v, got %v", future, scheduledAt)
	}
}

// TestSchedulePost_ModeratorCanScheduleAnothersPost proves the moderator
// bypass branch of the authorization check.
func TestSchedulePost_ModeratorCanScheduleAnothersPost(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, modUsername := createTestUser(t, d.Pool, "moderator")
	postID, _ := createTestPost(t, d.Pool, authorID, "draft")

	future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	body, _ := json.Marshal(map[string]string{"scheduled_at": future})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/schedule", bytes.NewReader(body))
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: modUsername, Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.SchedulePost(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected moderator to be allowed to schedule another user's post, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUnschedulePost_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/unschedule", nil)
	w := httptest.NewRecorder()

	handlers.UnschedulePost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestUnschedulePost_PostNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/does-not-exist/unschedule", nil)
	req.SetPathValue("id", "does-not-exist")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnschedulePost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for a nonexistent post, got %d", w.Code)
	}
}

// TestUnschedulePost_NotAuthorNorModerator_Returns403 proves the IDOR guard
// on the unschedule path too.
func TestUnschedulePost_NotAuthorNorModerator_Returns403(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, attackerUsername := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "scheduled")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/unschedule", nil)
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnschedulePost(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 when a non-author unschedules another user's post, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestUnschedulePost_HappyPath_RevertsPostToDraft proves a successful call
// clears scheduled_at and moves state back to draft, against a real DB.
func TestUnschedulePost_HappyPath_RevertsPostToDraft(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "draft")

	future := time.Now().Add(24 * time.Hour)
	if _, err := d.Pool.Exec(context.Background(),
		`UPDATE posts SET state='scheduled', scheduled_at=$1 WHERE id=$2`, future, postID,
	); err != nil {
		t.Fatalf("seed scheduled state: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/unschedule", nil)
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnschedulePost(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var state string
	var scheduledAt *time.Time
	if err := d.Pool.QueryRow(context.Background(),
		`SELECT state, scheduled_at FROM posts WHERE id=$1`, postID,
	).Scan(&state, &scheduledAt); err != nil {
		t.Fatalf("select: %v", err)
	}
	if state != "draft" {
		t.Errorf("expected state=draft, got %q", state)
	}
	if scheduledAt != nil {
		t.Errorf("expected scheduled_at to be cleared, got %v", *scheduledAt)
	}
}
