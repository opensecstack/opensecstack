package handlers_test

// DB-backed tests for comments.go — success paths, error paths, and
// authorization (IDOR) checks that a stubbed "bad pool" cannot exercise.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func createTestComment(t *testing.T, d handlers.Deps, postID, authorID string, parentID *string) string {
	t.Helper()
	var id string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO comments (post_id, parent_id, author_id, body) VALUES ($1,$2,$3,$4) RETURNING id`,
		postID, parentID, authorID, "a test comment",
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTestComment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM comments WHERE id=$1`, id)
	})
	return id
}

// ---------------------------------------------------------------------------
// ListComments
// ---------------------------------------------------------------------------

func TestListComments_Success_ReturnsCommentsForPost(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	createTestComment(t, d, postID, authorID, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/comments", nil)
	req.SetPathValue("id", postID)
	w := httptest.NewRecorder()

	handlers.ListComments(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Comments []map[string]any `json:"comments"`
		Count    int              `json:"count"`
		Total    int              `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || resp.Total != 1 {
		t.Errorf("expected 1 comment, got count=%d total=%d", resp.Count, resp.Total)
	}
}

// ---------------------------------------------------------------------------
// CreateComment
// ---------------------------------------------------------------------------

func TestCreateComment_Success_CreatesTopLevelComment(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	_, commenterUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/comments", strings.NewReader(`{"body":"Nice post!"}`))
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: commenterUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateComment(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == "" {
		t.Fatal("expected comment id in response")
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM comments WHERE id=$1`, resp["id"])
	})

	var body string
	if err := d.Pool.QueryRow(context.Background(), `SELECT body FROM comments WHERE id=$1`, resp["id"]).Scan(&body); err != nil {
		t.Fatalf("expected created comment to exist: %v", err)
	}
	if body != "Nice post!" {
		t.Errorf("expected body 'Nice post!', got %q", body)
	}
}

func TestCreateComment_ReplyFlattening_UsesGrandparentID(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	topLevelID := createTestComment(t, d, postID, authorID, nil)
	replyID := createTestComment(t, d, postID, authorID, &topLevelID)
	_, commenterUsername := createTestUser(t, d.Pool, "author")

	// A reply-to-a-reply should be flattened to reference topLevelID, not replyID.
	reqBody := `{"body":"deep reply","parent_id":"` + replyID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/comments", strings.NewReader(reqBody))
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: commenterUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateComment(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM comments WHERE id=$1`, resp["id"])
	})

	var parentID *string
	if err := d.Pool.QueryRow(context.Background(), `SELECT parent_id FROM comments WHERE id=$1`, resp["id"]).Scan(&parentID); err != nil {
		t.Fatalf("query: %v", err)
	}
	if parentID == nil || *parentID != topLevelID {
		t.Errorf("expected flattened parent_id=%q, got %v", topLevelID, parentID)
	}
}

func TestCreateComment_ParentFromDifferentPost_Returns400(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postA, _ := createTestPost(t, d.Pool, authorID, "published")
	postB, _ := createTestPost(t, d.Pool, authorID, "published")
	parentOnA := createTestComment(t, d, postA, authorID, nil)
	_, commenterUsername := createTestUser(t, d.Pool, "author")

	// Attempt to reply to a comment on postA while posting to postB.
	reqBody := `{"body":"cross-post reply","parent_id":"` + parentOnA + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postB+"/comments", strings.NewReader(reqBody))
	req.SetPathValue("id", postB)
	req = withClaims(req, &auth.Claims{Sub: commenterUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateComment(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for cross-post parent comment, got %d — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateComment — success + IDOR
// ---------------------------------------------------------------------------

func TestUpdateComment_Success_AuthorCanUpdateOwnComment(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/comments/"+commentID, strings.NewReader(`{"body":"edited"}`))
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdateComment(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var body string
	_ = d.Pool.QueryRow(context.Background(), `SELECT body FROM comments WHERE id=$1`, commentID).Scan(&body)
	if body != "edited" {
		t.Errorf("expected body to be updated, got %q", body)
	}
}

// IDOR: a different, unrelated user must not be able to edit someone else's
// comment. Note UpdateComment has no moderator bypass (unlike DeleteComment).
func TestUpdateComment_OtherUser_Returns403_IDOR(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/comments/"+commentID, strings.NewReader(`{"body":"hijacked"}`))
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdateComment(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when non-owner edits comment, got %d — body: %s", w.Code, w.Body.String())
	}
	var body string
	_ = d.Pool.QueryRow(context.Background(), `SELECT body FROM comments WHERE id=$1`, commentID).Scan(&body)
	if body == "hijacked" {
		t.Error("comment body must not have been changed by a non-owner")
	}
}

// IDOR: even a moderator cannot edit someone else's comment body via
// UpdateComment — only DeleteComment grants a moderator bypass. Confirms the
// handler's authorization check (authorUsername != claims.Sub) has no role
// exception, unlike posts_crud.go's UpdatePost.
func TestUpdateComment_Moderator_StillForbidden(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	_, modUsername := createTestUser(t, d.Pool, "moderator")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/comments/"+commentID, strings.NewReader(`{"body":"mod edit"}`))
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: modUsername, Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.UpdateComment(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 — UpdateComment has no moderator bypass, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteComment — success + IDOR + moderator bypass
// ---------------------------------------------------------------------------

func TestDeleteComment_Success_AuthorCanDeleteOwnComment(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/comments/"+commentID, nil)
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeleteComment(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM comments WHERE id=$1`, commentID).Scan(&count)
	if count != 0 {
		t.Error("expected comment to be deleted")
	}
}

// IDOR: a different, unrelated (non-moderator) user must not be able to
// delete someone else's comment.
func TestDeleteComment_OtherUser_Returns403_IDOR(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/comments/"+commentID, nil)
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeleteComment(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when non-owner deletes comment, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM comments WHERE id=$1`, commentID).Scan(&count)
	if count != 1 {
		t.Error("comment must still exist after forbidden delete attempt")
	}
}

func TestDeleteComment_Moderator_CanDeleteOthersComment(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	_, modUsername := createTestUser(t, d.Pool, "moderator")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/comments/"+commentID, nil)
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: modUsername, Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.DeleteComment(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected moderator to be able to delete others' comments, got %d — body: %s", w.Code, w.Body.String())
	}
}
