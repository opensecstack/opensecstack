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

func TestExportMyData_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/export", nil)
	w := httptest.NewRecorder()

	handlers.ExportMyData(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestExportMyData_ProfileNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/export", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ExportMyData(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestExportMyData_Success_IncludesOwnDataOnly seeds a full set of related
// rows (post, comment, follower/following, bookmark) for the requesting user
// plus a second user's post, and verifies the export payload contains only
// data scoped to the requester.
func TestExportMyData_Success_IncludesOwnDataOnly(t *testing.T) {
	d := dbDeps(t)

	// exportProfile.Email is scanned into a non-pointer string, so the seeded
	// user must have a non-NULL email — createTestUser doesn't set one.
	username := "exp_" + handlers.RandomSuffix()
	var userID string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO users (username, display_name, email, role) VALUES ($1,$1,$2,'author') RETURNING id`,
		username, username+"@example.test",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	handlers.CleanupUserByUsername(t, d.Pool, username)

	postID, _ := createTestPost(t, d.Pool, userID, "published")

	_, err = d.Pool.Exec(context.Background(),
		`INSERT INTO comments (post_id, author_id, body) VALUES ($1,$2,'my exported comment')`, postID, userID)
	if err != nil {
		t.Fatalf("seed comment: %v", err)
	}

	otherID, otherUsername := createTestUser(t, d.Pool, "author")

	// userID follows otherID, and otherID follows userID back.
	if _, err := d.Pool.Exec(context.Background(), `INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, userID, otherID); err != nil {
		t.Fatalf("seed following: %v", err)
	}
	if _, err := d.Pool.Exec(context.Background(), `INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, otherID, userID); err != nil {
		t.Fatalf("seed follower: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM follows WHERE follower_id IN ($1,$2) AND following_id IN ($1,$2)`, userID, otherID)
	})

	_, otherPostSlug := createTestPost(t, d.Pool, otherID, "published")
	var otherPostID string
	_ = d.Pool.QueryRow(context.Background(), `SELECT id FROM posts WHERE slug=$1`, otherPostSlug).Scan(&otherPostID)
	if _, err := d.Pool.Exec(context.Background(), `INSERT INTO bookmarks (user_id, post_id) VALUES ($1,$2)`, userID, otherPostID); err != nil {
		t.Fatalf("seed bookmark: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM bookmarks WHERE user_id=$1`, userID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/export", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ExportMyData(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Disposition"); got == "" {
		t.Error("expected Content-Disposition header for downloadable export")
	}

	var payload struct {
		Profile struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"profile"`
		Posts []struct {
			Title string `json:"title"`
		} `json:"posts"`
		Comments []struct {
			Body string `json:"body"`
		} `json:"comments"`
		Following []string `json:"following"`
		Followers []string `json:"followers"`
		Bookmarks []string `json:"bookmarks"`
	}
	if err := json.NewDecoder(w.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload.Profile.Username != username {
		t.Errorf("expected profile username %q, got %q", username, payload.Profile.Username)
	}
	if len(payload.Posts) != 1 {
		t.Fatalf("expected exactly 1 own post, got %d: %+v", len(payload.Posts), payload.Posts)
	}
	commentFound := false
	for _, c := range payload.Comments {
		if c.Body == "my exported comment" {
			commentFound = true
		}
	}
	if !commentFound {
		t.Error("expected own comment in export")
	}
	followingFound, followerFound, bookmarkFound := false, false, false
	for _, u := range payload.Following {
		if u == otherUsername {
			followingFound = true
		}
	}
	for _, u := range payload.Followers {
		if u == otherUsername {
			followerFound = true
		}
	}
	for _, s := range payload.Bookmarks {
		if s == otherPostSlug {
			bookmarkFound = true
		}
	}
	if !followingFound {
		t.Error("expected other user in following list")
	}
	if !followerFound {
		t.Error("expected other user in followers list")
	}
	if !bookmarkFound {
		t.Error("expected bookmarked post slug in bookmarks list")
	}
}
