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

func TestFollowUser_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/alice/follow", nil)
	w := httptest.NewRecorder()

	handlers.FollowUser(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestFollowUser_SelfFollow_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/alice/follow", nil)
	req.SetPathValue("username", "alice")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.FollowUser(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for self-follow, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "cannot follow yourself" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestFollowUser_FollowerNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/bob/follow", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.FollowUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUnfollowUser_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/alice/follow", nil)
	w := httptest.NewRecorder()

	handlers.UnfollowUser(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

// UnfollowUser fails open on DB error: still returns 204.
func TestUnfollowUser_FollowerNotFound_StillReturns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/bob/follow", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnfollowUser(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestListFollowers_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/followers", nil)
	req.SetPathValue("username", "alice")
	w := httptest.NewRecorder()

	handlers.ListFollowers(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

func TestListFollowing_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/following", nil)
	req.SetPathValue("username", "alice")
	w := httptest.NewRecorder()

	handlers.ListFollowing(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

// GetFollowCounts fails open: unknown user still returns 200 with zero counts.
func TestGetFollowCounts_UserNotFound_ReturnsZeros(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/follow-counts", nil)
	req.SetPathValue("username", "alice")
	w := httptest.NewRecorder()

	handlers.GetFollowCounts(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]int
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["followers"] != 0 || resp["following"] != 0 {
		t.Errorf("expected zero counts, got %+v", resp)
	}
}

func TestGetFollowStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/follow-status", nil)
	w := httptest.NewRecorder()

	handlers.GetFollowStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

// GetFollowStatus fails open: unresolvable user still returns following=false.
func TestGetFollowStatus_FollowerNotFound_ReturnsFalse(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bob/follow-status", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetFollowStatus(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["following"] {
		t.Error("expected following=false when follower cannot be resolved")
	}
}

// ---------------------------------------------------------------------------
// Live-DB success paths.
// ---------------------------------------------------------------------------

func TestFollowUser_Success_CreatesFollowRow(t *testing.T) {
	d := dbDeps(t)
	_, followerUsername := createTestUser(t, d.Pool, "author")
	targetID, targetUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+targetUsername+"/follow", nil)
	req.SetPathValue("username", targetUsername)
	req = withClaims(req, &auth.Claims{Sub: followerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.FollowUser(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM follows f JOIN users u ON u.id=f.follower_id WHERE u.username=$1 AND f.following_id=$2`,
		followerUsername, targetID,
	).Scan(&count)
	if count != 1 {
		t.Errorf("expected exactly one follow row, got %d", count)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM follows WHERE following_id=$1`, targetID)
	})
}

func TestFollowUser_TargetNotFound_Returns404(t *testing.T) {
	d := dbDeps(t)
	_, followerUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/nonexistent-user/follow", nil)
	req.SetPathValue("username", "nonexistent-user-"+handlers.RandomSuffix())
	req = withClaims(req, &auth.Claims{Sub: followerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.FollowUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUnfollowUser_Success_RemovesFollowRow(t *testing.T) {
	d := dbDeps(t)
	followerID, followerUsername := createTestUser(t, d.Pool, "author")
	targetID, targetUsername := createTestUser(t, d.Pool, "author")

	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, followerID, targetID); err != nil {
		t.Fatalf("seed follow: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+targetUsername+"/follow", nil)
	req.SetPathValue("username", targetUsername)
	req = withClaims(req, &auth.Claims{Sub: followerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnfollowUser(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM follows WHERE follower_id=$1 AND following_id=$2`, followerID, targetID,
	).Scan(&count)
	if count != 0 {
		t.Error("expected follow row to be removed")
	}
}

func TestListFollowers_Success_ReturnsFollower(t *testing.T) {
	d := dbDeps(t)
	followerID, followerUsername := createTestUser(t, d.Pool, "author")
	targetID, targetUsername := createTestUser(t, d.Pool, "author")

	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, followerID, targetID); err != nil {
		t.Fatalf("seed follow: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM follows WHERE follower_id=$1 AND following_id=$2`, followerID, targetID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+targetUsername+"/followers", nil)
	req.SetPathValue("username", targetUsername)
	w := httptest.NewRecorder()

	handlers.ListFollowers(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Users []map[string]any `json:"users"`
		Count int              `json:"count"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, u := range resp.Users {
		if u["username"] == followerUsername {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in followers list, got %+v", followerUsername, resp.Users)
	}
}

func TestListFollowing_Success_ReturnsFollowedUser(t *testing.T) {
	d := dbDeps(t)
	followerID, followerUsername := createTestUser(t, d.Pool, "author")
	targetID, targetUsername := createTestUser(t, d.Pool, "author")

	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, followerID, targetID); err != nil {
		t.Fatalf("seed follow: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM follows WHERE follower_id=$1 AND following_id=$2`, followerID, targetID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+followerUsername+"/following", nil)
	req.SetPathValue("username", followerUsername)
	w := httptest.NewRecorder()

	handlers.ListFollowing(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Users []map[string]any `json:"users"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, u := range resp.Users {
		if u["username"] == targetUsername {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in following list, got %+v", targetUsername, resp.Users)
	}
}

func TestGetFollowCounts_Success_ReflectsRealCounts(t *testing.T) {
	d := dbDeps(t)
	followerID, _ := createTestUser(t, d.Pool, "author")
	targetID, targetUsername := createTestUser(t, d.Pool, "author")

	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, followerID, targetID); err != nil {
		t.Fatalf("seed follow: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM follows WHERE follower_id=$1 AND following_id=$2`, followerID, targetID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+targetUsername+"/follow-counts", nil)
	req.SetPathValue("username", targetUsername)
	w := httptest.NewRecorder()

	handlers.GetFollowCounts(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]int
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["followers"] != 1 {
		t.Errorf("expected followers=1, got %d", resp["followers"])
	}
}

func TestGetFollowStatus_Success_ReturnsTrueWhenFollowing(t *testing.T) {
	d := dbDeps(t)
	followerID, followerUsername := createTestUser(t, d.Pool, "author")
	targetID, targetUsername := createTestUser(t, d.Pool, "author")

	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, followerID, targetID); err != nil {
		t.Fatalf("seed follow: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM follows WHERE follower_id=$1 AND following_id=$2`, followerID, targetID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+targetUsername+"/follow-status", nil)
	req.SetPathValue("username", targetUsername)
	req = withClaims(req, &auth.Claims{Sub: followerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetFollowStatus(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if !resp["following"] {
		t.Error("expected following=true")
	}
}
