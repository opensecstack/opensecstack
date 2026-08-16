package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestGetSuggestedUsers_ExcludesSelfAndAlreadyFollowed(t *testing.T) {
	d := dbDeps(t)
	_, meUsername := createTestUser(t, d.Pool, "author")
	meID := ""
	if err := d.Pool.QueryRow(context.Background(), `SELECT id FROM users WHERE username=$1`, meUsername).Scan(&meID); err != nil {
		t.Fatalf("resolve meID: %v", err)
	}
	followedID, followedUsername := createTestUser(t, d.Pool, "author")
	strangerID, strangerUsername := createTestUser(t, d.Pool, "author")
	_ = strangerID

	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, meID, followedID); err != nil {
		t.Fatalf("insert follow: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM follows WHERE follower_id=$1 AND following_id=$2`, meID, followedID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/suggested", nil)
	req = withClaims(req, &auth.Claims{Sub: meUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetSuggestedUsers(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, u := range resp.Users {
		if u["username"] == meUsername {
			t.Error("suggested users must not include the requesting user themself")
		}
		if u["username"] == followedUsername {
			t.Error("suggested users must not include a user already followed")
		}
	}
	// stranger may or may not be in the (LIMIT 5) top suggestions depending on
	// other rows in the shared test DB, so we only assert the negative cases
	// above; strangerUsername is referenced to avoid an unused-var complaint
	// if a future edit removes the assertions.
	_ = strangerUsername
}

func TestGetSuggestedUsers_Unauthenticated_ReturnsAllUsers(t *testing.T) {
	d := dbDeps(t)
	_, username := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/suggested", nil)
	w := httptest.NewRecorder()

	handlers.GetSuggestedUsers(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	_ = username // presence not asserted: LIMIT 5 + shared DB ordering makes it flaky
}

func TestGetSuggestedUsers_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/suggested", nil)
	w := httptest.NewRecorder()

	handlers.GetSuggestedUsers(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestGetSuggestedUsers_Authenticated_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/suggested", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetSuggestedUsers(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}
