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

func TestMuteUser_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/bob/mute", nil)
	w := httptest.NewRecorder()

	handlers.MuteUser(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMuteUser_MuterNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/bob/mute", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.MuteUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when caller cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUnmuteUser_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/bob/mute", nil)
	w := httptest.NewRecorder()

	handlers.UnmuteUser(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestUnmuteUser_MuterNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/bob/mute", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnmuteUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when caller cannot be resolved, got %d", w.Code)
	}
}

func TestGetMuteStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bob/mute", nil)
	w := httptest.NewRecorder()

	handlers.GetMuteStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestGetMuteStatus_MuterNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bob/mute", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetMuteStatus(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when caller cannot be resolved, got %d", w.Code)
	}
}

func TestListMutedUsers_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/mutes", nil)
	w := httptest.NewRecorder()

	handlers.ListMutedUsers(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestListMutedUsers_CallerNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/mutes", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListMutedUsers(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when caller cannot be resolved, got %d", w.Code)
	}
}

// ---------- live-DB success-path tests ----------

func TestMuteUser_SelfMute_Returns400(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "mute_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+username+"/mute", nil)
	req.SetPathValue("username", username)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.MuteUser(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for self-mute, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestMuteUser_TargetNotFound_Returns404(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "mute_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/nobody/mute", nil)
	req.SetPathValue("username", "nobody-"+handlers.RandomSuffix())
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.MuteUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent target, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestMuteUser_Success_Idempotent_Status_Unmute_List(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	muter := "mute_" + handlers.RandomSuffix()
	target := "mute_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, muter); err != nil {
		t.Fatalf("insert muter: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, muter)
	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, target); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, target)

	// Mute: succeeds.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+target+"/mute", nil)
	req.SetPathValue("username", target)
	req = withClaims(req, &auth.Claims{Sub: muter, Role: "author"})
	w := httptest.NewRecorder()
	handlers.MuteUser(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on first mute, got %d — body: %s", w.Code, w.Body.String())
	}

	// Mute again: idempotent (ON CONFLICT DO NOTHING), still 204.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+target+"/mute", nil)
	req2.SetPathValue("username", target)
	req2 = withClaims(req2, &auth.Claims{Sub: muter, Role: "author"})
	w2 := httptest.NewRecorder()
	handlers.MuteUser(d)(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on repeated mute (idempotent), got %d — body: %s", w2.Code, w2.Body.String())
	}

	// Status: true.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+target+"/mute", nil)
	req3.SetPathValue("username", target)
	req3 = withClaims(req3, &auth.Claims{Sub: muter, Role: "author"})
	w3 := httptest.NewRecorder()
	handlers.GetMuteStatus(d)(w3, req3)
	var statusResp map[string]bool
	_ = json.NewDecoder(w3.Body).Decode(&statusResp)
	if !statusResp["muted"] {
		t.Error("expected muted=true")
	}

	// List: contains target.
	req4 := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/mutes", nil)
	req4 = withClaims(req4, &auth.Claims{Sub: muter, Role: "author"})
	w4 := httptest.NewRecorder()
	handlers.ListMutedUsers(d)(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w4.Code, w4.Body.String())
	}
	var listResp struct {
		Users []struct {
			Username string `json:"username"`
		} `json:"users"`
	}
	_ = json.NewDecoder(w4.Body).Decode(&listResp)
	found := false
	for _, u := range listResp.Users {
		if u.Username == target {
			found = true
		}
	}
	if !found {
		t.Errorf("expected muted list to contain %q, got %+v", target, listResp.Users)
	}

	// Unmute: succeeds.
	req5 := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+target+"/mute", nil)
	req5.SetPathValue("username", target)
	req5 = withClaims(req5, &auth.Claims{Sub: muter, Role: "author"})
	w5 := httptest.NewRecorder()
	handlers.UnmuteUser(d)(w5, req5)
	if w5.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on unmute, got %d", w5.Code)
	}

	// Status: false again.
	req6 := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+target+"/mute", nil)
	req6.SetPathValue("username", target)
	req6 = withClaims(req6, &auth.Claims{Sub: muter, Role: "author"})
	w6 := httptest.NewRecorder()
	handlers.GetMuteStatus(d)(w6, req6)
	var statusResp2 map[string]bool
	_ = json.NewDecoder(w6.Body).Decode(&statusResp2)
	if statusResp2["muted"] {
		t.Error("expected muted=false after unmute")
	}
}
