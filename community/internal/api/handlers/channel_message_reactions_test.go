package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestToggleMessageReaction_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/messages/1/reactions", nil)
	w := httptest.NewRecorder()

	handlers.ToggleMessageReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestToggleMessageReaction_UserNotFound_Returns401(t *testing.T) {
	// resolveUserID fails against the bad DB pool, so userID is "".
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/messages/1/reactions",
		bytes.NewReader([]byte(`{"emoji":"👍"}`)))
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ToggleMessageReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "user not found" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestRemoveMessageReaction_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/s/channels/c/messages/1/reactions/emoji", nil)
	w := httptest.NewRecorder()

	handlers.RemoveMessageReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestRemoveMessageReaction_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/s/channels/c/messages/1/reactions/emoji", nil)
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req.SetPathValue("id", "1")
	req.SetPathValue("emoji", "👍")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.RemoveMessageReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}

// --- Live-DB tests: full toggle lifecycle + membership enforcement ---

func TestToggleMessageReaction_FullLifecycle_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	authorID, _ := mkUser13(t, pool, "author")
	memberID, memberUsername := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", authorID, memberID)

	var spaceID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO spaces (id, name, slug, description, icon_emoji, is_private, created_by, created_at, updated_at)
		 VALUES (gen_random_uuid(), 'S', $1, '', '', false, $2, now(), now()) RETURNING id`,
		"space-"+uuid.New().String()[:8], authorID,
	).Scan(&spaceID); err != nil {
		t.Fatalf("create space: %v", err)
	}
	defer cleanup13(pool, "spaces", "id", spaceID)

	channelSlug := "chan-" + uuid.New().String()[:8]
	var channelID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO channels (id, space_id, name, slug, description, type, position, created_at)
		 VALUES (gen_random_uuid(), $1, 'general', $2, '', 'text', 0, now()) RETURNING id`,
		spaceID, channelSlug,
	).Scan(&channelID); err != nil {
		t.Fatalf("create channel: %v", err)
	}

	// Member must join the space or membership check (403) will trip first.
	if _, err := pool.Exec(ctx,
		`INSERT INTO space_members (space_id, user_id, role, joined_at) VALUES ($1,$2,'member',now())`,
		spaceID, memberID); err != nil {
		t.Fatalf("join space: %v", err)
	}

	var msgID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO channel_messages (id, channel_id, author_id, content, created_at)
		 VALUES (gen_random_uuid(), $1, $2, 'hello', now()) RETURNING id`,
		channelID, authorID,
	).Scan(&msgID); err != nil {
		t.Fatalf("create message: %v", err)
	}

	// Non-member cannot react (space membership required).
	var spaceSlug string
	_ = pool.QueryRow(ctx, `SELECT slug FROM spaces WHERE id=$1`, spaceID).Scan(&spaceSlug)
	_, nonMemberUsername := mkUser13(t, pool, "author")
	nonMemberReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/spaces/x/channels/y/messages/"+msgID+"/reactions",
		bytes.NewReader([]byte(`{"emoji":"👍"}`)))
	nonMemberReq.SetPathValue("slug", spaceSlug)
	nonMemberReq.SetPathValue("channel", channelSlug)
	nonMemberReq.SetPathValue("id", msgID)
	nonMemberReq = withClaims(nonMemberReq, &auth.Claims{Sub: nonMemberUsername, Role: "author"})
	nonMemberW := httptest.NewRecorder()
	handlers.ToggleMessageReaction(d)(nonMemberW, nonMemberReq)
	if nonMemberW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-member reacting, got %d — body: %s", nonMemberW.Code, nonMemberW.Body.String())
	}

	// Member toggles reaction on: added=true.
	addReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/spaces/x/channels/y/messages/"+msgID+"/reactions",
		bytes.NewReader([]byte(`{"emoji":"🔥"}`)))
	addReq.SetPathValue("slug", spaceSlug)
	addReq.SetPathValue("channel", channelSlug)
	addReq.SetPathValue("id", msgID)
	addReq = withClaims(addReq, &auth.Claims{Sub: memberUsername, Role: "author"})
	addW := httptest.NewRecorder()
	handlers.ToggleMessageReaction(d)(addW, addReq)
	if addW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", addW.Code, addW.Body.String())
	}
	var addResp map[string]any
	_ = json.NewDecoder(addW.Body).Decode(&addResp)
	if added, _ := addResp["added"].(bool); !added {
		t.Errorf("expected added=true on first toggle, got %v", addResp)
	}
	reactions, _ := addResp["reactions"].(map[string]any)
	if reactions["🔥"] != float64(1) {
		t.Errorf("expected count 1 for 🔥, got %v", reactions)
	}

	// Toggle again: removes it (added=false).
	toggleOffReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/spaces/x/channels/y/messages/"+msgID+"/reactions",
		bytes.NewReader([]byte(`{"emoji":"🔥"}`)))
	toggleOffReq.SetPathValue("slug", spaceSlug)
	toggleOffReq.SetPathValue("channel", channelSlug)
	toggleOffReq.SetPathValue("id", msgID)
	toggleOffReq = withClaims(toggleOffReq, &auth.Claims{Sub: memberUsername, Role: "author"})
	toggleOffW := httptest.NewRecorder()
	handlers.ToggleMessageReaction(d)(toggleOffW, toggleOffReq)
	if toggleOffW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", toggleOffW.Code)
	}
	var offResp map[string]any
	_ = json.NewDecoder(toggleOffW.Body).Decode(&offResp)
	if added, _ := offResp["added"].(bool); added {
		t.Errorf("expected added=false on second toggle (removal), got %v", offResp)
	}

	// Add the reaction back directly, then explicitly remove it via the
	// RemoveMessageReaction endpoint (distinct from the toggle endpoint).
	if _, err := pool.Exec(ctx,
		`INSERT INTO channel_message_reactions (message_id, user_id, emoji) VALUES ($1,$2,'🔥') ON CONFLICT DO NOTHING`,
		msgID, memberID); err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	removeReq := httptest.NewRequest(http.MethodDelete,
		"/api/v1/spaces/x/channels/y/messages/"+msgID+"/reactions/%F0%9F%94%A5", nil)
	removeReq.SetPathValue("slug", spaceSlug)
	removeReq.SetPathValue("channel", channelSlug)
	removeReq.SetPathValue("id", msgID)
	removeReq.SetPathValue("emoji", "🔥")
	removeReq = withClaims(removeReq, &auth.Claims{Sub: memberUsername, Role: "author"})
	removeW := httptest.NewRecorder()
	handlers.RemoveMessageReaction(d)(removeW, removeReq)
	if removeW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", removeW.Code, removeW.Body.String())
	}
	var removeResp map[string]any
	_ = json.NewDecoder(removeW.Body).Decode(&removeResp)
	remainReactions, _ := removeResp["reactions"].(map[string]any)
	if _, present := remainReactions["🔥"]; present {
		t.Errorf("expected 🔥 reaction gone after explicit removal, got %v", remainReactions)
	}
}

func TestToggleMessageReaction_UnknownMessage_Returns404(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	var spaceID, spaceSlug string
	spaceSlug = "space-" + uuid.New().String()[:8]
	if err := pool.QueryRow(ctx,
		`INSERT INTO spaces (id, name, slug, description, icon_emoji, is_private, created_by, created_at, updated_at)
		 VALUES (gen_random_uuid(), 'S', $1, '', '', false, $2, now(), now()) RETURNING id`,
		spaceSlug, uid,
	).Scan(&spaceID); err != nil {
		t.Fatalf("create space: %v", err)
	}
	defer cleanup13(pool, "spaces", "id", spaceID)

	channelSlug := "chan-" + uuid.New().String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO channels (id, space_id, name, slug, description, type, position, created_at)
		 VALUES (gen_random_uuid(), $1, 'general', $2, '', 'text', 0, now())`,
		spaceID, channelSlug); err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO space_members (space_id, user_id, role, joined_at) VALUES ($1,$2,'member',now())`,
		spaceID, uid); err != nil {
		t.Fatalf("join space: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/spaces/x/channels/y/messages/"+uuid.New().String()+"/reactions",
		bytes.NewReader([]byte(`{"emoji":"👍"}`)))
	req.SetPathValue("slug", spaceSlug)
	req.SetPathValue("channel", channelSlug)
	req.SetPathValue("id", uuid.New().String())
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ToggleMessageReaction(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown message, got %d — body: %s", w.Code, w.Body.String())
	}
}
