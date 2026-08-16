package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestListChannelMessages_ChannelNotFound_Returns404(t *testing.T) {
	// No claims required — public endpoint. resolveChannel fails against the
	// bad DB pool, so the channel lookup returns not-found.
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/s/channels/c/messages", nil)
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	w := httptest.NewRecorder()

	handlers.ListChannelMessages(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "channel not found" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestCreateChannelMessage_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/messages", nil)
	w := httptest.NewRecorder()

	handlers.CreateChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestCreateChannelMessage_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/messages",
		bytes.NewReader([]byte(`{"content":"hello"}`)))
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}

func TestEditChannelMessage_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/s/channels/c/messages/1", nil)
	w := httptest.NewRecorder()

	handlers.EditChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestEditChannelMessage_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/s/channels/c/messages/1",
		bytes.NewReader([]byte(`{"content":"edited"}`)))
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.EditChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}

func TestDeleteChannelMessage_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/s/channels/c/messages/1", nil)
	w := httptest.NewRecorder()

	handlers.DeleteChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestDeleteChannelMessage_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/s/channels/c/messages/1", nil)
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeleteChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}

// ---- Live-DB coverage: success paths and authz/IDOR branches ----
//
// The tests below exercise ListChannelMessages/CreateChannelMessage/
// EditChannelMessage/DeleteChannelMessage against a real Postgres instance
// (see newLiveDepsSCS in spaces_test.go), including the IDOR-sensitive
// branches: can a non-member read a private space's channel, and can a
// non-author/non-moderator edit or delete someone else's message.

// IDOR check: resolveChannel treats a private-space non-member the same as
// a nonexistent channel (404), so this also verifies that private content
// isn't leaked in the response.
func TestListChannelMessages_PrivateSpace_NonMember_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, true)
	chID, chSlug := mkChannelSCS(t, d, spaceID, "text")
	mkMessageSCS(t, d, chID, ownerID, "secret message")
	outsider, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages", nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req = withClaims(req, claimsSCS(outsider, "author"))
	w := httptest.NewRecorder()
	handlers.ListChannelMessages(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("IDOR: expected 404 for non-member reading private channel, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListChannelMessages_Success_ReturnsMessagesDescending(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	chID, chSlug := mkChannelSCS(t, d, spaceID, "text")
	mkMessageSCS(t, d, chID, ownerID, "first")
	mkMessageSCS(t, d, chID, ownerID, "second")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages", nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.ListChannelMessages(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Messages []map[string]any `json:"messages"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(resp.Messages))
	}
	if resp.Messages[0]["content"] != "second" {
		t.Errorf("expected newest message first, got %v", resp.Messages[0]["content"])
	}
}

func TestCreateChannelMessage_NotSpaceMember_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")
	outsider, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages",
		bytes.NewReader([]byte(`{"content":"hi"}`)))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req = withClaims(req, claimsSCS(outsider, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannelMessage(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-member posting message, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateChannelMessage_EmptyContent_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages",
		bytes.NewReader([]byte(`{"content":"   "}`)))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannelMessage(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateChannelMessage_ChannelNotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/nope/channels/nope/messages",
		bytes.NewReader([]byte(`{"content":"hi"}`)))
	req.SetPathValue("slug", "nope")
	req.SetPathValue("channel", "nope")
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannelMessage(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCreateChannelMessage_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages",
		bytes.NewReader([]byte(`{"content":"hello world"}`)))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannelMessage(d)(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var msg map[string]any
	_ = json.NewDecoder(w.Body).Decode(&msg)
	if msg["content"] != "hello world" {
		t.Errorf("unexpected content: %v", msg["content"])
	}
}

// IDOR check: a member who did not author the message, and holds no
// moderator/owner role, must not be able to edit someone else's message.
func TestEditChannelMessage_NotAuthorNotModerator_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	chID, chSlug := mkChannelSCS(t, d, spaceID, "text")
	msgID := mkMessageSCS(t, d, chID, ownerID, "original")
	other, otherID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, otherID, "member")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages/"+msgID,
		bytes.NewReader([]byte(`{"content":"hijacked"}`)))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req.SetPathValue("id", msgID)
	req = withClaims(req, claimsSCS(other, "author"))
	w := httptest.NewRecorder()
	handlers.EditChannelMessage(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for non-author non-mod edit, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEditChannelMessage_Author_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	chID, chSlug := mkChannelSCS(t, d, spaceID, "text")
	msgID := mkMessageSCS(t, d, chID, ownerID, "original")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages/"+msgID,
		bytes.NewReader([]byte(`{"content":"edited by author"}`)))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req.SetPathValue("id", msgID)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.EditChannelMessage(d)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var msg map[string]any
	_ = json.NewDecoder(w.Body).Decode(&msg)
	if msg["content"] != "edited by author" {
		t.Errorf("unexpected content: %v", msg["content"])
	}
}

func TestEditChannelMessage_ModeratorCanEditOthersMessage(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	chID, chSlug := mkChannelSCS(t, d, spaceID, "text")
	author, authorID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, authorID, "member")
	msgID := mkMessageSCS(t, d, chID, authorID, "original")
	mod, modID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, modID, "moderator")
	_ = author

	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages/"+msgID,
		bytes.NewReader([]byte(`{"content":"moderated"}`)))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req.SetPathValue("id", msgID)
	req = withClaims(req, claimsSCS(mod, "author"))
	w := httptest.NewRecorder()
	handlers.EditChannelMessage(d)(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected moderator to be able to edit others' messages, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEditChannelMessage_MessageNotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages/"+uuid.New().String(),
		bytes.NewReader([]byte(`{"content":"x"}`)))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req.SetPathValue("id", uuid.New().String())
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.EditChannelMessage(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestEditChannelMessage_EmptyContent_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	chID, chSlug := mkChannelSCS(t, d, spaceID, "text")
	msgID := mkMessageSCS(t, d, chID, ownerID, "original")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages/"+msgID,
		bytes.NewReader([]byte(`{"content":"  "}`)))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req.SetPathValue("id", msgID)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.EditChannelMessage(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// IDOR check: a plain member must not be able to delete someone else's message.
func TestDeleteChannelMessage_NotAuthorNotModerator_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	chID, chSlug := mkChannelSCS(t, d, spaceID, "text")
	msgID := mkMessageSCS(t, d, chID, ownerID, "original")
	other, otherID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, otherID, "member")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages/"+msgID, nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req.SetPathValue("id", msgID)
	req = withClaims(req, claimsSCS(other, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteChannelMessage(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for non-author non-mod delete, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteChannelMessage_Author_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	chID, chSlug := mkChannelSCS(t, d, spaceID, "text")
	msgID := mkMessageSCS(t, d, chID, ownerID, "to be deleted")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages/"+msgID, nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req.SetPathValue("id", msgID)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteChannelMessage(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteChannelMessage_MessageNotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/messages/"+uuid.New().String(), nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel", chSlug)
	req.SetPathValue("id", uuid.New().String())
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteChannelMessage(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
