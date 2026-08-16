package handlers_test

// Live-DB test suite for spaces.go. These tests exercise the full HTTP
// handler stack (ListSpaces, CreateSpace, GetSpace, UpdateSpace, DeleteSpace,
// JoinSpace, LeaveSpace, CreateChannel, DeleteChannel, GetChannelPosts,
// CreateChannelPost, CreateSpaceInvite, JoinSpaceByInvite) against a real
// Postgres instance so that success paths and authz/IDOR branches (private
// space access, owner/moderator-only actions) are actually verified, not
// just the DB-unreachable branches.
//
// newLiveDepsSCS (Spaces/ChannelMessages/Series) is shared by
// channel_messages_test.go and series_test.go since they live in the same
// package and cover sibling files owned by this same work item.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
)

// migrateOnceSCS ensures db.Migrate is only replayed once per test-binary
// run. db.Migrate is not safe to call repeatedly against a database that
// already has live data: one of the historical migrations
// (ddlWelcomeNotification in internal/db/migrations_welcome_notif.go)
// unconditionally re-adds a restrictive CHECK constraint on
// notifications.type that a later migration (migrations_notifications_v2.go)
// intentionally drops again. Once any row with a newer notification type
// (e.g. "space_joined", written by JoinSpace) exists — which it will, the
// moment any space test runs — replaying the full migration list from
// scratch fails on that ADD CONSTRAINT step. This is a pre-existing
// ordering bug in internal/db, out of scope for this change (owned by other
// parallel work), so we defensively migrate only once and tolerate a
// failure there: in the shared live test DB the schema already exists from
// an earlier successful run, so tests can proceed regardless.
var (
	migrateOnceSCS sync.Once
	migrateErrSCS  error
)

func liveTestDBURLSCS() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://apiguard@localhost:5434/community_test?sslmode=disable"
}

// newLiveDepsSCS returns Deps backed by a real, migrated Postgres database.
// Tests that need it skip (rather than fail) when no live DB is reachable,
// so this file degrades gracefully in environments without Postgres.
func newLiveDepsSCS(t *testing.T) handlers.Deps {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), liveTestDBURLSCS())
	if err != nil {
		t.Skip("cannot create pool for live db:", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		t.Skip("live test db not reachable:", err)
	}
	migrateOnceSCS.Do(func() {
		migrateErrSCS = db.Migrate(pool)
	})
	if migrateErrSCS != nil {
		t.Logf("warning: db.Migrate returned an error (tolerated — schema is expected to already exist in the shared live test db): %v", migrateErrSCS)
	}
	t.Cleanup(pool.Close)
	return handlers.Deps{Pool: pool, Cfg: &config.Config{}}
}

// mkUserSCS inserts a user directly and returns (username, userID).
func mkUserSCS(t *testing.T, d handlers.Deps, role string) (string, string) {
	t.Helper()
	username := "u_" + uuid.New().String()[:12]
	var id string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO users (username, display_name, role) VALUES ($1,$1,$2) RETURNING id`,
		username, role).Scan(&id)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return username, id
}

// mkSpaceSCS inserts a space with the given owner and returns (spaceID, slug).
func mkSpaceSCS(t *testing.T, d handlers.Deps, ownerID string, private bool) (string, string) {
	t.Helper()
	slug := "space-" + uuid.New().String()[:12]
	var id string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO spaces (name, slug, is_private, created_by) VALUES ($1,$2,$3,$4) RETURNING id`,
		slug, slug, private, ownerID).Scan(&id)
	if err != nil {
		t.Fatalf("create test space: %v", err)
	}
	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO space_members (space_id, user_id, role) VALUES ($1,$2,'owner')`, id, ownerID); err != nil {
		t.Fatalf("add owner membership: %v", err)
	}
	return id, slug
}

func addMemberSCS(t *testing.T, d handlers.Deps, spaceID, userID, role string) {
	t.Helper()
	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO space_members (space_id, user_id, role) VALUES ($1,$2,$3)`, spaceID, userID, role); err != nil {
		t.Fatalf("add member: %v", err)
	}
}

func mkChannelSCS(t *testing.T, d handlers.Deps, spaceID, chType string) (string, string) {
	t.Helper()
	slug := "chan-" + uuid.New().String()[:12]
	var id string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO channels (space_id, name, slug, type) VALUES ($1,$2,$2,$3) RETURNING id`,
		spaceID, slug, chType).Scan(&id)
	if err != nil {
		t.Fatalf("create test channel: %v", err)
	}
	return id, slug
}

// mkMessageSCS inserts a channel message directly and returns its ID.
func mkMessageSCS(t *testing.T, d handlers.Deps, channelID, authorID, content string) string {
	t.Helper()
	var id string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO channel_messages (channel_id, author_id, content) VALUES ($1,$2,$3) RETURNING id::text`,
		channelID, authorID, content).Scan(&id)
	if err != nil {
		t.Fatalf("create test message: %v", err)
	}
	return id
}

func claimsSCS(username, role string) *auth.Claims {
	return &auth.Claims{Sub: username, Role: role}
}

// ---- ListSpaces ----

func TestListSpaces_ExcludesPrivateSpacesForOutsiders(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	_, pubSlug := mkSpaceSCS(t, d, ownerID, false)
	_, _ = mkSpaceSCS(t, d, ownerID, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces?limit=200", nil)
	w := httptest.NewRecorder()
	handlers.ListSpaces(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Spaces []map[string]any `json:"spaces"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, s := range resp.Spaces {
		if s["is_private"] == true {
			t.Errorf("private space leaked to anonymous listing: %v", s)
		}
	}
	found := false
	for _, s := range resp.Spaces {
		if s["slug"] == pubSlug {
			found = true
		}
	}
	if !found {
		t.Error("expected public space to be present in listing")
	}
}

func TestListSpaces_MemberSeesOwnPrivateSpace(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, ownerID := mkUserSCS(t, d, "author")
	_, privSlug := mkSpaceSCS(t, d, ownerID, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces?limit=200", nil)
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.ListSpaces(d)(w, req)

	var resp struct {
		Spaces []map[string]any `json:"spaces"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, s := range resp.Spaces {
		if s["slug"] == privSlug {
			found = true
		}
	}
	if !found {
		t.Error("expected member to see their own private space in listing")
	}
}

// ---- CreateSpace ----

func TestCreateSpace_Success_CreatesOwnerAndGeneralChannel(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")

	body, _ := json.Marshal(map[string]string{"name": "My Cool Space " + uuid.New().String()[:8]})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces", bytes.NewReader(body))
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.CreateSpace(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var space map[string]any
	_ = json.NewDecoder(w.Body).Decode(&space)
	if space["viewer_role"] != "owner" {
		t.Errorf("expected viewer_role owner, got %v", space["viewer_role"])
	}
	if space["is_member"] != true {
		t.Error("expected is_member true for creator")
	}

	// Fetch the space to confirm the auto-created #general channel exists.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+space["slug"].(string), nil)
	getReq.SetPathValue("slug", space["slug"].(string))
	getReq = withClaims(getReq, claimsSCS(username, "author"))
	getW := httptest.NewRecorder()
	handlers.GetSpace(d)(getW, getReq)

	var getResp struct {
		Channels []map[string]any `json:"channels"`
	}
	_ = json.NewDecoder(getW.Body).Decode(&getResp)
	if len(getResp.Channels) != 1 || getResp.Channels[0]["slug"] != "general" {
		t.Errorf("expected exactly one auto-created 'general' channel, got %+v", getResp.Channels)
	}
}

func TestCreateSpace_NoClaims_Returns401(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces", bytes.NewReader([]byte(`{"name":"x"}`)))
	w := httptest.NewRecorder()
	handlers.CreateSpace(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCreateSpace_EmptyName_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces", bytes.NewReader([]byte(`{"name":"   "}`)))
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.CreateSpace(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateSpace_BadJSON_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.CreateSpace(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateSpace_DuplicateSlug_Returns409(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	name := "dup-space-" + uuid.New().String()[:8]
	body, _ := json.Marshal(map[string]string{"name": name})

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/spaces", bytes.NewReader(body))
	req1 = withClaims(req1, claimsSCS(username, "author"))
	w1 := httptest.NewRecorder()
	handlers.CreateSpace(d)(w1, req1)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first create expected 201, got %d: %s", w1.Code, w1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/spaces", bytes.NewReader(body))
	req2 = withClaims(req2, claimsSCS(username, "author"))
	w2 := httptest.NewRecorder()
	handlers.CreateSpace(d)(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 on duplicate slug, got %d", w2.Code)
	}
}

func TestCreateSpace_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces", bytes.NewReader([]byte(`{"name":"x"}`)))
	req = withClaims(req, claimsSCS("ghost", "author"))
	w := httptest.NewRecorder()
	handlers.CreateSpace(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}

// ---- GetSpace ----

func TestGetSpace_NotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/nope", nil)
	req.SetPathValue("slug", "nope-"+uuid.New().String())
	w := httptest.NewRecorder()
	handlers.GetSpace(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// IDOR check: an outsider (no membership) must not be able to view a
// private space's details, even though they know its slug.
func TestGetSpace_PrivateSpace_NonMember_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, true)
	outsider, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+slug, nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(outsider, "author"))
	w := httptest.NewRecorder()
	handlers.GetSpace(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for non-member accessing private space, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetSpace_PrivateSpace_Member_Returns200(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, true)
	member, memberID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, memberID, "member")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+slug, nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(member, "author"))
	w := httptest.NewRecorder()
	handlers.GetSpace(d)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for member of private space, got %d: %s", w.Code, w.Body.String())
	}
}

// ---- UpdateSpace ----

func TestUpdateSpace_NoClaims_Returns401(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/x", bytes.NewReader([]byte(`{"name":"y"}`)))
	w := httptest.NewRecorder()
	handlers.UpdateSpace(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestUpdateSpace_NotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/nope", bytes.NewReader([]byte(`{"name":"y"}`)))
	req.SetPathValue("slug", "nope-"+uuid.New().String())
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.UpdateSpace(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// IDOR check: a regular member must not be able to update space settings
// belonging to someone else's space.
func TestUpdateSpace_NonOwnerMember_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	member, memberID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, memberID, "member")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/"+slug, bytes.NewReader([]byte(`{"name":"hijacked"}`)))
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(member, "author"))
	w := httptest.NewRecorder()
	handlers.UpdateSpace(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for non-owner update, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSpace_Owner_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, false)

	body, _ := json.Marshal(map[string]string{"name": "Renamed", "description": "new desc"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/"+slug, bytes.NewReader(body))
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.UpdateSpace(d)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSpace_EmptyName_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, false)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/"+slug, bytes.NewReader([]byte(`{"name":"  "}`)))
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.UpdateSpace(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---- DeleteSpace ----

func TestDeleteSpace_NonOwner_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	member, memberID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, memberID, "moderator")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/"+slug, nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(member, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteSpace(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for moderator deleting space (owner only), got %d", w.Code)
	}
}

func TestDeleteSpace_Owner_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, false)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/"+slug, nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteSpace(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+slug, nil)
	getReq.SetPathValue("slug", slug)
	getW := httptest.NewRecorder()
	handlers.GetSpace(d)(getW, getReq)
	if getW.Code != http.StatusNotFound {
		t.Errorf("expected space to be gone after delete, got %d", getW.Code)
	}
}

func TestDeleteSpace_NotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/nope", nil)
	req.SetPathValue("slug", "nope-"+uuid.New().String())
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteSpace(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ---- JoinSpace / LeaveSpace ----

func TestJoinSpace_PublicSpace_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, false)
	joiner, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/join", nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(joiner, "author"))
	w := httptest.NewRecorder()
	handlers.JoinSpace(d)(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestJoinSpace_PrivateSpace_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, true)
	joiner, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/join", nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(joiner, "author"))
	w := httptest.NewRecorder()
	handlers.JoinSpace(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 joining private space directly, got %d", w.Code)
	}
}

func TestJoinSpace_NotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/nope/join", nil)
	req.SetPathValue("slug", "nope-"+uuid.New().String())
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.JoinSpace(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestJoinSpace_NoClaims_Returns401(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/x/join", nil)
	w := httptest.NewRecorder()
	handlers.JoinSpace(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLeaveSpace_Owner_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/leave", nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.LeaveSpace(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when owner tries to leave, got %d", w.Code)
	}
}

func TestLeaveSpace_Member_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	member, memberID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, memberID, "member")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/leave", nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(member, "author"))
	w := httptest.NewRecorder()
	handlers.LeaveSpace(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

// ---- CreateChannel / DeleteChannel ----

func TestCreateChannel_Owner_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, false)

	body, _ := json.Marshal(map[string]string{"name": "random-chat"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels", bytes.NewReader(body))
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannel(d)(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

// IDOR check: a plain member (not owner/moderator) must not be able to
// create channels in someone else's space.
func TestCreateChannel_PlainMember_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	member, memberID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, memberID, "member")

	body, _ := json.Marshal(map[string]string{"name": "hijack-chan"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels", bytes.NewReader(body))
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(member, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannel(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for plain member creating channel, got %d", w.Code)
	}
}

func TestCreateChannel_SpaceNotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/nope/channels", bytes.NewReader([]byte(`{"name":"x"}`)))
	req.SetPathValue("slug", "nope-"+uuid.New().String())
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannel(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDeleteChannel_NonModerator_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")
	member, memberID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, memberID, "member")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/"+slug+"/channels/"+chSlug, nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", chSlug)
	req = withClaims(req, claimsSCS(member, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteChannel(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for plain member deleting channel, got %d", w.Code)
	}
}

func TestDeleteChannel_Owner_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/"+slug+"/channels/"+chSlug, nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", chSlug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteChannel(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteChannel_NotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, false)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/"+slug+"/channels/does-not-exist", nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", "does-not-exist")
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.DeleteChannel(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ---- GetChannelPosts / CreateChannelPost ----

// IDOR check: an outsider must not be able to list posts from a private
// space's channel.
func TestGetChannelPosts_PrivateSpace_NonMember_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, true)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")
	outsider, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/posts", nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", chSlug)
	req = withClaims(req, claimsSCS(outsider, "author"))
	w := httptest.NewRecorder()
	handlers.GetChannelPosts(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetChannelPosts_PublicSpace_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/posts", nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", chSlug)
	w := httptest.NewRecorder()
	handlers.GetChannelPosts(d)(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetChannelPosts_ChannelNotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/"+slug+"/channels/nope/posts", nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", "nope")
	w := httptest.NewRecorder()
	handlers.GetChannelPosts(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCreateChannelPost_NotMember_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")
	outsider, _ := mkUserSCS(t, d, "author")

	body, _ := json.Marshal(map[string]string{"title": "hello"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/posts", bytes.NewReader(body))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", chSlug)
	req = withClaims(req, claimsSCS(outsider, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannelPost(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-member posting, got %d: %s", w.Code, w.Body.String())
	}
}

// A plain member must not be able to post into an announcement-only channel.
func TestCreateChannelPost_AnnouncementChannel_PlainMemberForbidden(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "announcement")
	member, memberID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, memberID, "member")

	body, _ := json.Marshal(map[string]string{"title": "hello"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/posts", bytes.NewReader(body))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", chSlug)
	req = withClaims(req, claimsSCS(member, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannelPost(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for member posting in announcement channel, got %d", w.Code)
	}
}

func TestCreateChannelPost_Success_WithTags(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")

	body, _ := json.Marshal(map[string]any{
		"title": "Great post " + uuid.New().String()[:8],
		"body":  "body text",
		"tags":  []string{"golang", "testing"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/posts", bytes.NewReader(body))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", chSlug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannelPost(d)(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateChannelPost_EmptyTitle_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, false)
	_, chSlug := mkChannelSCS(t, d, spaceID, "text")

	body, _ := json.Marshal(map[string]string{"title": "  "})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/channels/"+chSlug+"/posts", bytes.NewReader(body))
	req.SetPathValue("slug", slug)
	req.SetPathValue("channel_slug", chSlug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.CreateChannelPost(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---- CreateSpaceInvite / JoinSpaceByInvite ----

func TestCreateSpaceInvite_NonModerator_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	spaceID, slug := mkSpaceSCS(t, d, ownerID, true)
	member, memberID := mkUserSCS(t, d, "author")
	addMemberSCS(t, d, spaceID, memberID, "member")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/invites", nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(member, "author"))
	w := httptest.NewRecorder()
	handlers.CreateSpaceInvite(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for plain member creating invite, got %d", w.Code)
	}
}

func TestCreateSpaceInvite_Owner_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/invites", nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.CreateSpaceInvite(d)(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestJoinSpaceByInvite_InvalidCode_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites/does-not-exist/join", nil)
	req.SetPathValue("code", "does-not-exist")
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.JoinSpaceByInvite(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestJoinSpaceByInvite_ValidCode_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	_, slug := mkSpaceSCS(t, d, ownerID, true)

	inviteReq := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/"+slug+"/invites", nil)
	inviteReq.SetPathValue("slug", slug)
	inviteReq = withClaims(inviteReq, claimsSCS(owner, "author"))
	inviteW := httptest.NewRecorder()
	handlers.CreateSpaceInvite(d)(inviteW, inviteReq)
	var inviteResp struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(inviteW.Body).Decode(&inviteResp)
	joiner, _ := mkUserSCS(t, d, "author")
	joinReq := httptest.NewRequest(http.MethodPost, "/api/v1/invites/"+inviteResp.Code+"/join", nil)
	joinReq.SetPathValue("code", inviteResp.Code)
	joinReq = withClaims(joinReq, claimsSCS(joiner, "author"))
	joinW := httptest.NewRecorder()
	handlers.JoinSpaceByInvite(d)(joinW, joinReq)

	if joinW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", joinW.Code, joinW.Body.String())
	}
	var joinResp map[string]string
	_ = json.NewDecoder(joinW.Body).Decode(&joinResp)
	if joinResp["space_slug"] != slug {
		t.Errorf("expected space_slug %q, got %q", slug, joinResp["space_slug"])
	}
}

func TestJoinSpaceByInvite_NoClaims_Returns401(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites/x/join", nil)
	w := httptest.NewRecorder()
	handlers.JoinSpaceByInvite(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
