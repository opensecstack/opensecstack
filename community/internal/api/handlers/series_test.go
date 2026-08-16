package handlers_test

// Live-DB test suite for series.go: CreateSeries, GetSeries, AddPostToSeries,
// RemovePostFromSeries, GetPostSeries, ListMySeries, UpdateSeriesPostPosition.
// Uses the shared newLiveDepsSCS/mkUserSCS helpers defined in spaces_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/opensecstack/community/internal/api/handlers"
)

// mkPostSCS inserts a published post directly and returns its ID.
func mkPostSCS(t *testing.T, d handlers.Deps, authorID string) string {
	t.Helper()
	slug := "post-" + uuid.New().String()[:12]
	var id string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO posts (author_id, title, slug, body, state, published_at)
		 VALUES ($1,$2,$3,'body','published', now()) RETURNING id`,
		authorID, slug, slug).Scan(&id)
	if err != nil {
		t.Fatalf("create test post: %v", err)
	}
	return id
}

// ---- CreateSeries ----

func TestCreateSeries_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")

	body, _ := json.Marshal(map[string]string{"title": "My Series " + uuid.New().String()[:8]})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/series", bytes.NewReader(body))
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.CreateSeries(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == "" || resp["slug"] == "" {
		t.Errorf("expected id and slug in response, got %+v", resp)
	}
}

func TestCreateSeries_NoClaims_Returns401(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/series", bytes.NewReader([]byte(`{"title":"x"}`)))
	w := httptest.NewRecorder()
	handlers.CreateSeries(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCreateSeries_InsufficientRole_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "viewer")

	body, _ := json.Marshal(map[string]string{"title": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/series", bytes.NewReader(body))
	req = withClaims(req, claimsSCS(username, "viewer"))
	w := httptest.NewRecorder()
	handlers.CreateSeries(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for viewer role, got %d", w.Code)
	}
}

func TestCreateSeries_EmptyTitle_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/series", bytes.NewReader([]byte(`{"title":"   "}`)))
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.CreateSeries(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateSeries_BadJSON_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/series", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.CreateSeries(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateSeries_UserNotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	body, _ := json.Marshal(map[string]string{"title": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/series", bytes.NewReader(body))
	req = withClaims(req, claimsSCS("ghost-"+uuid.New().String(), "author"))
	w := httptest.NewRecorder()
	handlers.CreateSeries(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when claims sub has no matching user row, got %d", w.Code)
	}
}

// ---- GetSeries ----

func TestGetSeries_NotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/series/nope", nil)
	req.SetPathValue("slug", "nope-"+uuid.New().String())
	w := httptest.NewRecorder()
	handlers.GetSeries(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetSeries_Success_WithPosts(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, userID := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, userID)

	createBody, _ := json.Marshal(map[string]string{"title": "Series With Posts " + uuid.New().String()[:8]})
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/series", bytes.NewReader(createBody))
	createReq = withClaims(createReq, claimsSCS(username, "author"))
	createW := httptest.NewRecorder()
	handlers.CreateSeries(d)(createW, createReq)
	var createResp map[string]string
	_ = json.NewDecoder(createW.Body).Decode(&createResp)
	addBody, _ := json.Marshal(map[string]any{"post_id": postID, "position": 0})
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/series/"+createResp["id"]+"/posts", bytes.NewReader(addBody))
	addReq.SetPathValue("id", createResp["id"])
	addReq = withClaims(addReq, claimsSCS(username, "author"))
	addW := httptest.NewRecorder()
	handlers.AddPostToSeries(d)(addW, addReq)
	if addW.Code != http.StatusNoContent {
		t.Fatalf("setup: expected 204 adding post to series, got %d: %s", addW.Code, addW.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/series/"+createResp["slug"], nil)
	getReq.SetPathValue("slug", createResp["slug"])
	getW := httptest.NewRecorder()
	handlers.GetSeries(d)(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getW.Code, getW.Body.String())
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	_ = json.NewDecoder(getW.Body).Decode(&resp)
	if len(resp.Posts) != 1 {
		t.Errorf("expected 1 post in series, got %d", len(resp.Posts))
	}
}

// ---- AddPostToSeries / RemovePostFromSeries ----

// IDOR check: a user who does not own the series must not be able to add
// posts to it.
func TestAddPostToSeries_NotOwner_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	attacker, attackerID := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, attackerID)
	_ = owner

	var seriesID string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3) RETURNING id`,
		ownerID, "victim-series", "victim-series-"+uuid.New().String()[:8]).Scan(&seriesID)
	if err != nil {
		t.Fatalf("setup series: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"post_id": postID, "position": 0})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/series/"+seriesID+"/posts", bytes.NewReader(body))
	req.SetPathValue("id", seriesID)
	req = withClaims(req, claimsSCS(attacker, "author"))
	w := httptest.NewRecorder()
	handlers.AddPostToSeries(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for non-owner adding post to series, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAddPostToSeries_Owner_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, ownerID)

	var seriesID string
	_ = d.Pool.QueryRow(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3) RETURNING id`,
		ownerID, "owner-series", "owner-series-"+uuid.New().String()[:8]).Scan(&seriesID)

	body, _ := json.Marshal(map[string]any{"post_id": postID, "position": 1})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/series/"+seriesID+"/posts", bytes.NewReader(body))
	req.SetPathValue("id", seriesID)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.AddPostToSeries(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAddPostToSeries_SeriesNotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, userID := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, userID)

	body, _ := json.Marshal(map[string]any{"post_id": postID, "position": 0})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/series/"+uuid.New().String()+"/posts", bytes.NewReader(body))
	req.SetPathValue("id", uuid.New().String())
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.AddPostToSeries(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAddPostToSeries_NoClaims_Returns401(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/series/x/posts", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	handlers.AddPostToSeries(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// IDOR check: a user who does not own the series must not be able to remove
// posts from it.
func TestRemovePostFromSeries_NotOwner_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, ownerID := mkUserSCS(t, d, "author")
	attacker, _ := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, ownerID)

	var seriesID string
	_ = d.Pool.QueryRow(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3) RETURNING id`,
		ownerID, "s2", "s2-"+uuid.New().String()[:8]).Scan(&seriesID)
	_, _ = d.Pool.Exec(context.Background(),
		`INSERT INTO series_posts (series_id, post_id, position) VALUES ($1,$2,0)`, seriesID, postID)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/series/"+seriesID+"/posts/"+postID, nil)
	req.SetPathValue("id", seriesID)
	req.SetPathValue("post_id", postID)
	req = withClaims(req, claimsSCS(attacker, "author"))
	w := httptest.NewRecorder()
	handlers.RemovePostFromSeries(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for non-owner removing post from series, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRemovePostFromSeries_Owner_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, ownerID)

	var seriesID string
	_ = d.Pool.QueryRow(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3) RETURNING id`,
		ownerID, "s3", "s3-"+uuid.New().String()[:8]).Scan(&seriesID)
	_, _ = d.Pool.Exec(context.Background(),
		`INSERT INTO series_posts (series_id, post_id, position) VALUES ($1,$2,0)`, seriesID, postID)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/series/"+seriesID+"/posts/"+postID, nil)
	req.SetPathValue("id", seriesID)
	req.SetPathValue("post_id", postID)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.RemovePostFromSeries(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRemovePostFromSeries_SeriesNotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/series/"+uuid.New().String()+"/posts/"+uuid.New().String(), nil)
	req.SetPathValue("id", uuid.New().String())
	req.SetPathValue("post_id", uuid.New().String())
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.RemovePostFromSeries(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ---- GetPostSeries ----

func TestGetPostSeries_NotInSeries_ReturnsNullSeries200(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, userID := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, userID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/series", nil)
	req.SetPathValue("id", postID)
	w := httptest.NewRecorder()
	handlers.GetPostSeries(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Series any `json:"series"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Series != nil {
		t.Errorf("expected null series for post not in any series, got %v", resp.Series)
	}
}

func TestGetPostSeries_InSeries_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	_, userID := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, userID)

	var seriesID string
	_ = d.Pool.QueryRow(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3) RETURNING id`,
		userID, "s4", "s4-"+uuid.New().String()[:8]).Scan(&seriesID)
	_, _ = d.Pool.Exec(context.Background(),
		`INSERT INTO series_posts (series_id, post_id, position) VALUES ($1,$2,2)`, seriesID, postID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/series", nil)
	req.SetPathValue("id", postID)
	w := httptest.NewRecorder()
	handlers.GetPostSeries(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Series          map[string]any `json:"series"`
		CurrentPosition int            `json:"current_position"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Series == nil || resp.Series["id"] != seriesID {
		t.Errorf("expected series info to be returned, got %+v", resp.Series)
	}
	if resp.CurrentPosition != 2 {
		t.Errorf("expected current_position 2, got %d", resp.CurrentPosition)
	}
}

// ---- ListMySeries ----

func TestListMySeries_NoClaims_Returns401(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/series", nil)
	w := httptest.NewRecorder()
	handlers.ListMySeries(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestListMySeries_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, ownerID := mkUserSCS(t, d, "author")
	_, _ = d.Pool.Exec(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3)`,
		ownerID, "mine", "mine-"+uuid.New().String()[:8])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/series", nil)
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.ListMySeries(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var items []map[string]any
	_ = json.NewDecoder(w.Body).Decode(&items)
	if len(items) != 1 {
		t.Errorf("expected 1 series owned by user, got %d", len(items))
	}
}

// ---- UpdateSeriesPostPosition ----

func TestUpdateSeriesPostPosition_NoClaims_Returns401(t *testing.T) {
	d := newLiveDepsSCS(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/series/x/posts/y/position", bytes.NewReader([]byte(`{"position":1}`)))
	w := httptest.NewRecorder()
	handlers.UpdateSeriesPostPosition(d)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestUpdateSeriesPostPosition_NotFound_Returns404(t *testing.T) {
	d := newLiveDepsSCS(t)
	username, _ := mkUserSCS(t, d, "author")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/series/"+uuid.New().String()+"/posts/"+uuid.New().String()+"/position",
		bytes.NewReader([]byte(`{"position":1}`)))
	req.SetPathValue("id", uuid.New().String())
	req.SetPathValue("post_id", uuid.New().String())
	req = withClaims(req, claimsSCS(username, "author"))
	w := httptest.NewRecorder()
	handlers.UpdateSeriesPostPosition(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// IDOR check: a non-owner must not be able to reorder posts in someone
// else's series.
func TestUpdateSeriesPostPosition_NotOwner_Returns403(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	attacker, _ := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, ownerID)
	_ = owner

	var seriesID string
	_ = d.Pool.QueryRow(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3) RETURNING id`,
		ownerID, "s5", "s5-"+uuid.New().String()[:8]).Scan(&seriesID)
	_, _ = d.Pool.Exec(context.Background(),
		`INSERT INTO series_posts (series_id, post_id, position) VALUES ($1,$2,0)`, seriesID, postID)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/series/"+seriesID+"/posts/"+postID+"/position",
		bytes.NewReader([]byte(`{"position":5}`)))
	req.SetPathValue("id", seriesID)
	req.SetPathValue("post_id", postID)
	req = withClaims(req, claimsSCS(attacker, "author"))
	w := httptest.NewRecorder()
	handlers.UpdateSeriesPostPosition(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403 for non-owner reordering series posts, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSeriesPostPosition_Owner_Success(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")
	postID := mkPostSCS(t, d, ownerID)

	var seriesID string
	_ = d.Pool.QueryRow(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3) RETURNING id`,
		ownerID, "s6", "s6-"+uuid.New().String()[:8]).Scan(&seriesID)
	_, _ = d.Pool.Exec(context.Background(),
		`INSERT INTO series_posts (series_id, post_id, position) VALUES ($1,$2,0)`, seriesID, postID)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/series/"+seriesID+"/posts/"+postID+"/position",
		bytes.NewReader([]byte(`{"position":9}`)))
	req.SetPathValue("id", seriesID)
	req.SetPathValue("post_id", postID)
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.UpdateSeriesPostPosition(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSeriesPostPosition_BadJSON_Returns400(t *testing.T) {
	d := newLiveDepsSCS(t)
	owner, ownerID := mkUserSCS(t, d, "author")

	var seriesID string
	_ = d.Pool.QueryRow(context.Background(),
		`INSERT INTO series (author_id, title, slug) VALUES ($1,$2,$3) RETURNING id`,
		ownerID, "s7", "s7-"+uuid.New().String()[:8]).Scan(&seriesID)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/series/"+seriesID+"/posts/x/position", bytes.NewReader([]byte(`{bad`)))
	req.SetPathValue("id", seriesID)
	req.SetPathValue("post_id", "x")
	req = withClaims(req, claimsSCS(owner, "author"))
	w := httptest.NewRecorder()
	handlers.UpdateSeriesPostPosition(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---- Bad-DB error branches ----

func TestGetSeries_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/series/x", nil)
	req.SetPathValue("slug", "x")
	w := httptest.NewRecorder()
	handlers.GetSeries(d)(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when DB unreachable, got %d", w.Code)
	}
}
