package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestAdminCreateTag_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"Go"}`)))
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTag(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestAdminCreateTag_EmptyName_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"   "}`)))
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTag(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty name, got %d", w.Code)
	}
}

func TestAdminCreateTag_InvalidColor_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"Go","color":"notacolor"}`)))
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTag(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid color, got %d", w.Code)
	}
}

func TestAdminCreateTag_NameProducesEmptySlug_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	// "***" has no alphanumeric characters, so slugFromName produces "".
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"***"}`)))
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTag(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty slug, got %d", w.Code)
	}
}

func TestAdminCreateTag_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTag(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestAdminCreateTag_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"Golang"}`)))
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTag(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestAdminUpdateTag_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/tags/go", bytes.NewReader([]byte(`{"name":"Go"}`)))
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "viewer"})
	w := httptest.NewRecorder()

	handlers.AdminUpdateTag(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestAdminUpdateTag_EmptyName_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/tags/go", bytes.NewReader([]byte(`{"name":""}`)))
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminUpdateTag(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty name, got %d", w.Code)
	}
}

func TestAdminUpdateTag_InvalidColor_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/tags/go", bytes.NewReader([]byte(`{"name":"Go","color":"xyz"}`)))
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminUpdateTag(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid color, got %d", w.Code)
	}
}

func TestAdminUpdateTag_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/tags/go", bytes.NewReader([]byte(`{"name":"Golang"}`)))
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminUpdateTag(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestAdminDeleteTag_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/tags/go", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.AdminDeleteTag(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestAdminDeleteTag_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/tags/go", nil)
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminDeleteTag(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

// --- Live-DB success paths ---

func TestAdminCreateTag_Success_ThenDuplicateReturns409(t *testing.T) {
	d := requireLiveDB(t)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")
	name := "Gru Tag " + adminUsername

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"`+name+`"}`)))
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminCreateTag(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID    string `json:"id"`
		Slug  string `json:"slug"`
		Color string `json:"color"`
	}
	_ = json.NewDecoder(w.Body).Decode(&created)
	if created.Color != "#6366f1" {
		t.Errorf("expected default color #6366f1, got %q", created.Color)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(req.Context(), `DELETE FROM tags WHERE id=$1`, created.ID)
	})

	// Same name again must conflict (duplicate slug/name).
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"`+name+`"}`)))
	req2 = withClaims(req2, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w2 := httptest.NewRecorder()
	handlers.AdminCreateTag(d)(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate tag name, got %d — body: %s", w2.Code, w2.Body.String())
	}
}

func TestAdminUpdateTag_Success_RenamesTag(t *testing.T) {
	d := requireLiveDB(t)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")
	origName := "Gru Orig " + adminUsername

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"`+origName+`"}`)))
	createReq = withClaims(createReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	createW := httptest.NewRecorder()
	handlers.AdminCreateTag(d)(createW, createReq)
	var created struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	_ = json.NewDecoder(createW.Body).Decode(&created)
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(createReq.Context(), `DELETE FROM tags WHERE id=$1`, created.ID)
	})

	newName := "Gru Renamed " + adminUsername
	updateReq := httptest.NewRequest(http.MethodPut, "/api/v1/admin/tags/"+created.Slug, bytes.NewReader([]byte(`{"name":"`+newName+`","color":"#00ff00"}`)))
	updateReq.SetPathValue("slug", created.Slug)
	updateReq = withClaims(updateReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	updateW := httptest.NewRecorder()
	handlers.AdminUpdateTag(d)(updateW, updateReq)

	if updateW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", updateW.Code, updateW.Body.String())
	}
	var updated struct {
		Name  string `json:"name"`
		Color string `json:"color"`
	}
	_ = json.NewDecoder(updateW.Body).Decode(&updated)
	if updated.Name != newName {
		t.Errorf("expected name %q, got %q", newName, updated.Name)
	}
	if updated.Color != "#00ff00" {
		t.Errorf("expected color #00ff00, got %q", updated.Color)
	}
}

func TestAdminUpdateTag_NotFound_Returns404(t *testing.T) {
	d := requireLiveDB(t)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/tags/does-not-exist", bytes.NewReader([]byte(`{"name":"whatever"}`)))
	req.SetPathValue("slug", "does-not-exist")
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminUpdateTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestAdminDeleteTag_Success_RemovesTag(t *testing.T) {
	d := requireLiveDB(t)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")
	name := "Gru Delete Me " + adminUsername

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags", bytes.NewReader([]byte(`{"name":"`+name+`"}`)))
	createReq = withClaims(createReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	createW := httptest.NewRecorder()
	handlers.AdminCreateTag(d)(createW, createReq)
	var created struct {
		Slug string `json:"slug"`
	}
	_ = json.NewDecoder(createW.Body).Decode(&created)

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/tags/"+created.Slug, nil)
	deleteReq.SetPathValue("slug", created.Slug)
	deleteReq = withClaims(deleteReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminDeleteTag(d)(w, deleteReq)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var count int
	if err := d.Pool.QueryRow(deleteReq.Context(), `SELECT count(*) FROM tags WHERE slug=$1`, created.Slug).Scan(&count); err != nil {
		t.Fatalf("count tags: %v", err)
	}
	if count != 0 {
		t.Errorf("expected tag to be deleted, but %d row(s) remain", count)
	}
}

func TestAdminDeleteTag_NotFound_Returns404(t *testing.T) {
	d := requireLiveDB(t)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/tags/does-not-exist", nil)
	req.SetPathValue("slug", "does-not-exist")
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminDeleteTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d — body: %s", w.Code, w.Body.String())
	}
}
