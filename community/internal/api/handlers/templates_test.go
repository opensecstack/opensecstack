package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestListTemplates_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
	w := httptest.NewRecorder()

	handlers.ListTemplates(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestListTemplates_UnknownUser_ReturnsEmptyList(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
	req = withClaims(req, &auth.Claims{Sub: "nobody", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListTemplates(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with empty list when user unresolvable, got %d — body: %s", w.Code, w.Body.String())
	}
	var got []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %v", got)
	}
}

func TestCreateTemplate_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", bytes.NewReader([]byte(`{"name":"x"}`)))
	w := httptest.NewRecorder()

	handlers.CreateTemplate(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestCreateTemplate_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateTemplate(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestCreateTemplate_EmptyName_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", bytes.NewReader([]byte(`{"name":""}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateTemplate(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty name, got %d", w.Code)
	}
}

func TestCreateTemplate_UnknownUser_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", bytes.NewReader([]byte(`{"name":"tpl"}`)))
	req = withClaims(req, &auth.Claims{Sub: "nobody", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateTemplate(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when user not found, got %d", w.Code)
	}
}

func TestDeleteTemplate_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/1", nil)
	w := httptest.NewRecorder()

	handlers.DeleteTemplate(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestDeleteTemplate_InvalidID_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/notanumber", nil)
	req.SetPathValue("id", "notanumber")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeleteTemplate(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid id, got %d", w.Code)
	}
}

func TestDeleteTemplate_UnknownUser_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/1", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "nobody", Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeleteTemplate(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when user not found, got %d", w.Code)
	}
}

// --- Live-DB success-path + cross-user isolation tests ---

func TestTemplates_CreateListDelete_FullLifecycle_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	// Create.
	body, _ := json.Marshal(map[string]any{
		"name":  "my-template",
		"title": "Title",
		"body":  "Body content",
		"tags":  []string{"go", "testing"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.CreateTemplate(d)(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	tplID := created["id"]
	if tplID == nil {
		t.Fatalf("expected id in response, got %v", created)
	}
	if created["name"] != "my-template" {
		t.Errorf("expected name echoed back, got %v", created["name"])
	}

	// List — should contain the created template.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
	listReq = withClaims(listReq, &auth.Claims{Sub: username, Role: "author"})
	listW := httptest.NewRecorder()
	handlers.ListTemplates(d)(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listW.Code)
	}
	var list []map[string]any
	_ = json.NewDecoder(listW.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("expected 1 template listed, got %d: %v", len(list), list)
	}

	// A second user must not be able to list or delete this template.
	_, otherUsername := mkUser13(t, pool, "author")
	otherListReq := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
	otherListReq = withClaims(otherListReq, &auth.Claims{Sub: otherUsername, Role: "author"})
	otherListW := httptest.NewRecorder()
	handlers.ListTemplates(d)(otherListW, otherListReq)
	var otherList []map[string]any
	_ = json.NewDecoder(otherListW.Body).Decode(&otherList)
	if len(otherList) != 0 {
		t.Errorf("expected other user to see no templates (isolation), got %v", otherList)
	}

	idStr := jsonNumberToString(t, tplID)
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/"+idStr, nil)
	delReq.SetPathValue("id", idStr)
	delReq = withClaims(delReq, &auth.Claims{Sub: otherUsername, Role: "author"})
	delW := httptest.NewRecorder()
	handlers.DeleteTemplate(d)(delW, delReq)
	if delW.Code != http.StatusNotFound {
		t.Errorf("expected 404 when a different user tries to delete someone else's template (IDOR check), got %d", delW.Code)
	}

	// Owner can delete.
	ownDelReq := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/"+idStr, nil)
	ownDelReq.SetPathValue("id", idStr)
	ownDelReq = withClaims(ownDelReq, &auth.Claims{Sub: username, Role: "author"})
	ownDelW := httptest.NewRecorder()
	handlers.DeleteTemplate(d)(ownDelW, ownDelReq)
	if ownDelW.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when owner deletes, got %d — body: %s", ownDelW.Code, ownDelW.Body.String())
	}

	// Deleting again returns 404.
	againReq := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/"+idStr, nil)
	againReq.SetPathValue("id", idStr)
	againReq = withClaims(againReq, &auth.Claims{Sub: username, Role: "author"})
	againW := httptest.NewRecorder()
	handlers.DeleteTemplate(d)(againW, againReq)
	if againW.Code != http.StatusNotFound {
		t.Errorf("expected 404 on double delete, got %d", againW.Code)
	}

	// cleanup the other user
	cleanup13(pool, "users", "id", mustUserID13(t, pool, otherUsername))
	_ = context.Background()
}

// jsonNumberToString converts a decoded JSON number (float64) or string id
// into its canonical string form for use in URL path values.
func jsonNumberToString(t *testing.T, v any) string {
	t.Helper()
	switch x := v.(type) {
	case string:
		return x
	case float64:
		// template ids are int64 (bigint); json.Decode turns them into float64.
		return fmt.Sprintf("%.0f", x)
	default:
		t.Fatalf("unexpected id type %T: %v", v, v)
		return ""
	}
}

func mustUserID13(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `SELECT id FROM users WHERE username=$1`, username).Scan(&id); err != nil {
		t.Fatalf("mustUserID13: %v", err)
	}
	return id
}
