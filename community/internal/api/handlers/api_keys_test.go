package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestListAPIKeys_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/api-keys", nil)
	w := httptest.NewRecorder()

	handlers.ListAPIKeys(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestListAPIKeys_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/api-keys", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListAPIKeys(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

func TestCreateAPIKey_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewReader([]byte(`{"name":"my key"}`)))
	w := httptest.NewRecorder()

	handlers.CreateAPIKey(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestCreateAPIKey_EmptyName_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewReader([]byte(`{"name":""}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateAPIKey(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty name, got %d", w.Code)
	}
}

func TestCreateAPIKey_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateAPIKey(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestCreateAPIKey_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewReader([]byte(`{"name":"my key"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateAPIKey(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error counting keys, got %d — body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "db error") {
		t.Errorf("expected db error message, got %q", w.Body.String())
	}
}

func TestDeleteAPIKey_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/api-keys/1", nil)
	w := httptest.NewRecorder()

	handlers.DeleteAPIKey(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestDeleteAPIKey_DBErrorOrNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/api-keys/1", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeleteAPIKey(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on db error/not found, got %d", w.Code)
	}
}

// --- Live-DB tests: full lifecycle + cross-user IDOR checks ---

func TestAPIKeys_CreateListDelete_FullLifecycle_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	// Create.
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewReader([]byte(`{"name":"CI token"}`)))
	createReq = withClaims(createReq, &auth.Claims{Sub: username, Role: "author"})
	createW := httptest.NewRecorder()
	handlers.CreateAPIKey(d)(createW, createReq)
	if createW.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", createW.Code, createW.Body.String())
	}
	var created map[string]string
	_ = json.NewDecoder(createW.Body).Decode(&created)
	keyID := created["id"]
	rawKey := created["key"]
	if keyID == "" || rawKey == "" {
		t.Fatalf("expected id and key in response, got %v", created)
	}
	if !strings.HasPrefix(rawKey, "sin_") {
		t.Errorf("expected raw key with sin_ prefix, got %q", rawKey)
	}

	// List — owner sees it.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/me/api-keys", nil)
	listReq = withClaims(listReq, &auth.Claims{Sub: username, Role: "author"})
	listW := httptest.NewRecorder()
	handlers.ListAPIKeys(d)(listW, listReq)
	var listResp map[string]any
	_ = json.NewDecoder(listW.Body).Decode(&listResp)
	keys, _ := listResp["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key listed, got %d: %v", len(keys), keys)
	}
	first, _ := keys[0].(map[string]any)
	if raw, ok := first["key"]; ok {
		t.Errorf("expected the raw secret to never be included in the list response, but found key=%v", raw)
	}

	// IDOR check: a different user must not see this key in their own list.
	_, otherUsername := mkUser13(t, pool, "author")
	otherListReq := httptest.NewRequest(http.MethodGet, "/api/v1/me/api-keys", nil)
	otherListReq = withClaims(otherListReq, &auth.Claims{Sub: otherUsername, Role: "author"})
	otherListW := httptest.NewRecorder()
	handlers.ListAPIKeys(d)(otherListW, otherListReq)
	var otherListResp map[string]any
	_ = json.NewDecoder(otherListW.Body).Decode(&otherListResp)
	otherKeys, _ := otherListResp["keys"].([]any)
	if len(otherKeys) != 0 {
		t.Errorf("expected other user to see 0 keys (isolation), got %v", otherKeys)
	}

	// IDOR check: a different user must not be able to delete this key by ID.
	otherDelReq := httptest.NewRequest(http.MethodDelete, "/api/v1/me/api-keys/"+keyID, nil)
	otherDelReq.SetPathValue("id", keyID)
	otherDelReq = withClaims(otherDelReq, &auth.Claims{Sub: otherUsername, Role: "author"})
	otherDelW := httptest.NewRecorder()
	handlers.DeleteAPIKey(d)(otherDelW, otherDelReq)
	if otherDelW.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when a different user tries to delete someone else's API key (IDOR), got %d", otherDelW.Code)
	}

	// Confirm it's still there after the attempted cross-user delete.
	stillThereW := httptest.NewRecorder()
	handlers.ListAPIKeys(d)(stillThereW, listReq)
	var stillThereResp map[string]any
	_ = json.NewDecoder(stillThereW.Body).Decode(&stillThereResp)
	stillKeys, _ := stillThereResp["keys"].([]any)
	if len(stillKeys) != 1 {
		t.Fatalf("expected key to survive a cross-user delete attempt, got %d keys", len(stillKeys))
	}

	// Owner can delete it.
	ownDelReq := httptest.NewRequest(http.MethodDelete, "/api/v1/me/api-keys/"+keyID, nil)
	ownDelReq.SetPathValue("id", keyID)
	ownDelReq = withClaims(ownDelReq, &auth.Claims{Sub: username, Role: "author"})
	ownDelW := httptest.NewRecorder()
	handlers.DeleteAPIKey(d)(ownDelW, ownDelReq)
	if ownDelW.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when owner deletes their own key, got %d — body: %s", ownDelW.Code, ownDelW.Body.String())
	}
}

func TestCreateAPIKey_LimitOfTenEnforced_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewReader([]byte(`{"name":"k"}`)))
		req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
		w := httptest.NewRecorder()
		handlers.CreateAPIKey(d)(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 creating key %d, got %d — body: %s", i, w.Code, w.Body.String())
		}
	}

	// The 11th must be rejected.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/api-keys", bytes.NewReader([]byte(`{"name":"one too many"}`)))
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.CreateAPIKey(d)(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when exceeding the 10-key limit, got %d — body: %s", w.Code, w.Body.String())
	}
}
