package handlers_test

import (
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

func TestGenerateInvite_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GenerateInvite(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-moderator, got %d", w.Code)
	}
}

func TestGenerateInvite_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites", nil)
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.GenerateInvite(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

func TestListInvites_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "viewer"})
	w := httptest.NewRecorder()

	handlers.ListInvites(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-moderator, got %d", w.Code)
	}
}

func TestListInvites_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites", nil)
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.ListInvites(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

func TestValidateInvite_MissingCode_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites/validate/", nil)
	w := httptest.NewRecorder()

	handlers.ValidateInvite(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing code, got %d", w.Code)
	}
}

func TestValidateInvite_NotFound_ReturnsInvalid(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites/validate/abc123", nil)
	req.SetPathValue("code", "abc123")
	w := httptest.NewRecorder()

	handlers.ValidateInvite(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if valid, _ := resp["valid"].(bool); valid {
		t.Error("expected valid=false for unknown code")
	}
	if resp["reason"] != "not found" {
		t.Errorf("expected reason='not found', got %v", resp["reason"])
	}
}

// --- Live-DB tests: full invite lifecycle ---

func TestInvites_GenerateListValidate_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	modID, modUsername := mkUser13(t, pool, "moderator")
	defer cleanup13(pool, "users", "id", modID)

	genReq := httptest.NewRequest(http.MethodPost, "/api/v1/invites", nil)
	genReq = withClaims(genReq, &auth.Claims{Sub: modUsername, Role: "moderator"})
	genW := httptest.NewRecorder()
	handlers.GenerateInvite(d)(genW, genReq)
	if genW.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", genW.Code, genW.Body.String())
	}
	var created map[string]any
	_ = json.NewDecoder(genW.Body).Decode(&created)
	code, _ := created["code"].(string)
	if code == "" {
		t.Fatalf("expected non-empty invite code, got %v", created)
	}

	// A freshly created invite validates as valid.
	validReq := httptest.NewRequest(http.MethodGet, "/api/v1/invites/validate/"+code, nil)
	validReq.SetPathValue("code", code)
	validW := httptest.NewRecorder()
	handlers.ValidateInvite(d)(validW, validReq)
	var validResp map[string]any
	_ = json.NewDecoder(validW.Body).Decode(&validResp)
	if valid, _ := validResp["valid"].(bool); !valid {
		t.Fatalf("expected freshly generated invite to be valid, got %v", validResp)
	}

	// It shows up in the list.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/invites", nil)
	listReq = withClaims(listReq, &auth.Claims{Sub: modUsername, Role: "moderator"})
	listW := httptest.NewRecorder()
	handlers.ListInvites(d)(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listW.Code)
	}
	var listResp map[string]any
	_ = json.NewDecoder(listW.Body).Decode(&listResp)
	invites, _ := listResp["invites"].([]any)
	found := false
	for _, inv := range invites {
		m, _ := inv.(map[string]any)
		if m["code"] == code {
			found = true
			if m["created_by_username"] != modUsername {
				t.Errorf("expected created_by_username=%q, got %v", modUsername, m["created_by_username"])
			}
		}
	}
	if !found {
		t.Errorf("expected generated invite %q to appear in list", code)
	}

	// Mark it used, then it must validate as invalid ("already used").
	_, err := pool.Exec(context.Background(),
		`UPDATE invites SET used_by=$1, used_at=now() WHERE code=$2`, modID, code)
	if err != nil {
		t.Fatalf("mark used: %v", err)
	}
	usedW := httptest.NewRecorder()
	handlers.ValidateInvite(d)(usedW, validReq)
	var usedResp map[string]any
	_ = json.NewDecoder(usedW.Body).Decode(&usedResp)
	if valid, _ := usedResp["valid"].(bool); valid {
		t.Errorf("expected used invite to be invalid, got %v", usedResp)
	}
	if usedResp["reason"] != "already used" {
		t.Errorf("expected reason='already used', got %v", usedResp["reason"])
	}
}

func TestValidateInvite_Expired_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	modID, _ := mkUser13(t, pool, "moderator")
	defer cleanup13(pool, "users", "id", modID)

	var code string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO invites (id, code, created_by, expires_at, created_at)
		 VALUES (gen_random_uuid(), $1, $2, now() - interval '1 hour', now())
		 RETURNING code`,
		"expired-"+uuid.New().String()[:8], modID,
	).Scan(&code)
	if err != nil {
		t.Fatalf("seed expired invite: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites/validate/"+code, nil)
	req.SetPathValue("code", code)
	w := httptest.NewRecorder()
	handlers.ValidateInvite(d)(w, req)
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if valid, _ := resp["valid"].(bool); valid {
		t.Errorf("expected expired invite to be invalid, got %v", resp)
	}
	if resp["reason"] != "expired" {
		t.Errorf("expected reason='expired', got %v", resp["reason"])
	}
}
