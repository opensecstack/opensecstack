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

func TestUpsertContextNote_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/context-note", bytes.NewReader([]byte(`{"body":"note"}`)))
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpsertContextNote(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-moderator, got %d", w.Code)
	}
}

func TestUpsertContextNote_EmptyBody_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/context-note", bytes.NewReader([]byte(`{"body":"  "}`)))
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.UpsertContextNote(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", w.Code)
	}
}

func TestUpsertContextNote_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/context-note", bytes.NewReader([]byte(`{bad`)))
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.UpsertContextNote(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestUpsertContextNote_AuthorNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/context-note", bytes.NewReader([]byte(`{"body":"note"}`)))
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.UpsertContextNote(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDeleteContextNote_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/1/context-note", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "viewer"})
	w := httptest.NewRecorder()

	handlers.DeleteContextNote(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-moderator, got %d", w.Code)
	}
}

func TestDeleteContextNote_Moderator_Returns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/1/context-note", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.DeleteContextNote(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestGetContextNote_NotFound_ReturnsNullNote(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/1/context-note", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()

	handlers.GetContextNote(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["note"] != nil {
		t.Errorf("expected note=nil, got %v", resp["note"])
	}
}
