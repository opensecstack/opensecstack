package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestListModNotes_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/bob/notes", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListModNotes(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestListModNotes_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/bob/notes", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "mod1", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.ListModNotes(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestCreateModNote_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/bob/notes", bytes.NewReader([]byte(`{"body":"note"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "viewer"})
	w := httptest.NewRecorder()

	handlers.CreateModNote(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCreateModNote_EmptyBody_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/bob/notes", bytes.NewReader([]byte(`{"body":"   "}`)))
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "mod1", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.CreateModNote(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for whitespace-only body, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestCreateModNote_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/bob/notes", bytes.NewReader([]byte(`{bad`)))
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "mod1", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.CreateModNote(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestCreateModNote_UnresolvableAuthor_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/bob/notes", bytes.NewReader([]byte(`{"body":"a real note"}`)))
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "mod1", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.CreateModNote(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when author cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestDeleteModNote_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/notes/1", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeleteModNote(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestDeleteModNote_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/notes/1", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "mod1", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.DeleteModNote(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}
