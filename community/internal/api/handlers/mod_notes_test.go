package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

// --- Live-DB tests: full mod-note lifecycle ---

func TestModNotes_CreateListDelete_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	modID, modUsername := mkUser13(t, pool, "moderator")
	subjectID, subjectUsername := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", modID, subjectID)

	// Create a note.
	body, _ := json.Marshal(map[string]string{"body": "  flagged for review  "})
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+subjectUsername+"/notes", bytes.NewReader(body))
	createReq.SetPathValue("username", subjectUsername)
	createReq = withClaims(createReq, &auth.Claims{Sub: modUsername, Role: "moderator"})
	createW := httptest.NewRecorder()
	handlers.CreateModNote(d)(createW, createReq)
	if createW.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", createW.Code, createW.Body.String())
	}
	var created map[string]string
	_ = json.NewDecoder(createW.Body).Decode(&created)
	noteID := created["id"]
	if noteID == "" {
		t.Fatalf("expected note id in response, got %v", created)
	}

	// List notes for the subject — should contain the trimmed body.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/"+subjectUsername+"/notes", nil)
	listReq.SetPathValue("username", subjectUsername)
	listReq = withClaims(listReq, &auth.Claims{Sub: modUsername, Role: "moderator"})
	listW := httptest.NewRecorder()
	handlers.ListModNotes(d)(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listW.Code)
	}
	var notes []map[string]string
	_ = json.NewDecoder(listW.Body).Decode(&notes)
	if len(notes) != 1 {
		t.Fatalf("expected 1 note, got %d: %v", len(notes), notes)
	}
	if notes[0]["body"] != "flagged for review" {
		t.Errorf("expected trimmed body, got %q", notes[0]["body"])
	}
	if notes[0]["author_username"] != modUsername {
		t.Errorf("expected author_username=%q, got %q", modUsername, notes[0]["author_username"])
	}

	// A different subject's note list is empty (no cross-contamination).
	_, otherSubjectUsername := mkUser13(t, pool, "author")
	otherListReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/"+otherSubjectUsername+"/notes", nil)
	otherListReq.SetPathValue("username", otherSubjectUsername)
	otherListReq = withClaims(otherListReq, &auth.Claims{Sub: modUsername, Role: "moderator"})
	otherListW := httptest.NewRecorder()
	handlers.ListModNotes(d)(otherListW, otherListReq)
	var otherNotes []map[string]string
	_ = json.NewDecoder(otherListW.Body).Decode(&otherNotes)
	if len(otherNotes) != 0 {
		t.Errorf("expected no notes for unrelated subject, got %v", otherNotes)
	}

	// Delete the note.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/notes/"+noteID, nil)
	delReq.SetPathValue("id", noteID)
	delReq = withClaims(delReq, &auth.Claims{Sub: modUsername, Role: "moderator"})
	delW := httptest.NewRecorder()
	handlers.DeleteModNote(d)(delW, delReq)
	if delW.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", delW.Code, delW.Body.String())
	}

	// Deleting again is 404.
	delAgainW := httptest.NewRecorder()
	handlers.DeleteModNote(d)(delAgainW, delReq)
	if delAgainW.Code != http.StatusNotFound {
		t.Errorf("expected 404 on double delete, got %d", delAgainW.Code)
	}
}

func TestCreateModNote_UnknownSubject_Returns404_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	modID, modUsername := mkUser13(t, pool, "moderator")
	defer cleanup13(pool, "users", "id", modID)

	body, _ := json.Marshal(map[string]string{"body": "note"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/ghost/notes", bytes.NewReader(body))
	req.SetPathValue("username", "ghost-user-does-not-exist")
	req = withClaims(req, &auth.Claims{Sub: modUsername, Role: "moderator"})
	w := httptest.NewRecorder()
	handlers.CreateModNote(d)(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown subject, got %d — body: %s", w.Code, w.Body.String())
	}
}

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
