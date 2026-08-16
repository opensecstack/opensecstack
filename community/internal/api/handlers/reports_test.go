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

func TestReportPost_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/report", bytes.NewReader([]byte(`{"reason":"spam"}`)))
	w := httptest.NewRecorder()

	handlers.ReportPost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestReportPost_InvalidReason_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/report", bytes.NewReader([]byte(`{"reason":"not_a_reason"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReportPost(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid reason, got %d", w.Code)
	}
}

func TestReportPost_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/report", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReportPost(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestReportPost_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/report", bytes.NewReader([]byte(`{"reason":"spam"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReportPost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when the reporting user can't be resolved, got %d", w.Code)
	}
}

func TestReportComment_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/1/report", bytes.NewReader([]byte(`{"reason":"spam"}`)))
	w := httptest.NewRecorder()

	handlers.ReportComment(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestReportComment_InvalidReason_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/1/report", bytes.NewReader([]byte(`{"reason":"bogus"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReportComment(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid reason, got %d", w.Code)
	}
}

func TestListReports_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mod/reports", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListReports(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-moderator, got %d", w.Code)
	}
}

func TestListReports_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mod/reports", nil)
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.ListReports(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on db error, got %d", w.Code)
	}
}

func TestResolveReport_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mod/reports/1/resolve", bytes.NewReader([]byte(`{"action":"resolve"}`)))
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ResolveReport(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-moderator, got %d", w.Code)
	}
}

func TestResolveReport_InvalidAction_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mod/reports/1/resolve", bytes.NewReader([]byte(`{"action":"delete"}`)))
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.ResolveReport(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid action, got %d", w.Code)
	}
}

func TestResolveReport_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mod/reports/1/resolve", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.ResolveReport(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

// --- Live-DB success paths ---

func TestReportPost_Success_ThenDuplicateReturns409(t *testing.T) {
	d := requireLiveDB(t)
	authorID, _ := seedTestUser(t, d.Pool, "author")
	_, reporterUsername := seedTestUser(t, d.Pool, "author")
	postID, _ := seedTestPost(t, d.Pool, authorID)

	body := `{"reason":"spam","note":"looks like spam"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/report", bytes.NewReader([]byte(body)))
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: reporterUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReportPost(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}

	// Reporting the same post again as the same user must conflict.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/report", bytes.NewReader([]byte(body)))
	req2.SetPathValue("id", postID)
	req2 = withClaims(req2, &auth.Claims{Sub: reporterUsername, Role: "author"})
	w2 := httptest.NewRecorder()
	handlers.ReportPost(d)(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate report, got %d", w2.Code)
	}
}

func TestReportPost_PostNotFound_Returns404(t *testing.T) {
	d := requireLiveDB(t)
	_, reporterUsername := seedTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/00000000-0000-0000-0000-000000000000/report", bytes.NewReader([]byte(`{"reason":"spam"}`)))
	req.SetPathValue("id", "00000000-0000-0000-0000-000000000000")
	req = withClaims(req, &auth.Claims{Sub: reporterUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReportPost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent post, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestReportComment_Success_ThenDuplicateReturns409(t *testing.T) {
	d := requireLiveDB(t)
	authorID, _ := seedTestUser(t, d.Pool, "author")
	_, reporterUsername := seedTestUser(t, d.Pool, "author")
	postID, _ := seedTestPost(t, d.Pool, authorID)
	commentID := seedTestComment(t, d.Pool, postID, authorID)

	body := `{"reason":"harassment","note":"rude"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/"+commentID+"/report", bytes.NewReader([]byte(body)))
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: reporterUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReportComment(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/comments/"+commentID+"/report", bytes.NewReader([]byte(body)))
	req2.SetPathValue("id", commentID)
	req2 = withClaims(req2, &auth.Claims{Sub: reporterUsername, Role: "author"})
	w2 := httptest.NewRecorder()
	handlers.ReportComment(d)(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate report, got %d", w2.Code)
	}
}

func TestReportComment_CommentNotFound_Returns404(t *testing.T) {
	d := requireLiveDB(t)
	_, reporterUsername := seedTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/00000000-0000-0000-0000-000000000000/report", bytes.NewReader([]byte(`{"reason":"spam"}`)))
	req.SetPathValue("id", "00000000-0000-0000-0000-000000000000")
	req = withClaims(req, &auth.Claims{Sub: reporterUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReportComment(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent comment, got %d", w.Code)
	}
}

func TestListReports_Success_ReturnsPendingReport(t *testing.T) {
	d := requireLiveDB(t)
	authorID, authorUsername := seedTestUser(t, d.Pool, "author")
	_, reporterUsername := seedTestUser(t, d.Pool, "author")
	_, modUsername := seedTestUser(t, d.Pool, "moderator")
	postID, postSlug := seedTestPost(t, d.Pool, authorID)

	insertReportReq := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/report", bytes.NewReader([]byte(`{"reason":"spam","note":"n"}`)))
	insertReportReq.SetPathValue("id", postID)
	insertReportReq = withClaims(insertReportReq, &auth.Claims{Sub: reporterUsername, Role: "author"})
	handlers.ReportPost(d)(httptest.NewRecorder(), insertReportReq)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/mod/reports?status=pending", nil)
	listReq = withClaims(listReq, &auth.Claims{Sub: modUsername, Role: "moderator"})
	w := httptest.NewRecorder()
	handlers.ListReports(d)(w, listReq)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Reports []struct {
			PostSlug           *string `json:"post_slug"`
			PostAuthorUsername *string `json:"post_author_username"`
		} `json:"reports"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, r := range resp.Reports {
		if r.PostSlug != nil && *r.PostSlug == postSlug {
			found = true
			if r.PostAuthorUsername == nil || *r.PostAuthorUsername != authorUsername {
				t.Errorf("expected post_author_username %q, got %v", authorUsername, r.PostAuthorUsername)
			}
		}
	}
	if !found {
		t.Error("expected the seeded report to appear in the moderator list")
	}
}

func TestResolveReport_Success_MarksResolved(t *testing.T) {
	d := requireLiveDB(t)
	authorID, _ := seedTestUser(t, d.Pool, "author")
	_, reporterUsername := seedTestUser(t, d.Pool, "author")
	_, modUsername := seedTestUser(t, d.Pool, "moderator")
	postID, _ := seedTestPost(t, d.Pool, authorID)

	reportReq := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/report", bytes.NewReader([]byte(`{"reason":"spam"}`)))
	reportReq.SetPathValue("id", postID)
	reportReq = withClaims(reportReq, &auth.Claims{Sub: reporterUsername, Role: "author"})
	reportW := httptest.NewRecorder()
	handlers.ReportPost(d)(reportW, reportReq)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(reportW.Body).Decode(&created)
	resolveReq := httptest.NewRequest(http.MethodPost, "/api/v1/mod/reports/"+created.ID+"/resolve", bytes.NewReader([]byte(`{"action":"resolve","note":"handled"}`)))
	resolveReq.SetPathValue("id", created.ID)
	resolveReq = withClaims(resolveReq, &auth.Claims{Sub: modUsername, Role: "moderator"})
	w := httptest.NewRecorder()
	handlers.ResolveReport(d)(w, resolveReq)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var status string
	if err := d.Pool.QueryRow(resolveReq.Context(), `SELECT status FROM reports WHERE id=$1`, created.ID).Scan(&status); err != nil {
		t.Fatalf("lookup report status: %v", err)
	}
	if status != "resolved" {
		t.Errorf("expected status resolved, got %q", status)
	}
}
