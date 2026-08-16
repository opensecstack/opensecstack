package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkcitadel "github.com/opensecstack/sdk/go/citadel"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/citadel"
	"github.com/opensecstack/community/internal/config"
)

// marshalEvaluateStub returns an httptest handler mimicking CITADEL's
// POST /api/v1/marshal/evaluate, always responding with the given outcome —
// mirrors evaluateHandler in internal/citadel/governance_test.go, kept
// local here since that helper is unexported.
func marshalEvaluateStub(t *testing.T, outcome string, reasons []string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		if outcome == sdkcitadel.OutcomeHardStop {
			status = http.StatusForbidden
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(sdkcitadel.Decision{Outcome: outcome, Reasons: reasons})
	}
}

func TestRequestDeletion_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	w := httptest.NewRecorder()

	handlers.RequestDeletion(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestRequestDeletion_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.RequestDeletion(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCancelDeletion_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/deletion-request", nil)
	w := httptest.NewRecorder()

	handlers.CancelDeletion(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestCancelDeletion_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/deletion-request", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CancelDeletion(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetDeletionStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/deletion-request", nil)
	w := httptest.NewRecorder()

	handlers.GetDeletionStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestGetDeletionStatus_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/deletion-request", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetDeletionStatus(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestAdminListDeletionRequests_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/deletion-requests", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.AdminListDeletionRequests(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestAdminListDeletionRequests_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/deletion-requests", nil)
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminListDeletionRequests(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

func TestAdminApproveDeletion_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/1/approve", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.AdminApproveDeletion(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestAdminApproveDeletion_RequestNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/1/approve", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminApproveDeletion(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "deletion request not found" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestAdminProcessDeletion_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/1/process", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.AdminProcessDeletion(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestAdminProcessDeletion_RequestNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/1/process", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminProcessDeletion(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Live-DB success paths and cross-user isolation ---
//
// The GDPR erasure flow is the highest-consequence code in this file: it is
// what actually deletes an account. These tests exercise it against a real
// schema (see gru_live_db_test.go) rather than only the "DB unreachable"
// branch, and explicitly verify the privacy-critical property that one
// user's deletion-request state is never visible to, or actionable by,
// another ordinary user.

func TestRequestDeletion_Success_CreatesPendingRequest(t *testing.T) {
	d := requireLiveDB(t)
	_, username := seedTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RequestDeletion(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["scheduled_for"] == "" {
		t.Error("expected scheduled_for to be populated")
	}
}

func TestRequestDeletion_AlreadyPending_Returns409(t *testing.T) {
	d := requireLiveDB(t)
	_, username := seedTestUser(t, d.Pool, "author")
	claims := &auth.Claims{Sub: username, Role: "author"}

	first := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	first = withClaims(first, claims)
	handlers.RequestDeletion(d)(httptest.NewRecorder(), first)

	second := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	second = withClaims(second, claims)
	w := httptest.NewRecorder()
	handlers.RequestDeletion(d)(w, second)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate pending request, got %d", w.Code)
	}
}

func TestCancelDeletion_Success_ClearsPendingRequest(t *testing.T) {
	d := requireLiveDB(t)
	_, username := seedTestUser(t, d.Pool, "author")
	claims := &auth.Claims{Sub: username, Role: "author"}

	reqReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	reqReq = withClaims(reqReq, claims)
	handlers.RequestDeletion(d)(httptest.NewRecorder(), reqReq)

	cancelReq := httptest.NewRequest(http.MethodDelete, "/api/v1/me/deletion-request", nil)
	cancelReq = withClaims(cancelReq, claims)
	w := httptest.NewRecorder()
	handlers.CancelDeletion(d)(w, cancelReq)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/me/deletion-request", nil)
	statusReq = withClaims(statusReq, claims)
	statusW := httptest.NewRecorder()
	handlers.GetDeletionStatus(d)(statusW, statusReq)

	var resp map[string]any
	_ = json.NewDecoder(statusW.Body).Decode(&resp)
	if resp["request"] != nil {
		t.Errorf("expected no active request after cancel, got %v", resp["request"])
	}
}

func TestGetDeletionStatus_Success_ReturnsOwnPendingRequest(t *testing.T) {
	d := requireLiveDB(t)
	_, username := seedTestUser(t, d.Pool, "author")
	claims := &auth.Claims{Sub: username, Role: "author"}

	reqReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	reqReq = withClaims(reqReq, claims)
	handlers.RequestDeletion(d)(httptest.NewRecorder(), reqReq)

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/me/deletion-request", nil)
	statusReq = withClaims(statusReq, claims)
	w := httptest.NewRecorder()
	handlers.GetDeletionStatus(d)(w, statusReq)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["request"] == nil {
		t.Fatal("expected an active deletion request in the response")
	}
}

// TestGetDeletionStatus_CrossUserIsolation_NeverSeesAnotherUsersRequest is the
// headline privacy check for this file: user A files a GDPR deletion
// request, and a completely unrelated user B — who never requested anything
// — must see request: nil when they check their own status. GDPR erasure
// state is per-subject; if this ever leaked, one user's deletion request
// (and by extension deletion-request timing/existence) would be visible to
// another user, which is a real cross-tenant privacy violation, not just a
// cosmetic bug.
func TestGetDeletionStatus_CrossUserIsolation_NeverSeesAnotherUsersRequest(t *testing.T) {
	d := requireLiveDB(t)
	_, userAUsername := seedTestUser(t, d.Pool, "author")
	_, userBUsername := seedTestUser(t, d.Pool, "author")

	reqA := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	reqA = withClaims(reqA, &auth.Claims{Sub: userAUsername, Role: "author"})
	wA := httptest.NewRecorder()
	handlers.RequestDeletion(d)(wA, reqA)
	if wA.Code != http.StatusCreated {
		t.Fatalf("setup: user A's deletion request failed with %d — body: %s", wA.Code, wA.Body.String())
	}

	// User B never requested deletion. Their own status check must be
	// scoped strictly to their own user_id and must not see A's request.
	reqB := httptest.NewRequest(http.MethodGet, "/api/v1/me/deletion-request", nil)
	reqB = withClaims(reqB, &auth.Claims{Sub: userBUsername, Role: "author"})
	wB := httptest.NewRecorder()
	handlers.GetDeletionStatus(d)(wB, reqB)

	if wB.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", wB.Code)
	}
	var respB map[string]any
	_ = json.NewDecoder(wB.Body).Decode(&respB)
	if respB["request"] != nil {
		t.Errorf("cross-user data leak: user B saw user A's deletion request: %v", respB["request"])
	}

	// Cancelling as B must not be able to touch A's request either — verify
	// A's request is still intact afterwards.
	cancelB := httptest.NewRequest(http.MethodDelete, "/api/v1/me/deletion-request", nil)
	cancelB = withClaims(cancelB, &auth.Claims{Sub: userBUsername, Role: "author"})
	handlers.CancelDeletion(d)(httptest.NewRecorder(), cancelB)

	statusA := httptest.NewRequest(http.MethodGet, "/api/v1/me/deletion-request", nil)
	statusA = withClaims(statusA, &auth.Claims{Sub: userAUsername, Role: "author"})
	wA2 := httptest.NewRecorder()
	handlers.GetDeletionStatus(d)(wA2, statusA)
	var respA map[string]any
	_ = json.NewDecoder(wA2.Body).Decode(&respA)
	if respA["request"] == nil {
		t.Error("user B's cancel call incorrectly cancelled user A's deletion request")
	}
}

func TestAdminListDeletionRequests_Success_ReturnsPendingRequest(t *testing.T) {
	d := requireLiveDB(t)
	_, targetUsername := seedTestUser(t, d.Pool, "author")
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	reqReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	reqReq = withClaims(reqReq, &auth.Claims{Sub: targetUsername, Role: "author"})
	handlers.RequestDeletion(d)(httptest.NewRecorder(), reqReq)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/deletion-requests", nil)
	listReq = withClaims(listReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminListDeletionRequests(d)(w, listReq)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Requests []struct {
			Username string `json:"username"`
			Status   string `json:"status"`
		} `json:"requests"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, r := range resp.Requests {
		if r.Username == targetUsername {
			found = true
			if r.Status != "pending" {
				t.Errorf("expected status pending, got %q", r.Status)
			}
		}
	}
	if !found {
		t.Error("expected the seeded deletion request to appear in the admin list")
	}
}

func TestAdminApproveDeletion_SelfApproval_Returns403(t *testing.T) {
	d := requireLiveDB(t)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	// The admin requests their own deletion, then tries to approve it
	// themselves — separation of duties (NDS) must reject this before any
	// state changes, exactly as documented on AdminApproveDeletion.
	reqReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	reqReq = withClaims(reqReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	handlers.RequestDeletion(d)(httptest.NewRecorder(), reqReq)

	var requestID string
	if err := d.Pool.QueryRow(reqReq.Context(),
		`SELECT id FROM deletion_requests WHERE status='pending' ORDER BY requested_at DESC LIMIT 1`,
	).Scan(&requestID); err != nil {
		t.Fatalf("lookup seeded request id: %v", err)
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/"+requestID+"/approve", nil)
	approveReq.SetPathValue("id", requestID)
	approveReq = withClaims(approveReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminApproveDeletion(d)(w, approveReq)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for self-approval, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestAdminApproveDeletion_Success_ThenProcessDeletesUser(t *testing.T) {
	d := requireLiveDB(t)
	targetID, targetUsername := seedTestUser(t, d.Pool, "author")
	_, approverUsername := seedTestUser(t, d.Pool, "admin")

	reqReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	reqReq = withClaims(reqReq, &auth.Claims{Sub: targetUsername, Role: "author"})
	handlers.RequestDeletion(d)(httptest.NewRecorder(), reqReq)

	var requestID string
	if err := d.Pool.QueryRow(reqReq.Context(),
		`SELECT id FROM deletion_requests WHERE user_id=$1 AND status='pending'`, targetID,
	).Scan(&requestID); err != nil {
		t.Fatalf("lookup seeded request id: %v", err)
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/"+requestID+"/approve", nil)
	approveReq.SetPathValue("id", requestID)
	approveReq = withClaims(approveReq, &auth.Claims{Sub: approverUsername, Role: "admin"})
	approveW := httptest.NewRecorder()
	handlers.AdminApproveDeletion(d)(approveW, approveReq)
	if approveW.Code != http.StatusOK {
		t.Fatalf("expected 200 approving, got %d — body: %s", approveW.Code, approveW.Body.String())
	}

	// Re-approving must now conflict — it's no longer 'pending'.
	reapproveReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/"+requestID+"/approve", nil)
	reapproveReq.SetPathValue("id", requestID)
	reapproveReq = withClaims(reapproveReq, &auth.Claims{Sub: approverUsername, Role: "admin"})
	reapproveW := httptest.NewRecorder()
	handlers.AdminApproveDeletion(d)(reapproveW, reapproveReq)
	if reapproveW.Code != http.StatusConflict {
		t.Errorf("expected 409 re-approving an already-approved request, got %d", reapproveW.Code)
	}

	processReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/"+requestID+"/process", nil)
	processReq.SetPathValue("id", requestID)
	processReq = withClaims(processReq, &auth.Claims{Sub: approverUsername, Role: "admin"})
	processW := httptest.NewRecorder()
	handlers.AdminProcessDeletion(d)(processW, processReq)
	if processW.Code != http.StatusNoContent {
		t.Fatalf("expected 204 processing deletion, got %d — body: %s", processW.Code, processW.Body.String())
	}

	var stillExists string
	err := d.Pool.QueryRow(reqReq.Context(), `SELECT id FROM users WHERE id=$1`, targetID).Scan(&stillExists)
	if err == nil {
		t.Error("expected user row to be deleted after AdminProcessDeletion, but it still exists")
	}
}

func TestAdminProcessDeletion_NotApproved_Returns400(t *testing.T) {
	d := requireLiveDB(t)
	targetID, targetUsername := seedTestUser(t, d.Pool, "author")
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	reqReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	reqReq = withClaims(reqReq, &auth.Claims{Sub: targetUsername, Role: "author"})
	handlers.RequestDeletion(d)(httptest.NewRecorder(), reqReq)

	var requestID string
	if err := d.Pool.QueryRow(reqReq.Context(),
		`SELECT id FROM deletion_requests WHERE user_id=$1 AND status='pending'`, targetID,
	).Scan(&requestID); err != nil {
		t.Fatalf("lookup seeded request id: %v", err)
	}

	processReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/"+requestID+"/process", nil)
	processReq.SetPathValue("id", requestID)
	processReq = withClaims(processReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminProcessDeletion(d)(w, processReq)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 processing a not-yet-approved request, got %d — body: %s", w.Code, w.Body.String())
	}
}

// setupApprovedDeletion seeds a target user with a pending deletion request
// that has already been approved by a distinct admin, and returns the
// request id — the state AdminProcessDeletion requires before it will ever
// touch CITADEL or delete anything.
func setupApprovedDeletion(t *testing.T, d handlers.Deps) (targetID, requestID string) {
	t.Helper()
	targetUsername, approverUsername := "", ""
	targetID, targetUsername = seedTestUser(t, d.Pool, "author")
	_, approverUsername = seedTestUser(t, d.Pool, "admin")

	reqReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/deletion-request", nil)
	reqReq = withClaims(reqReq, &auth.Claims{Sub: targetUsername, Role: "author"})
	handlers.RequestDeletion(d)(httptest.NewRecorder(), reqReq)

	if err := d.Pool.QueryRow(reqReq.Context(),
		`SELECT id FROM deletion_requests WHERE user_id=$1 AND status='pending'`, targetID,
	).Scan(&requestID); err != nil {
		t.Fatalf("lookup seeded request id: %v", err)
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/"+requestID+"/approve", nil)
	approveReq.SetPathValue("id", requestID)
	approveReq = withClaims(approveReq, &auth.Claims{Sub: approverUsername, Role: "admin"})
	approveW := httptest.NewRecorder()
	handlers.AdminApproveDeletion(d)(approveW, approveReq)
	if approveW.Code != http.StatusOK {
		t.Fatalf("setup: approving deletion request failed with %d — body: %s", approveW.Code, approveW.Body.String())
	}
	return targetID, requestID
}

// TestAdminProcessDeletion_CitadelExecute_DeletesUser exercises the real
// MARSHAL-integration branch (d.Marshal != nil) that AdminProcessDeletion
// only takes when a GovernanceClient is wired in — every other test in this
// file leaves d.Marshal nil and so skips this code entirely. An EXECUTE
// verdict from MARSHAL must let the deletion proceed exactly as if there
// were no CITADEL integration at all.
func TestAdminProcessDeletion_CitadelExecute_DeletesUser(t *testing.T) {
	d := requireLiveDB(t)
	srv := httptest.NewServer(marshalEvaluateStub(t, sdkcitadel.OutcomeExecute, nil))
	defer srv.Close()
	d.Marshal = citadel.NewGovernanceClient(srv.URL)

	targetID, requestID := setupApprovedDeletion(t, d)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	processReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/"+requestID+"/process", nil)
	processReq.SetPathValue("id", requestID)
	processReq = withClaims(processReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminProcessDeletion(d)(w, processReq)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when MARSHAL returns EXECUTE, got %d — body: %s", w.Code, w.Body.String())
	}

	var stillExists string
	err := d.Pool.QueryRow(processReq.Context(), `SELECT id FROM users WHERE id=$1`, targetID).Scan(&stillExists)
	if err == nil {
		t.Error("expected user to be deleted after an EXECUTE verdict")
	}
}

// TestAdminProcessDeletion_CitadelRefuse_BlocksDeletion is the headline
// regression test for the CITADEL integration: if MARSHAL says REFUSE, the
// account must survive. A bug here means an account gets erased despite
// governance saying no — see the identical concern already covered for the
// bare EvaluateDeletion call in internal/citadel/governance_test.go; this
// test proves the handler actually honours that verdict end-to-end,
// including not deleting the row and not marking the request processed.
func TestAdminProcessDeletion_CitadelRefuse_BlocksDeletion(t *testing.T) {
	d := requireLiveDB(t)
	srv := httptest.NewServer(marshalEvaluateStub(t, sdkcitadel.OutcomeRefuse, []string{"policy violation"}))
	defer srv.Close()
	d.Marshal = citadel.NewGovernanceClient(srv.URL)

	targetID, requestID := setupApprovedDeletion(t, d)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	processReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deletion-requests/"+requestID+"/process", nil)
	processReq.SetPathValue("id", requestID)
	processReq = withClaims(processReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.AdminProcessDeletion(d)(w, processReq)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when MARSHAL returns REFUSE, got %d — body: %s", w.Code, w.Body.String())
	}

	var stillExists string
	if err := d.Pool.QueryRow(processReq.Context(), `SELECT id FROM users WHERE id=$1`, targetID).Scan(&stillExists); err != nil {
		t.Fatal("REFUSE must block deletion, but the user row is gone")
	}

	var status string
	if err := d.Pool.QueryRow(processReq.Context(), `SELECT status FROM deletion_requests WHERE id=$1`, requestID).Scan(&status); err != nil {
		t.Fatalf("lookup request status: %v", err)
	}
	if status != "approved" {
		t.Errorf("expected request to remain 'approved' (not processed) after REFUSE, got %q", status)
	}
}
