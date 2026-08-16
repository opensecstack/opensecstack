package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	sdkcitadel "github.com/opensecstack/sdk/go/citadel"

	"github.com/opensecstack/opencsirt/internal/auth"
)

// TestAdvisoryPublish_CitadelRefuseBlocksAndSurfacesReason proves two
// things about the new governance wiring on advisory publication:
//
//  1. The Kerkese submitted to MARSHAL carries the real authenticated
//     Actor — the UUID and bearer token of the caller, not a placeholder —
//     while the Verifier is (deliberately, per the code comment in
//     advisory.go's Publish handler) a fixed system placeholder distinct
//     from the Actor.
//  2. A REFUSE decision from CITADEL blocks the publish (h.Service is nil
//     here — if it were reached, the test would panic — proving the
//     handler returns before ever calling advisory.Service.Publish) and
//     the decision's reasons are surfaced to the HTTP caller, not
//     silently swallowed.
func TestAdvisoryPublish_CitadelRefuseBlocksAndSurfacesReason(t *testing.T) {
	actorID := uuid.New()
	advisoryID := uuid.New()
	const bearerToken = "real-sinauth-bearer-token-abc123"
	const refuseReason = "AUTHZ_FAIL: role csirt_lead is not permitted to perform ADVISORY_PUBLISH"

	var captured sdkcitadel.Kerkese
	var hitPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode kerkese: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sdkcitadel.Decision{
			Outcome:     sdkcitadel.OutcomeRefuse,
			ExecutionID: captured.ExecutionID,
			Reasons:     []string{refuseReason},
		})
	}))
	defer srv.Close()

	h := &Advisory{
		// Left nil on purpose: Publish must REFUSE and return before ever
		// touching h.Service. A nil-pointer panic here would mean the
		// governance check ran too late (or not at all).
		Service:          nil,
		Citadel:          sdkcitadel.NewClient(srv.URL, nil),
		CitadelProjectID: "opencsirt-test",
		CitadelDryRun:    true,
		Logger:           zerolog.Nop(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/advisories/"+advisoryID.String()+"/publish", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", advisoryID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
		Sub:  actorID.String(),
		Role: auth.RoleCSIRTLead,
	}))

	w := httptest.NewRecorder()
	h.Publish(w, req)

	if hitPath != "/api/v1/marshal/evaluate" {
		t.Fatalf("citadel mock was hit at %q, want /api/v1/marshal/evaluate", hitPath)
	}

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), refuseReason) {
		t.Errorf("response body %q does not surface the CITADEL refusal reason", w.Body.String())
	}

	// Real Actor identity, not a placeholder.
	if captured.Actor.UserID != actorID.String() {
		t.Errorf("Actor.UserID = %q, want %q", captured.Actor.UserID, actorID.String())
	}
	if captured.Actor.UserID == "" || captured.Actor.UserID == "unauthenticated" || captured.Actor.UserID == "opencsirt-system-verifier" {
		t.Errorf("Actor.UserID must be the real caller, got placeholder-looking value %q", captured.Actor.UserID)
	}
	if captured.ActorToken != bearerToken {
		t.Errorf("ActorToken = %q, want the forwarded bearer token %q", captured.ActorToken, bearerToken)
	}
	if captured.SoD.OperatorUserID != actorID.String() {
		t.Errorf("SoD.OperatorUserID = %q, want %q", captured.SoD.OperatorUserID, actorID.String())
	}
	if captured.ExecutionID != advisoryID {
		t.Errorf("ExecutionID = %v, want %v", captured.ExecutionID, advisoryID)
	}

	// Verifier must be distinct from the Actor (Gate 3 NDS_SAME_IDENTITY).
	if captured.Verifier.UserID == captured.Actor.UserID {
		t.Errorf("Verifier.UserID must differ from Actor.UserID")
	}
	if captured.SoD.VerifierUserID == captured.SoD.OperatorUserID {
		t.Errorf("SoD.VerifierUserID must differ from SoD.OperatorUserID")
	}
}
