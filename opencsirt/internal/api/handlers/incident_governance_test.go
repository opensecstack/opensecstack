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

	"github.com/opensecstack/opencsirt/internal/auth"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"
)

// TestIncidentClose_CitadelHardStopBlocksAndSurfacesReason mirrors
// TestAdvisoryPublish_CitadelRefuseBlocksAndSurfacesReason for incident
// closure, using a HARD_STOP outcome (the other blocking verdict MARSHAL
// can return) to prove both blocking outcomes — not just REFUSE — stop the
// action and surface their reasons.
func TestIncidentClose_CitadelHardStopBlocksAndSurfacesReason(t *testing.T) {
	actorID := uuid.New()
	incidentID := uuid.New()
	const bearerToken = "real-sinauth-bearer-token-def456"
	const hardStopReason = "NDS_SAME_IDENTITY: operator and verifier are the same user"

	var captured sdkcitadel.Kerkese
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/marshal/evaluate" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode kerkese: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sdkcitadel.Decision{
			Outcome:     sdkcitadel.OutcomeHardStop,
			ExecutionID: captured.ExecutionID,
			Reasons:     []string{hardStopReason},
		})
	}))
	defer srv.Close()

	h := &Incident{
		// Left nil on purpose — see advisory_governance_test.go for why.
		Service:          nil,
		Citadel:          sdkcitadel.NewClient(srv.URL, nil),
		CitadelProjectID: "opencsirt-test",
		CitadelDryRun:    true,
		Logger:           zerolog.Nop(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID.String()+"/close", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", incidentID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
		Sub:  actorID.String(),
		Role: auth.RoleOperator,
	}))

	w := httptest.NewRecorder()
	h.Close(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), hardStopReason) {
		t.Errorf("response body %q does not surface the CITADEL HARD_STOP reason", w.Body.String())
	}

	if captured.Actor.UserID != actorID.String() {
		t.Errorf("Actor.UserID = %q, want %q", captured.Actor.UserID, actorID.String())
	}
	if captured.ActorToken != bearerToken {
		t.Errorf("ActorToken = %q, want %q", captured.ActorToken, bearerToken)
	}
	if captured.Action.Type != "INCIDENT_CLOSE" {
		t.Errorf("Action.Type = %q, want \"INCIDENT_CLOSE\"", captured.Action.Type)
	}
	if captured.ExecutionID != incidentID {
		t.Errorf("ExecutionID = %v, want %v", captured.ExecutionID, incidentID)
	}
	if captured.Verifier.UserID == captured.Actor.UserID {
		t.Errorf("Verifier.UserID must differ from Actor.UserID")
	}
}
