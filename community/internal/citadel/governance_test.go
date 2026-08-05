package citadel

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"
)

func TestResolveIdentity(t *testing.T) {
	t.Run("prefers real sinauth UUID when present", func(t *testing.T) {
		got := ResolveIdentity(sql.NullString{String: "11111111-1111-1111-1111-111111111111", Valid: true}, "community-internal-id")
		want := "11111111-1111-1111-1111-111111111111"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("falls back to a marked community identity when sinauth_id is null", func(t *testing.T) {
		got := ResolveIdentity(sql.NullString{}, "community-internal-id")
		want := "community-user:community-internal-id"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("falls back when sinauth_id is an empty string", func(t *testing.T) {
		got := ResolveIdentity(sql.NullString{String: "", Valid: true}, "community-internal-id")
		want := "community-user:community-internal-id"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestDeletionKerkese_UsesRealNonPlaceholderIdentities(t *testing.T) {
	reqID := uuid.New()
	k := DeletionKerkese("community-0", reqID, "sinauth-uuid-actor", "sinauth-uuid-verifier")

	if k.Actor.UserID != "sinauth-uuid-actor" {
		t.Errorf("Actor.UserID = %q, want %q", k.Actor.UserID, "sinauth-uuid-actor")
	}
	if k.Verifier.UserID != "sinauth-uuid-verifier" {
		t.Errorf("Verifier.UserID = %q, want %q", k.Verifier.UserID, "sinauth-uuid-verifier")
	}
	if k.SoD.OperatorUserID != k.Actor.UserID || k.SoD.VerifierUserID != k.Verifier.UserID {
		t.Error("SoD identifiers must match Actor/Verifier")
	}
	if k.Actor.UserID == k.Verifier.UserID {
		t.Error("Actor and Verifier must never be the same identity (separation of duties)")
	}
	if k.ExecutionID != reqID {
		t.Errorf("ExecutionID = %v, want %v", k.ExecutionID, reqID)
	}
	if k.SigOperator != "" || k.SigVerifier != "" {
		t.Error("SigOperator/SigVerifier must be left empty — no key-custody UX exists")
	}
	if k.ActorToken != "" || k.VerifierToken != "" {
		t.Error("ActorToken/VerifierToken must be left empty — community has no live sinauth bearer token to forward")
	}
}

// evaluateHandler returns an httptest handler that always responds with the
// given MARSHAL outcome, mimicking CITADEL's POST /api/v1/marshal/evaluate.
func evaluateHandler(t *testing.T, outcome string, reasons []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/marshal/evaluate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		status := http.StatusOK
		if outcome == sdkcitadel.OutcomeHardStop {
			status = http.StatusForbidden
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(sdkcitadel.Decision{
			Outcome: outcome,
			Reasons: reasons,
		})
	}
}

func TestEvaluateDeletion_ExecuteAllowsProceeding(t *testing.T) {
	srv := httptest.NewServer(evaluateHandler(t, sdkcitadel.OutcomeExecute, nil))
	defer srv.Close()

	gov := NewGovernanceClient(srv.URL)
	k := DeletionKerkese("community-0", uuid.New(), "actor", "verifier")

	proceed, reasons, err := gov.EvaluateDeletion(context.Background(), k)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !proceed {
		t.Errorf("expected proceed=true on EXECUTE, got false (reasons=%v)", reasons)
	}
}

// TestEvaluateDeletion_RefuseBlocksDeletion is the explicit regression test
// the task calls out: a bug here means a real GDPR violation risk (an
// account gets deleted despite MARSHAL saying no). REFUSE must genuinely
// block — proceed must be false.
func TestEvaluateDeletion_RefuseBlocksDeletion(t *testing.T) {
	srv := httptest.NewServer(evaluateHandler(t, sdkcitadel.OutcomeRefuse, []string{"policy violation"}))
	defer srv.Close()

	gov := NewGovernanceClient(srv.URL)
	k := DeletionKerkese("community-0", uuid.New(), "actor", "verifier")

	proceed, reasons, err := gov.EvaluateDeletion(context.Background(), k)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proceed {
		t.Fatal("REFUSE must block the deletion (proceed=false), got proceed=true")
	}
	if len(reasons) == 0 {
		t.Error("expected non-empty reasons on REFUSE")
	}
}

// TestEvaluateDeletion_HardStopBlocksDeletion is the same regression test as
// above but for HARD_STOP, CITADEL's more severe outcome.
func TestEvaluateDeletion_HardStopBlocksDeletion(t *testing.T) {
	srv := httptest.NewServer(evaluateHandler(t, sdkcitadel.OutcomeHardStop, []string{"NDS same-identity violation"}))
	defer srv.Close()

	gov := NewGovernanceClient(srv.URL)
	k := DeletionKerkese("community-0", uuid.New(), "actor", "verifier")

	proceed, reasons, err := gov.EvaluateDeletion(context.Background(), k)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proceed {
		t.Fatal("HARD_STOP must block the deletion (proceed=false), got proceed=true")
	}
	if len(reasons) == 0 {
		t.Error("expected non-empty reasons on HARD_STOP")
	}
}

// TestEvaluateDeletion_MissingReasonsGetsDefaultMessage ensures callers
// never see an empty reasons slice for a blocked deletion (writeJSON would
// otherwise render an empty error message).
func TestEvaluateDeletion_MissingReasonsGetsDefaultMessage(t *testing.T) {
	srv := httptest.NewServer(evaluateHandler(t, sdkcitadel.OutcomeRefuse, nil))
	defer srv.Close()

	gov := NewGovernanceClient(srv.URL)
	k := DeletionKerkese("community-0", uuid.New(), "actor", "verifier")

	proceed, reasons, _ := gov.EvaluateDeletion(context.Background(), k)
	if proceed {
		t.Fatal("expected proceed=false")
	}
	if len(reasons) == 0 {
		t.Error("expected a default reason to be populated when CITADEL returns none")
	}
}

// TestEvaluateDeletion_TransportErrorFailsClosed: an unreachable CITADEL
// must block a GDPR deletion by default, not let it proceed ungoverned.
// sdk/go/citadel.Client synthesizes a HARD_STOP Decision (FailMode =
// FailClosed, the zero value) when it can't be reached. err is still
// returned so the caller can log it even though proceed is false.
func TestEvaluateDeletion_TransportErrorFailsClosed(t *testing.T) {
	gov := NewGovernanceClient("http://127.0.0.1:0") // nothing listening
	k := DeletionKerkese("community-0", uuid.New(), "actor", "verifier")

	proceed, reasons, err := gov.EvaluateDeletion(context.Background(), k)
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if proceed {
		t.Error("expected fail-closed (proceed=false) on a transport error, got proceed=true")
	}
	if len(reasons) == 0 {
		t.Error("expected a human-readable reason even for a fail-closed synthetic decision")
	}
}
