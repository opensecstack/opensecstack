package citadel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEvaluate_RefuseReturnsDecisionNotError is a regression test: CITADEL
// returns HTTP 403 for REFUSE/HARD_STOP outcomes with a well-formed Decision
// body — that must come back as a parsed *Decision, not a generic error,
// or callers can never see Decision.Reasons to explain why an action was
// blocked. (Found via a real consumer during the openscrub/opencsirt/
// cyberpath/community CITADEL-integration rollout — every one of them
// needed Reasons on a REFUSE/HARD_STOP.)
func TestEvaluate_RefuseReturnsDecisionNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(Decision{
			Outcome: OutcomeRefuse,
			Reasons: []string{"AUTHZ_FAIL: role \"viewer\" is not permitted to perform \"CONFIG_CHANGE\""},
			Gates:   []GateResult{{Gate: 2, Name: "AuthZ", Status: "FAIL"}},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	decision, err := c.Evaluate(context.Background(), Kerkese{})
	if err != nil {
		t.Fatalf("Evaluate returned an error for a well-formed REFUSE decision: %v", err)
	}
	if decision.Outcome != OutcomeRefuse {
		t.Errorf("Outcome = %q, want %q", decision.Outcome, OutcomeRefuse)
	}
	if len(decision.Reasons) == 0 || decision.Reasons[0] == "" {
		t.Error("Decision.Reasons must be populated so callers can surface why the action was blocked")
	}
}

func TestEvaluate_HardStopReturnsDecisionNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(Decision{
			Outcome: OutcomeHardStop,
			Reasons: []string{"NDS_SAME_IDENTITY: operator and verifier are the same user"},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	decision, err := c.Evaluate(context.Background(), Kerkese{})
	if err != nil {
		t.Fatalf("Evaluate returned an error for a well-formed HARD_STOP decision: %v", err)
	}
	if decision.Outcome != OutcomeHardStop {
		t.Errorf("Outcome = %q, want %q", decision.Outcome, OutcomeHardStop)
	}
}

func TestEvaluate_ServerErrorWithoutDecisionBodyIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	if _, err := c.Evaluate(context.Background(), Kerkese{}); err == nil {
		t.Error("Evaluate should return an error for a genuine 500 with no Decision body")
	}
}

func TestEvaluate_UnreachableDefaultsToFailClosed(t *testing.T) {
	// Port 1 is reserved and nothing listens there — a reliable, fast way
	// to force a transport failure without a flaky timeout-based test.
	c := NewClient("http://127.0.0.1:1", nil)
	decision, err := c.Evaluate(context.Background(), Kerkese{})
	if err == nil {
		t.Fatal("expected a transport error for an unreachable CITADEL")
	}
	if decision == nil {
		t.Fatal("Evaluate must return a non-nil Decision even on transport failure")
	}
	if decision.Outcome != OutcomeHardStop {
		t.Errorf("Outcome = %q, want %q (FailClosed is the zero-value default)", decision.Outcome, OutcomeHardStop)
	}
	if decision.Allowed() {
		t.Error("a fail-closed synthetic Decision must not be Allowed()")
	}
}

func TestEvaluate_FailOpenReturnsExecuteOnUnreachable(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", nil)
	c.FailMode = FailOpen
	decision, err := c.Evaluate(context.Background(), Kerkese{})
	if err == nil {
		t.Fatal("expected a transport error for an unreachable CITADEL")
	}
	if decision == nil || decision.Outcome != OutcomeExecute {
		t.Errorf("Outcome = %v, want %q with FailMode = FailOpen", decision, OutcomeExecute)
	}
	if !decision.Allowed() {
		t.Error("a fail-open synthetic Decision must be Allowed()")
	}
}

func TestDecision_Allowed(t *testing.T) {
	cases := []struct {
		outcome string
		want    bool
	}{
		{OutcomeExecute, true},
		{OutcomeRefuse, false},
		{OutcomeHardStop, false},
		{"", false},
	}
	for _, tc := range cases {
		d := &Decision{Outcome: tc.outcome}
		if got := d.Allowed(); got != tc.want {
			t.Errorf("Decision{Outcome: %q}.Allowed() = %v, want %v", tc.outcome, got, tc.want)
		}
	}
	var nilDecision *Decision
	if nilDecision.Allowed() {
		t.Error("a nil Decision must not be Allowed()")
	}
}

func TestEvaluate_ExecuteReturnsDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(Decision{Outcome: OutcomeExecute})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	decision, err := c.Evaluate(context.Background(), Kerkese{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Outcome != OutcomeExecute {
		t.Errorf("Outcome = %q, want %q", decision.Outcome, OutcomeExecute)
	}
}
