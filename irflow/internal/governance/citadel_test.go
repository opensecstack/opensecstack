package governance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

func TestCitadel_EvaluateSuccessMapsDecision(t *testing.T) {
	var captured kerkese
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/marshal/evaluate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Citadel-Signature") == "" {
			t.Error("X-Citadel-Signature header missing")
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"outcome":"EXECUTE","worm_entry_id":"wentry-7","reasons":["all gates passed"]}`))
	}))
	defer srv.Close()

	c := NewCitadelClient(CitadelClientConfig{
		BaseURL:   srv.URL,
		KeyID:     "kid-1",
		KeySecret: "topsecret",
		ProjectID: "proj-a",
	})

	res, err := c.Evaluate(context.Background(), incident.MarshalRequest{
		IncidentID: "inc-9",
		ActionType: "contain",
		OperatorID: "alice",
		VerifierID: "bob",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != "EXECUTE" {
		t.Errorf("outcome = %s, want EXECUTE", res.Outcome)
	}
	if res.WORMEntryID != "wentry-7" {
		t.Errorf("worm_entry_id = %s, want wentry-7", res.WORMEntryID)
	}
	if captured.Action.IncidentID != "inc-9" {
		t.Errorf("kerkese did not embed incident id: %s", captured.Action.IncidentID)
	}
	if captured.ProjectID != "proj-a" {
		t.Errorf("project_id = %s, want proj-a", captured.ProjectID)
	}
	if captured.SoD.OperatorUserID == captured.SoD.VerifierUserID {
		t.Error("operator and verifier hashed to same ID — SoD would be bypassed")
	}
}

func TestCitadel_EvaluateHardStopIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"outcome":"HARD_STOP","reasons":["emergency freeze active"]}`))
	}))
	defer srv.Close()

	c := NewCitadelClient(CitadelClientConfig{BaseURL: srv.URL, KeySecret: "x"})
	res, err := c.Evaluate(context.Background(), incident.MarshalRequest{ActionType: "deploy"})
	if err != nil {
		t.Fatalf("HARD_STOP should be returned as a decision, not an error; got %v", err)
	}
	if res.Outcome != "HARD_STOP" {
		t.Errorf("outcome = %s, want HARD_STOP", res.Outcome)
	}
}

func TestCitadel_Evaluate500IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`oops`))
	}))
	defer srv.Close()

	c := NewCitadelClient(CitadelClientConfig{BaseURL: srv.URL, KeySecret: "x"})
	if _, err := c.Evaluate(context.Background(), incident.MarshalRequest{}); err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

func TestCitadel_EmitSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/worm/emit" {
			t.Fatalf("path = %s, want /api/v1/worm/emit", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"source":"irflow"`) {
			t.Errorf("source not set in body: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"worm_entry_id":"w1","chain_hash":"ch","prev_hash":"ph","sequence_num":42}`))
	}))
	defer srv.Close()

	c := NewCitadelClient(CitadelClientConfig{BaseURL: srv.URL, KeySecret: "s", ProjectID: "p"})
	receipt, err := c.Emit(context.Background(), incident.WORMEvent{
		Source:    "irflow",
		EventType: "incident.created",
		Payload:   json.RawMessage(`{"id":"inc-1"}`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receipt.WORMEntryID != "w1" || receipt.SequenceNum != 42 {
		t.Errorf("receipt = %+v, want {w1, seq 42}", receipt)
	}
}

func TestCitadel_NoBaseURLFailsClosed(t *testing.T) {
	c := NewCitadelClient(CitadelClientConfig{KeySecret: "x"})
	if _, err := c.Evaluate(context.Background(), incident.MarshalRequest{}); err == nil {
		t.Fatal("expected error when BaseURL empty")
	}
}

func TestSign_Deterministic(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	a := sign("secret", body)
	b := sign("secret", body)
	if a != b {
		t.Errorf("sign is non-deterministic: %s vs %s", a, b)
	}
	if sign("different", body) == a {
		t.Error("signing with different secrets produced the same signature")
	}
}

func TestHashUserID_StableAndDifferentForDifferentInputs(t *testing.T) {
	// Materialise both calls so staticcheck (SA4000) doesn't flag the
	// determinism check as an identical-both-sides compare — the *point* is
	// that independent invocations produce the same value.
	a1 := hashUserID("alice")
	a2 := hashUserID("alice")
	if a1 != a2 {
		t.Error("hashUserID is not deterministic")
	}
	if hashUserID("alice") == hashUserID("bob") {
		t.Error("alice and bob hashed to the same ID — SoD would be bypassed")
	}
	if hashUserID("") != 0 {
		t.Errorf("empty input should hash to 0, got %d", hashUserID(""))
	}
}

func TestNewUUIDv4_SyntacticallyValid(t *testing.T) {
	id := newUUIDv4()
	if len(id) != 36 {
		t.Fatalf("len = %d, want 36", len(id))
	}
	// version nibble at position 14 must be '4'
	if id[14] != '4' {
		t.Errorf("version nibble = %c, want 4", id[14])
	}
	// variant nibble at position 19 must be one of 8, 9, a, b
	v := id[19]
	if v != '8' && v != '9' && v != 'a' && v != 'b' {
		t.Errorf("variant nibble = %c, want 8/9/a/b", v)
	}
}
