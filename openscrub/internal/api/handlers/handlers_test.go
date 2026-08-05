package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	sdkcitadel "github.com/opensecstack/sdk/go/citadel"

	"github.com/opensecstack/openscrub/internal/api"
	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/auth"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
)

func newTestServer(t *testing.T) (http.Handler, *rules.Service) {
	t.Helper()
	plane := dataplane.NewNoopClient()
	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: plane, NodeName: "test", Logger: zerolog.Nop(),
	})
	r := api.NewRouter(api.Deps{
		Health:   &handlers.Health{},
		Rules:    &handlers.Rules{Service: svc, Logger: zerolog.Nop()},
		Verifier: auth.NewHS256Verifier(nil, ""),
		DevMode:  true,
		Logger:   zerolog.Nop(),
	})
	return r, svc
}

func TestPostRulesCreatesAndGet(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(map[string]any{
		"type":        "blocklist",
		"cidr":        "203.0.113.0/24",
		"ttl_seconds": 3600,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d body=%s", rec.Code, rec.Body.String())
	}
	var created rules.Rule
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Type != rules.TypeBlocklist || created.CIDR != "203.0.113.0/24" {
		t.Fatalf("unexpected created: %+v", created)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+created.ID.String(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var list struct {
		Rules []rules.Rule `json:"rules"`
		Count int          `json:"count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if list.Count != 1 {
		t.Fatalf("count = %d", list.Count)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/rules/"+created.ID.String(), nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+created.ID.String(), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestPostRulesValidationFailure(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"type": "blocklist", "cidr": "not-cidr", "ttl_seconds": 60})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d want 400", rec.Code)
	}
}

func TestDeleteUnknownReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/rules/"+uuid.New().String(), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d want 404", rec.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var h map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &h)
	if _, ok := h["status"]; !ok {
		t.Fatal("missing status")
	}
}

// fakeGovernor is a stub CitadelGovernor recording every Kerkese it's
// asked to evaluate, so tests can assert on the Actor/Verifier shape
// the handler built without standing up a real CITADEL server.
type fakeGovernor struct {
	calls    []sdkcitadel.Kerkese
	decision *sdkcitadel.Decision
	err      error
}

func (f *fakeGovernor) Evaluate(_ context.Context, k sdkcitadel.Kerkese) (*sdkcitadel.Decision, error) {
	f.calls = append(f.calls, k)
	return f.decision, f.err
}

func newRulesHandlerForGovernanceTest(gov handlers.CitadelGovernor) (*handlers.Rules, *rules.Service) {
	plane := dataplane.NewNoopClient()
	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: plane, NodeName: "test", Logger: zerolog.Nop(),
	})
	return &handlers.Rules{
		Service:          svc,
		Logger:           zerolog.Nop(),
		Citadel:          gov,
		CitadelProjectID: "openscrub-test",
	}, svc
}

// TestRulesCreateGovernanceBuildsRealActorAndPlaceholderVerifier is the
// core regression guard for the manual-insertion Kerkese shape: Actor
// must carry the real authenticated caller's sinauth sub + bearer
// token, and Verifier must be the documented, non-colliding system
// placeholder with an empty token.
func TestRulesCreateGovernanceBuildsRealActorAndPlaceholderVerifier(t *testing.T) {
	gov := &fakeGovernor{decision: &sdkcitadel.Decision{Outcome: sdkcitadel.OutcomeExecute}}
	h, _ := newRulesHandlerForGovernanceTest(gov)

	body, _ := json.Marshal(map[string]any{"type": "blocklist", "cidr": "203.0.113.0/24", "ttl_seconds": 3600})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer real-operator-token")
	realUserID := "11111111-1111-1111-1111-111111111111"
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{Sub: realUserID, Role: auth.RoleOperator}))

	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(gov.calls) != 1 {
		t.Fatalf("expected exactly 1 CITADEL evaluate call, got %d", len(gov.calls))
	}
	k := gov.calls[0]
	if k.Actor.UserID != realUserID {
		t.Fatalf("actor.user_id = %q, want real caller id %q", k.Actor.UserID, realUserID)
	}
	if k.ActorToken != "real-operator-token" {
		t.Fatalf("actor_token = %q, want forwarded bearer token", k.ActorToken)
	}
	if k.Verifier.UserID != "openscrub-system-verifier" {
		t.Fatalf("verifier.user_id = %q, want documented placeholder", k.Verifier.UserID)
	}
	if k.VerifierToken != "" {
		t.Fatalf("verifier_token = %q, want empty (no real approver flow)", k.VerifierToken)
	}
	if k.Actor.UserID == k.Verifier.UserID {
		t.Fatal("actor and verifier identity must never collide (NDS)")
	}
	if k.SigOperator != "" || k.SigVerifier != "" {
		t.Fatal("sig_operator/sig_verifier must be left empty (no key custody UX yet)")
	}
	if k.ProjectID != "openscrub-test" {
		t.Fatalf("project_id = %q", k.ProjectID)
	}
}

// TestRulesCreateBlockedOnRefuse asserts a REFUSE decision surfaces as
// 403 with the reasons AND that the rule is never installed.
func TestRulesCreateBlockedOnRefuse(t *testing.T) {
	gov := &fakeGovernor{decision: &sdkcitadel.Decision{
		Outcome: sdkcitadel.OutcomeRefuse,
		Reasons: []string{"NDS same-identity violation"},
	}}
	h, svc := newRulesHandlerForGovernanceTest(gov)

	body, _ := json.Marshal(map[string]any{"type": "blocklist", "cidr": "203.0.113.0/24", "ttl_seconds": 3600})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{Sub: "op-1", Role: auth.RoleOperator}))

	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("NDS same-identity violation")) {
		t.Fatalf("expected reason in response body, got %s", rec.Body.String())
	}
	list, err := svc.List(context.Background(), "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("REFUSE must block installation — got %d rules installed", len(list))
	}
}

// TestRulesCreateBlockedOnHardStop mirrors the REFUSE case for
// HARD_STOP.
func TestRulesCreateBlockedOnHardStop(t *testing.T) {
	gov := &fakeGovernor{decision: &sdkcitadel.Decision{
		Outcome: sdkcitadel.OutcomeHardStop,
		Reasons: []string{"emergency freeze active"},
	}}
	h, svc := newRulesHandlerForGovernanceTest(gov)

	body, _ := json.Marshal(map[string]any{"type": "blocklist", "cidr": "198.51.100.0/24", "ttl_seconds": 60})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{Sub: "op-1", Role: auth.RoleOperator}))

	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	list, _ := svc.List(context.Background(), "", 10, 0)
	if len(list) != 0 {
		t.Fatalf("HARD_STOP must block installation — got %d rules installed", len(list))
	}
}

// TestRulesCreateFailsClosedOnCitadelUnreachable: a CITADEL outage must
// block mitigation rule creation by default — sdk/go/citadel.Client now
// synthesizes a HARD_STOP Decision (FailMode = FailClosed, the zero
// value) when it can't be reached, rather than the caller silently
// treating "couldn't evaluate" as "allowed."
func TestRulesCreateFailsClosedOnCitadelUnreachable(t *testing.T) {
	gov := &fakeGovernor{err: errors.New("dial tcp: connection refused")}
	h, svc := newRulesHandlerForGovernanceTest(gov)

	body, _ := json.Marshal(map[string]any{"type": "blocklist", "cidr": "203.0.113.0/24", "ttl_seconds": 3600})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{Sub: "op-1", Role: auth.RoleOperator}))

	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected fail-closed 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	list, _ := svc.List(context.Background(), "", 10, 0)
	if len(list) != 0 {
		t.Fatalf("expected no rule installed when CITADEL is unreachable (fail-closed), got %d", len(list))
	}
}

// TestRulesCreateSourceCannotBypassGovernance guards against an
// operator spoofing req.Source to dodge the gate: every request through
// this HTTP handler must be evaluated regardless of the claimed source.
func TestRulesCreateSourceCannotBypassGovernance(t *testing.T) {
	gov := &fakeGovernor{decision: &sdkcitadel.Decision{Outcome: sdkcitadel.OutcomeRefuse, Reasons: []string{"blocked"}}}
	h, _ := newRulesHandlerForGovernanceTest(gov)

	body, _ := json.Marshal(map[string]any{
		"type": "blocklist", "cidr": "203.0.113.0/24", "ttl_seconds": 3600, "source": "threatflow",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{Sub: "op-1", Role: auth.RoleOperator}))

	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if len(gov.calls) != 1 {
		t.Fatalf("expected the governance gate to still run when source is spoofed, got %d calls", len(gov.calls))
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (gate still enforced), got %d", rec.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("openscrub_rules_total")) {
		t.Fatal("metrics body missing openscrub_rules_total")
	}
}
