package customrules

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/modules"
)

// fakeExecutor is a minimal modules.HTTPExecutor stub for customrules tests.
type fakeExecutor struct {
	responses []*modules.HTTPResponse
	errs      []error
	idx       int
	calls     []*http.Request
}

func (f *fakeExecutor) Do(ctx context.Context, req *http.Request) (*modules.HTTPResponse, error) {
	f.calls = append(f.calls, req)
	if f.idx >= len(f.responses) {
		return &modules.HTTPResponse{StatusCode: 200, Headers: make(http.Header)}, nil
	}
	r := f.responses[f.idx]
	var err error
	if f.idx < len(f.errs) {
		err = f.errs[f.idx]
	}
	f.idx++
	return r, err
}

func fakeResp(code int, body string, headers ...string) *modules.HTTPResponse {
	h := make(http.Header)
	for i := 0; i+1 < len(headers); i += 2 {
		h.Set(headers[i], headers[i+1])
	}
	return &modules.HTTPResponse{StatusCode: code, Headers: h, Body: []byte(body), Duration: 10 * time.Millisecond}
}

// ---- ID / Name ----

func TestCustomRuleModule_IDAndName(t *testing.T) {
	rule := CustomRule{ID: "CR-001", Name: "Missing security header"}
	m := NewModule(rule)
	if m.ID() != "CR-001" {
		t.Errorf("ID() = %q, want CR-001", m.ID())
	}
	if m.Name() != "Missing security header" {
		t.Errorf("Name() = %q, want %q", m.Name(), "Missing security header")
	}
}

// ---- matchesTarget / matchesMethod ----

func TestMatchesTarget(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"*", "/anything", true},
		{"", "/anything", true},
		{"/api/users", "/api/users", true},
		{"/API/Users", "/api/users", true}, // case-insensitive
		{"/api/users", "/api/orders", false},
	}
	for _, tc := range tests {
		if got := matchesTarget(tc.pattern, tc.path); got != tc.want {
			t.Errorf("matchesTarget(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestMatchesMethod(t *testing.T) {
	tests := []struct {
		pattern, method string
		want            bool
	}{
		{"*", "GET", true},
		{"", "POST", true},
		{"GET", "GET", true},
		{"get", "GET", true}, // case-insensitive
		{"GET", "POST", false},
	}
	for _, tc := range tests {
		if got := matchesMethod(tc.pattern, tc.method); got != tc.want {
			t.Errorf("matchesMethod(%q, %q) = %v, want %v", tc.pattern, tc.method, got, tc.want)
		}
	}
}

// ---- parseSeverity ----

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want domain.Severity
	}{
		{"critical", domain.SeverityCritical},
		{"CRITICAL", domain.SeverityCritical},
		{"high", domain.SeverityHigh},
		{"medium", domain.SeverityMedium},
		{"low", domain.SeverityLow},
		{"info", domain.SeverityInfo},
		{"garbage", domain.SeverityInfo},
		{"", domain.SeverityInfo},
	}
	for _, tc := range tests {
		if got := parseSeverity(tc.in); got != tc.want {
			t.Errorf("parseSeverity(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// ---- applyAuth ----

func TestApplyAuth_Bearer(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	applyAuth(req, &modules.AuthConfig{Type: "bearer", Token: "tok123"})
	if got := req.Header.Get("Authorization"); got != "Bearer tok123" {
		t.Errorf("Authorization = %q, want Bearer tok123", got)
	}
}

func TestApplyAuth_APIKeyHeader(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	applyAuth(req, &modules.AuthConfig{Type: "apikey", APIKey: "key1", APIKeyName: "X-Api-Key", APIKeyIn: "header"})
	if got := req.Header.Get("X-Api-Key"); got != "key1" {
		t.Errorf("X-Api-Key = %q, want key1", got)
	}
}

func TestApplyAuth_APIKeyQuery(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/path", nil)
	applyAuth(req, &modules.AuthConfig{Type: "apikey", APIKey: "key1", APIKeyName: "api_key", APIKeyIn: "query"})
	if got := req.URL.Query().Get("api_key"); got != "key1" {
		t.Errorf("query api_key = %q, want key1", got)
	}
}

func TestApplyAuth_Basic(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	applyAuth(req, &modules.AuthConfig{Type: "basic", Username: "user", Password: "pass"})
	u, p, ok := req.BasicAuth()
	if !ok || u != "user" || p != "pass" {
		t.Errorf("BasicAuth() = (%q, %q, %v), want (user, pass, true)", u, p, ok)
	}
}

func TestApplyAuth_EmptyTokenNoHeader(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	applyAuth(req, &modules.AuthConfig{Type: "bearer", Token: ""})
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("expected no Authorization header, got %q", got)
	}
}

// ---- evaluate: each check type ----

func TestEvaluate_HeaderMissing_Triggers(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-1", Name: "n", Severity: "high"})
	check := Check{Type: "header_missing", Params: map[string]string{"header": "X-Frame-Options"}}
	resp := fakeResp(200, "")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	f, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true when header is missing")
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if f.ModuleID != "CR-1" {
		t.Errorf("ModuleID = %q, want CR-1", f.ModuleID)
	}
}

func TestEvaluate_HeaderMissing_DoesNotTrigger(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-1", Name: "n"})
	check := Check{Type: "header_missing", Params: map[string]string{"header": "X-Frame-Options"}}
	resp := fakeResp(200, "", "X-Frame-Options", "DENY")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if triggered {
		t.Fatal("expected triggered=false when header is present")
	}
}

func TestEvaluate_HeaderValue_TriggersOnMismatch(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-2", Name: "n"})
	check := Check{Type: "header_value", Params: map[string]string{"header": "Content-Type", "pattern": "^application/json$"}}
	resp := fakeResp(200, "", "Content-Type", "text/html")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true when header value does not match pattern")
	}
}

func TestEvaluate_HeaderValue_NoTriggerOnMatch(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-2", Name: "n"})
	check := Check{Type: "header_value", Params: map[string]string{"header": "Content-Type", "pattern": "^application/json$"}}
	resp := fakeResp(200, "", "Content-Type", "application/json")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if triggered {
		t.Fatal("expected triggered=false when header value matches pattern")
	}
}

func TestEvaluate_HeaderValue_InvalidPatternTriggers(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-2", Name: "n"})
	check := Check{Type: "header_value", Params: map[string]string{"header": "X", "pattern": "("}} // invalid regex
	resp := fakeResp(200, "", "X", "val")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true on invalid regex pattern (fail-safe)")
	}
}

func TestEvaluate_StatusCode_Triggers(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-3", Name: "n"})
	check := Check{Type: "status_code", Params: map[string]string{"expected": "401,403"}}
	resp := fakeResp(401, "")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true when status code is in expected list")
	}
}

func TestEvaluate_StatusCode_NoTrigger(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-3", Name: "n"})
	check := Check{Type: "status_code", Params: map[string]string{"expected": "401,403"}}
	resp := fakeResp(200, "")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if triggered {
		t.Fatal("expected triggered=false when status code is not in expected list")
	}
}

func TestEvaluate_ResponseBodyContains_Triggers(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-4", Name: "n"})
	check := Check{Type: "response_body_contains", Params: map[string]string{"text": "stack trace"}}
	resp := fakeResp(500, "internal error: stack trace follows")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true when body contains text")
	}
}

func TestEvaluate_ResponseBodyNotContains_Triggers(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-5", Name: "n"})
	check := Check{Type: "response_body_not_contains", Params: map[string]string{"text": "request_id"}}
	resp := fakeResp(200, `{"data":"ok"}`)
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true when required text is absent from body")
	}
}

func TestEvaluate_ResponseTimeExceeds_Triggers(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-6", Name: "n"})
	check := Check{Type: "response_time_exceeds", Params: map[string]string{"ms": "5"}}
	resp := fakeResp(200, "")
	resp.Duration = 50 * time.Millisecond
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true when response time exceeds threshold")
	}
}

func TestEvaluate_ResponseTimeExceeds_NoTrigger(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-6", Name: "n"})
	check := Check{Type: "response_time_exceeds", Params: map[string]string{"ms": "1000"}}
	resp := fakeResp(200, "")
	resp.Duration = 5 * time.Millisecond
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if triggered {
		t.Fatal("expected triggered=false when response time is within threshold")
	}
}

func TestEvaluate_UnknownCheckType_NeverTriggers(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-7", Name: "n"})
	check := Check{Type: "not_a_real_check_type"}
	resp := fakeResp(200, "")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	_, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if triggered {
		t.Fatal("expected triggered=false for unknown check type")
	}
}

func TestEvaluate_CustomMessageUsed(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-8", Name: "n"})
	check := Check{Type: "header_missing", Params: map[string]string{"header": "X"}, Message: "custom message here"}
	resp := fakeResp(200, "")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	f, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true")
	}
	if f.Description != "custom message here" {
		t.Errorf("Description = %q, want %q", f.Description, "custom message here")
	}
}

func TestEvaluate_DefaultMessageWhenEmpty(t *testing.T) {
	m := NewModule(CustomRule{ID: "CR-9", Name: "n"})
	check := Check{Type: "header_missing", Params: map[string]string{"header": "X"}}
	resp := fakeResp(200, "")
	tc := modules.TestCase{Method: "GET", Path: "/x"}

	f, triggered := m.evaluate(check, tc, "https://x/x", resp)
	if !triggered {
		t.Fatal("expected triggered=true")
	}
	if f.Description == "" {
		t.Error("expected a default description to be generated")
	}
}

// ---- Run ----

func TestRun_FindsMatchingEndpointAndReturnsFinding(t *testing.T) {
	rule := CustomRule{
		ID:   "CR-10",
		Name: "Missing header",
		Checks: []Check{
			{Type: "header_missing", Target: "*", Method: "*", Params: map[string]string{"header": "X-Frame-Options"}},
		},
	}
	m := NewModule(rule)
	exec := &fakeExecutor{responses: []*modules.HTTPResponse{fakeResp(200, "")}}
	suite := modules.TestSuite{Cases: []modules.TestCase{{Method: "GET", Path: "/api/x"}}}

	findings, err := m.Run(context.Background(), exec, suite, "https://target.example", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
}

func TestRun_NoMatchingTargetProducesNoFindings(t *testing.T) {
	rule := CustomRule{
		ID:   "CR-11",
		Name: "n",
		Checks: []Check{
			{Type: "header_missing", Target: "/only/this/path", Method: "*", Params: map[string]string{"header": "X"}},
		},
	}
	m := NewModule(rule)
	exec := &fakeExecutor{responses: []*modules.HTTPResponse{fakeResp(200, "")}}
	suite := modules.TestSuite{Cases: []modules.TestCase{{Method: "GET", Path: "/different/path"}}}

	findings, err := m.Run(context.Background(), exec, suite, "https://target.example", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestRun_ExecutorErrorSkipsCase(t *testing.T) {
	rule := CustomRule{
		ID:   "CR-12",
		Name: "n",
		Checks: []Check{
			{Type: "header_missing", Target: "*", Method: "*", Params: map[string]string{"header": "X"}},
		},
	}
	m := NewModule(rule)
	exec := &fakeExecutor{
		responses: []*modules.HTTPResponse{nil},
		errs:      []error{context.DeadlineExceeded},
	}
	suite := modules.TestSuite{Cases: []modules.TestCase{{Method: "GET", Path: "/x"}}}

	findings, err := m.Run(context.Background(), exec, suite, "https://target.example", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when the HTTP request itself fails, got %d", len(findings))
	}
}

func TestRun_ContextCancelledStopsEarly(t *testing.T) {
	rule := CustomRule{
		ID:   "CR-13",
		Name: "n",
		Checks: []Check{
			{Type: "header_missing", Target: "*", Method: "*", Params: map[string]string{"header": "X"}},
		},
	}
	m := NewModule(rule)
	exec := &fakeExecutor{responses: []*modules.HTTPResponse{fakeResp(200, "")}}
	suite := modules.TestSuite{Cases: []modules.TestCase{{Method: "GET", Path: "/x"}}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings, err := m.Run(ctx, exec, suite, "https://target.example", nil)
	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings when context is already cancelled, got %d", len(findings))
	}
}

func TestRun_StopsAfterFirstFindingPerCheck(t *testing.T) {
	rule := CustomRule{
		ID:   "CR-14",
		Name: "n",
		Checks: []Check{
			{Type: "header_missing", Target: "*", Method: "*", Params: map[string]string{"header": "X"}},
		},
	}
	m := NewModule(rule)
	// Two endpoints both missing the header; only the first should produce
	// a finding because the module breaks out after one hit per check.
	exec := &fakeExecutor{responses: []*modules.HTTPResponse{fakeResp(200, ""), fakeResp(200, "")}}
	suite := modules.TestSuite{Cases: []modules.TestCase{
		{Method: "GET", Path: "/a"},
		{Method: "GET", Path: "/b"},
	}}

	findings, err := m.Run(context.Background(), exec, suite, "https://target.example", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (stop after first hit), got %d", len(findings))
	}
}
