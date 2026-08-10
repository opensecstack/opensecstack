package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/integrations/meetings"
)

func newMeetingsHandler(platforms []meetings.PlatformConfig) *MeetingsHandler {
	return NewMeetingsHandler(platforms, "https://vertguard.example.com", zerolog.Nop())
}

// withPlatformParam wraps a request with a chi route context carrying a
// {platform} URL param, matching how the router injects it in production.
func withPlatformParam(r *http.Request, platform string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("platform", platform)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// ─── Connect ────────────────────────────────────────────────────────

func TestConnect_UnknownPlatform_Returns404(t *testing.T) {
	h := newMeetingsHandler(nil)
	r := withPlatformParam(httptest.NewRequest(http.MethodGet, "/connect/zoom", nil), "zoom")
	w := httptest.NewRecorder()
	h.Connect(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestConnect_DisabledPlatform_Returns503(t *testing.T) {
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformZoom, Enabled: false},
	})
	r := withPlatformParam(httptest.NewRequest(http.MethodGet, "/connect/zoom", nil), "zoom")
	w := httptest.NewRecorder()
	h.Connect(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestConnect_EnabledPlatform_RedirectsWithState(t *testing.T) {
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformZoom, Enabled: true, ClientID: "zoom-client-id"},
	})
	r := withPlatformParam(httptest.NewRequest(http.MethodGet, "/connect/zoom", nil), "zoom")
	w := httptest.NewRecorder()
	h.Connect(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d body=%s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://zoom.us/oauth/authorize") {
		t.Errorf("Location = %q, want zoom authorize base", loc)
	}
	if !strings.Contains(loc, "client_id=zoom-client-id") {
		t.Errorf("Location missing client_id: %s", loc)
	}
	// A state nonce must have been recorded so the callback can validate it.
	h.stateMu.Lock()
	n := len(h.states)
	h.stateMu.Unlock()
	if n != 1 {
		t.Errorf("states recorded = %d, want 1", n)
	}
}

// ─── Callback ───────────────────────────────────────────────────────

func TestCallback_OAuthErrorParam_Returns400(t *testing.T) {
	h := newMeetingsHandler(nil)
	r := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied", nil)
	w := httptest.NewRecorder()
	h.Callback(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestCallback_MissingParams_Returns400(t *testing.T) {
	h := newMeetingsHandler(nil)
	r := httptest.NewRequest(http.MethodGet, "/callback", nil)
	w := httptest.NewRecorder()
	h.Callback(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "missing_params" {
		t.Errorf("code = %q, want missing_params", resp["code"])
	}
}

// TestCallback_UnknownState_Returns400 is the critical CSRF guard: a
// state nonce that was never issued by Connect (or was already
// consumed) must never be accepted.
func TestCallback_UnknownState_Returns400(t *testing.T) {
	h := newMeetingsHandler(nil)
	r := httptest.NewRequest(http.MethodGet, "/callback?state=forged-nonce&code=abc", nil)
	w := httptest.NewRecorder()
	h.Callback(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "invalid_state" {
		t.Errorf("code = %q, want invalid_state", resp["code"])
	}
}

// TestCallback_ValidState_ConsumedOnce verifies a state nonce is
// single-use: replaying the same callback twice must fail the second
// time (classic CSRF/replay protection).
func TestCallback_ValidState_ConsumedOnce(t *testing.T) {
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformZoom, Enabled: true, ClientID: "zoom-client-id"},
	})

	// Drive Connect to mint a real state nonce.
	connReq := withPlatformParam(httptest.NewRequest(http.MethodGet, "/connect/zoom", nil), "zoom")
	connW := httptest.NewRecorder()
	h.Connect(connW, connReq)
	loc := connW.Header().Get("Location")
	stateIdx := strings.Index(loc, "state=")
	if stateIdx == -1 {
		t.Fatalf("no state param in redirect: %s", loc)
	}
	state := loc[stateIdx+len("state="):]
	if amp := strings.Index(state, "&"); amp != -1 {
		state = state[:amp]
	}

	// First callback: state is known → token exchange path (501, not 400).
	r1 := httptest.NewRequest(http.MethodGet, "/callback?state="+state+"&code=abc123", nil)
	w1 := httptest.NewRecorder()
	h.Callback(w1, r1)
	if w1.Code != http.StatusNotImplemented {
		t.Fatalf("first callback: want 501 (sdk not provisioned), got %d body=%s", w1.Code, w1.Body.String())
	}

	// Second callback with the same state must be rejected — it was consumed.
	r2 := httptest.NewRequest(http.MethodGet, "/callback?state="+state+"&code=abc123", nil)
	w2 := httptest.NewRecorder()
	h.Callback(w2, r2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback: want 400 (state already consumed), got %d body=%s", w2.Code, w2.Body.String())
	}
}

// ─── Webhook ────────────────────────────────────────────────────────

func TestWebhook_UnknownPlatform_Returns404(t *testing.T) {
	h := newMeetingsHandler(nil)
	r := withPlatformParam(httptest.NewRequest(http.MethodPost, "/webhook/zoom", strings.NewReader("{}")), "zoom")
	w := httptest.NewRecorder()
	h.Webhook(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestWebhook_BadSignature_Returns401(t *testing.T) {
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformWebEx, Enabled: true, WebhookSecret: "real-secret"},
	})
	body := `{"resource":"meetings","event":"started","data":{"meetingId":"m1"}}`
	r := withPlatformParam(httptest.NewRequest(http.MethodPost, "/webhook/webex", strings.NewReader(body)), "webex")
	r.Header.Set("X-Spark-Signature", "0000000000000000000000000000000000000000000000000000000000000000")
	w := httptest.NewRecorder()
	h.Webhook(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for a forged webhook signature, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhook_ValidSignature_Returns200(t *testing.T) {
	secret := "real-secret"
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformWebEx, Enabled: true, WebhookSecret: secret},
	})
	body := []byte(`{"resource":"meetings","event":"started","data":{"meetingId":"m1","personId":"p1"}}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	r := withPlatformParam(httptest.NewRequest(http.MethodPost, "/webhook/webex", strings.NewReader(string(body))), "webex")
	r.Header.Set("X-Spark-Signature", sig)
	w := httptest.NewRecorder()
	h.Webhook(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestWebhook_NoCredentialConfigured_SkipsAuth documents the deliberate
// dev-mode fail-open: when no webhook secret is configured for the
// platform, signature validation is skipped (logged as a warning)
// rather than rejecting every request outright.
func TestWebhook_NoCredentialConfigured_SkipsAuth(t *testing.T) {
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformWebEx, Enabled: true}, // WebhookSecret empty
	})
	body := `{"resource":"meetings","event":"started","data":{"meetingId":"m1"}}`
	r := withPlatformParam(httptest.NewRequest(http.MethodPost, "/webhook/webex", strings.NewReader(body)), "webex")
	w := httptest.NewRecorder()
	h.Webhook(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (dev-mode skip), got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhook_MalformedBody_Returns400(t *testing.T) {
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformWebEx, Enabled: true}, // no secret → auth skipped, parse still enforced
	})
	r := withPlatformParam(httptest.NewRequest(http.MethodPost, "/webhook/webex", strings.NewReader("not json")), "webex")
	w := httptest.NewRecorder()
	h.Webhook(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhook_OversizedBody_Returns413(t *testing.T) {
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformWebEx, Enabled: true},
	})
	oversized := strings.Repeat("a", meetingsMaxBodyBytes+100)
	r := withPlatformParam(httptest.NewRequest(http.MethodPost, "/webhook/webex", strings.NewReader(oversized)), "webex")
	w := httptest.NewRecorder()
	h.Webhook(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d body=%s", w.Code, w.Body.String())
	}
}

// ─── Status ─────────────────────────────────────────────────────────

func TestStatus_ReportsAllKnownPlatforms(t *testing.T) {
	h := newMeetingsHandler([]meetings.PlatformConfig{
		{Platform: meetings.PlatformZoom, Enabled: true, ClientID: "id", ClientSecret: "secret"},
	})
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	h.Status(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		Platforms []struct {
			Name            string `json:"name"`
			Enabled         bool   `json:"enabled"`
			OAuthConfigured bool   `json:"oauth_configured"`
		} `json:"platforms"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Platforms) != 3 {
		t.Fatalf("platforms count = %d, want 3 (zoom, teams, webex)", len(resp.Platforms))
	}
	seen := map[string]struct {
		Enabled         bool
		OAuthConfigured bool
	}{}
	for _, p := range resp.Platforms {
		seen[p.Name] = struct {
			Enabled         bool
			OAuthConfigured bool
		}{p.Enabled, p.OAuthConfigured}
	}
	if !seen["zoom"].Enabled || !seen["zoom"].OAuthConfigured {
		t.Errorf("zoom status = %+v, want enabled+oauth_configured", seen["zoom"])
	}
	if seen["teams"].Enabled || seen["teams"].OAuthConfigured {
		t.Errorf("teams status = %+v, want disabled+unconfigured (never wired)", seen["teams"])
	}
}

// ─── generateState / min8 ───────────────────────────────────────────

func TestGenerateState_ProducesDistinctHex(t *testing.T) {
	a, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	b, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	if a == b {
		t.Error("two calls to generateState produced the same nonce")
	}
	if len(a) != 64 { // 32 bytes hex-encoded
		t.Errorf("len(state) = %d, want 64", len(a))
	}
}

func TestMin8(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"12345678", 8},
		{"123456789", 8},
	}
	for _, tc := range tests {
		if got := min8(tc.in); got != tc.want {
			t.Errorf("min8(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
