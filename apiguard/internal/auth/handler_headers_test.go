package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUpdateToken(t *testing.T) {
	h, err := NewHandler(Config{Type: TokenTypeBearer, Token: "old-token"}, []byte("secret"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h.UpdateToken("new-token")

	got := h.GetConfig()
	if got.Token != "new-token" {
		t.Errorf("Token after UpdateToken = %q, want new-token", got.Token)
	}
}

func TestHeaders_Bearer(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenTypeBearer, Token: "abc123"}, []byte("secret"))
	headers := h.Headers()
	if headers["Authorization"] != "Bearer abc123" {
		t.Errorf("Authorization = %q, want %q", headers["Authorization"], "Bearer abc123")
	}
}

func TestHeaders_BearerEmptyToken(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenTypeBearer, Token: ""}, []byte("secret"))
	headers := h.Headers()
	if _, ok := headers["Authorization"]; ok {
		t.Errorf("expected no Authorization header for empty token, got %q", headers["Authorization"])
	}
}

func TestHeaders_JWTAndOAuth2UseBearerScheme(t *testing.T) {
	for _, typ := range []TokenType{TokenTypeJWT, TokenTypeOAuth2} {
		h, _ := NewHandler(Config{Type: typ, Token: "tok"}, []byte("secret"))
		headers := h.Headers()
		if headers["Authorization"] != "Bearer tok" {
			t.Errorf("type %s: Authorization = %q, want %q", typ, headers["Authorization"], "Bearer tok")
		}
	}
}

func TestHeaders_APIKeyHeaderDefaultName(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenTypeAPIKey, APIKey: "key-val", APIKeyIn: "header"}, []byte("secret"))
	headers := h.Headers()
	if headers["X-API-Key"] != "key-val" {
		t.Errorf("X-API-Key = %q, want key-val", headers["X-API-Key"])
	}
}

func TestHeaders_APIKeyHeaderCustomName(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenTypeAPIKey, APIKey: "key-val", APIKeyIn: "header", APIKeyName: "X-Custom"}, []byte("secret"))
	headers := h.Headers()
	if headers["X-Custom"] != "key-val" {
		t.Errorf("X-Custom = %q, want key-val", headers["X-Custom"])
	}
	if _, ok := headers["X-API-Key"]; ok {
		t.Error("expected default header name not to be set when custom name is provided")
	}
}

func TestHeaders_APIKeyInQueryProducesNoHeader(t *testing.T) {
	// APIKeyIn="query" means the key belongs in the URL, not headers.
	h, _ := NewHandler(Config{Type: TokenTypeAPIKey, APIKey: "key-val", APIKeyIn: "query"}, []byte("secret"))
	headers := h.Headers()
	if len(headers) != 0 {
		t.Errorf("expected no headers for query-based API key, got %v", headers)
	}
}

func TestHeaders_APIKeyEmptyKeyProducesNoHeader(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenTypeAPIKey, APIKey: "", APIKeyIn: "header"}, []byte("secret"))
	headers := h.Headers()
	if len(headers) != 0 {
		t.Errorf("expected no headers for empty API key, got %v", headers)
	}
}

func TestHeaders_APIKeyInCaseInsensitive(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenTypeAPIKey, APIKey: "key-val", APIKeyIn: "HEADER"}, []byte("secret"))
	headers := h.Headers()
	if headers["X-API-Key"] != "key-val" {
		t.Errorf("expected APIKeyIn to be matched case-insensitively, headers = %v", headers)
	}
}

func TestHeaders_Basic(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenTypeBasic, Username: "alice", Password: "wonderland"}, []byte("secret"))
	headers := h.Headers()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wonderland"))
	if headers["Authorization"] != want {
		t.Errorf("Authorization = %q, want %q", headers["Authorization"], want)
	}
}

func TestHeaders_BasicEmptyUsernameProducesNoHeader(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenTypeBasic, Username: "", Password: "x"}, []byte("secret"))
	headers := h.Headers()
	if len(headers) != 0 {
		t.Errorf("expected no headers for empty username, got %v", headers)
	}
}

func TestHeaders_UnknownTypeProducesNoHeaders(t *testing.T) {
	h, _ := NewHandler(Config{Type: TokenType("unknown")}, []byte("secret"))
	headers := h.Headers()
	if len(headers) != 0 {
		t.Errorf("expected no headers for unknown token type, got %v", headers)
	}
}

// ---- GenerateExpiredToken ----

func TestGenerateExpiredToken(t *testing.T) {
	h, err := NewHandler(Config{}, []byte("secret-for-signing"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := h.GenerateExpiredToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload.Exp != 1 {
		t.Errorf("Exp = %d, want 1 (Unix epoch, always expired)", payload.Exp)
	}
	if payload.Sub != "apiguard-expiry-test" {
		t.Errorf("Sub = %q, want apiguard-expiry-test", payload.Sub)
	}
}

// ---- GenerateOtherUserToken with empty subject ----

func TestGenerateOtherUserToken_EmptySubjectGetsRandomID(t *testing.T) {
	h, err := NewHandler(Config{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := h.GenerateOtherUserToken("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parts := strings.Split(token, ".")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if !strings.HasPrefix(payload.Sub, "apiguard-other-user-") {
		t.Errorf("Sub = %q, want prefix apiguard-other-user-", payload.Sub)
	}

	now := time.Now().Unix()
	if payload.Exp <= now {
		t.Errorf("Exp = %d, want a future timestamp (> %d)", payload.Exp, now)
	}
}

// ---- GenerateInvalidToken ----

func TestGenerateInvalidToken(t *testing.T) {
	h, err := NewHandler(Config{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token := h.GenerateInvalidToken()
	if !strings.HasPrefix(token, "invalid.garbage.apiguard-test.") {
		t.Errorf("token = %q, want prefix invalid.garbage.apiguard-test.", token)
	}
	// A structurally valid JWT is exactly 3 dot-separated segments;
	// this generator is documented to produce a syntactically invalid token.
	if len(strings.Split(token, ".")) == 3 {
		t.Errorf("token %q should not look like a well-formed 3-segment JWT", token)
	}
}

// ---- GenerateNoAuthConfig ----

func TestGenerateNoAuthConfig(t *testing.T) {
	h, err := NewHandler(Config{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := h.GenerateNoAuthConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Type != "" || cfg.Token != "" || cfg.APIKey != "" || cfg.Username != "" {
		t.Errorf("expected a zero-value Config, got %+v", cfg)
	}
}
