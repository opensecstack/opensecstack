package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/opencsirt/internal/auth"
)

func testAuthenticator(t *testing.T) *auth.Authenticator {
	t.Helper()
	pepper := "test-pepper"
	pwHash := sha256.Sum256([]byte(pepper + ":secret"))
	users := "alice:admin:" + hex.EncodeToString(pwHash[:])
	a, err := auth.New([][]byte{[]byte(strings.Repeat("k", 32))}, "test", time.Hour, pepper, users)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

func TestAuthHandler_Login_Success(t *testing.T) {
	h := &Auth{Authenticator: testAuthenticator(t)}
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "secret"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["token"] == "" || resp["token"] == nil {
		t.Error("expected a non-empty token")
	}
	if resp["role"] != "admin" {
		t.Errorf("role = %v, want admin", resp["role"])
	}
}

func TestAuthHandler_Login_BadCredentials(t *testing.T) {
	h := &Auth{Authenticator: testAuthenticator(t)}
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_credentials") {
		t.Errorf("body = %s, want invalid_credentials", w.Body.String())
	}
}

func TestAuthHandler_Login_IssuerDisabled(t *testing.T) {
	a, err := auth.New([][]byte{[]byte(strings.Repeat("k", 32))}, "test", time.Hour, "p", "")
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	h := &Auth{Authenticator: a}
	body, _ := json.Marshal(map[string]string{"username": "nobody", "password": "x"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "issuer_disabled") {
		t.Errorf("body = %s, want issuer_disabled", w.Body.String())
	}
}

func TestAuthHandler_Login_MalformedBody(t *testing.T) {
	h := &Auth{Authenticator: testAuthenticator(t)}
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":`))
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}
