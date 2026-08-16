package handlers_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
)

// testHash replicates the handler's internal sha256Hash so tests can produce
// matching hashes without access to the unexported package function.
func testHash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// loginPayload marshals username/password into a JSON reader.
func loginPayload(username, password string) *bytes.Reader {
	b, _ := json.Marshal(map[string]string{"username": username, "password": password})
	return bytes.NewReader(b)
}

// configUserDeps returns Deps pre-loaded with a single hardcoded config user.
// The config-user login branch issues a best-effort DB INSERT but still returns
// the token even if the INSERT fails, so we can use an unreachable pool here.
func configUserDeps(t *testing.T, username, password, role string) handlers.Deps {
	t.Helper()
	pepper := "test-pepper"
	hash := testHash(pepper + ":" + password)
	d := newDepsWithBadDB(t)
	d.Cfg = &config.Config{
		JWTSecret: "unit-test-secret",
		JWTIssuer: "test",
		TokenTTL:  3_600_000_000_000, // 1 hour in nanoseconds
		Pepper:    pepper,
		Users: []config.UserEntry{
			{Username: username, Role: role, Hash: hash},
		},
	}
	return d
}

// ---------------------------------------------------------------------------
// Login — config-user branch (no real DB required)
// ---------------------------------------------------------------------------

func TestLogin_ConfigUser_CorrectCredentials_Returns200WithToken(t *testing.T) {
	d := configUserDeps(t, "admin", "s3cr3tpass", "admin")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginPayload("admin", "s3cr3tpass"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.Login(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Token string `json:"token"`
		Role  string `json:"role"`
		Sub   string `json:"sub"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
	if resp.Role != "admin" {
		t.Errorf("expected role=admin, got %q", resp.Role)
	}
	if resp.Sub != "admin" {
		t.Errorf("expected sub=admin, got %q", resp.Sub)
	}
}

func TestLogin_ConfigUser_WrongPassword_Returns401(t *testing.T) {
	d := configUserDeps(t, "admin", "s3cr3tpass", "admin")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginPayload("admin", "wrongpassword"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.Login(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong password, got %d", w.Code)
	}
}

func TestLogin_UnknownUser_Returns401(t *testing.T) {
	// No config users and DB is unreachable — QueryRow.Scan will fail → 401.
	d := newDepsWithBadDB(t)
	d.Cfg = &config.Config{
		JWTSecret: "unit-test-secret",
		JWTIssuer: "test",
		TokenTTL:  3_600_000_000_000,
		Pepper:    "test-pepper",
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginPayload("nobody", "doesnotmatter"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.Login(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unknown user, got %d", w.Code)
	}
}

func TestLogin_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{
		Cfg: &config.Config{},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte(`{bad json}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.Login(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

// Register handler tests live in register_test.go (register.go is outside
// this pass's scope: oauth.go, oauth_sinauth.go, oauth_google.go, auth.go).
