package handlers_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// ---------------------------------------------------------------------------
// Register — validation-only cases (no DB required)
// ---------------------------------------------------------------------------

func TestRegister_MissingFields_Returns400(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]string
	}{
		{"empty username", map[string]string{"username": "", "email": "a@b.com", "password": "longenough"}},
		{"short username", map[string]string{"username": "ab", "email": "a@b.com", "password": "longenough"}},
		{"invalid email", map[string]string{"username": "validuser", "email": "notanemail", "password": "longenough"}},
		{"short password", map[string]string{"username": "validuser", "email": "a@b.com", "password": "short"}},
	}

	d := newDepsWithBadDB(t)
	d.Cfg = &config.Config{
		JWTSecret: "unit-test-secret",
		JWTIssuer: "test",
		TokenTTL:  3_600_000_000_000,
		Pepper:    "pepper",
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handlers.Register(d)(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRegister_InviteOnlyWithoutCode_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	d.Cfg = &config.Config{
		JWTSecret:  "unit-test-secret",
		JWTIssuer:  "test",
		TokenTTL:   3_600_000_000_000,
		Pepper:     "pepper",
		InviteOnly: true,
	}

	body, _ := json.Marshal(map[string]string{
		"username": "newuser",
		"email":    "new@example.com",
		"password": "strongpassword",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing invite code, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp["error"], "invite") {
		t.Errorf("expected invite-related error, got %q", resp["error"])
	}
}

func TestRegister_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{
		Cfg: &config.Config{},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte(`not json`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestRegister_AllowedEmailDomains_Rejected_Returns403(t *testing.T) {
	d := newDepsWithBadDB(t)
	d.Cfg = &config.Config{
		JWTSecret:           "unit-test-secret",
		JWTIssuer:           "test",
		TokenTTL:            3_600_000_000_000,
		Pepper:              "pepper",
		AllowedEmailDomains: []string{"company.internal"},
	}

	body, _ := json.Marshal(map[string]string{
		"username": "outsider",
		"email":    "user@gmail.com",
		"password": "strongpassword",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for disallowed email domain, got %d", w.Code)
	}
}
