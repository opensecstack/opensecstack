// Tests for the auth handlers. Lives in the handlers package because
// the handlers themselves live here; the brief in the auth bring-up
// asked for `internal/auth/handlers_test.go` but that would force a
// circular import (handlers -> auth, auth_test -> handlers).
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opensecstack/cyberpath/internal/auth"
)

// ── fakes ─────────────────────────────────────────────────────────

type fakeUserStore struct {
	mu      sync.Mutex
	byEmail map[string]*User
	byID    map[string]*User
}

func newFakeUserStore(users ...*User) *fakeUserStore {
	s := &fakeUserStore{
		byEmail: make(map[string]*User),
		byID:    make(map[string]*User),
	}
	for _, u := range users {
		s.byEmail[strings.ToLower(u.Email)] = u
		s.byID[u.ID] = u
	}
	return s
}

func (s *fakeUserStore) FindByEmail(_ context.Context, email string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *fakeUserStore) FindByID(_ context.Context, id string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *fakeUserStore) UpdatePasswordHash(_ context.Context, id, h string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byID[id]; ok {
		u.PasswordHash = h
		return nil
	}
	return ErrUserNotFound
}

type fakeAuthAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *fakeAuthAudit) Record(_ context.Context, ev AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

func (a *fakeAuthAudit) byAction(action string) []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditEvent
	for _, e := range a.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// ── helpers ───────────────────────────────────────────────────────

const testPepper = "0123456789abcdef0123456789abcdef" // >=16 bytes

func newTestHandlers(t *testing.T, store *fakeUserStore) (*AuthHandlers, *fakeAuthAudit, auth.SessionStore) {
	t.Helper()
	iss, err := auth.NewIssuer(auth.IssuerConfig{
		SigningKey: []byte("test-signing-key"),
		Issuer:     "cyberpath-test",
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	sessions := auth.NewMemorySessionStore()
	audit := &fakeAuthAudit{}
	h, err := NewAuthHandlers(AuthDeps{
		Users:    store,
		Sessions: sessions,
		Issuer:   iss,
		Audit:    audit,
		Pepper:   []byte(testPepper),
		LoginPad: time.Millisecond, // keep tests fast
	})
	if err != nil {
		t.Fatalf("handlers: %v", err)
	}
	return h, audit, sessions
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := auth.HashPassword(pw, []byte(testPepper))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}

func postJSON(h http.Handler, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// ── tests ─────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	user := &User{
		ID: "u1", TenantID: "t1", Email: "alice@example.test",
		DisplayName: "Alice", Locale: "sq", Role: "learner",
		PasswordHash: mustHash(t, "correct horse"),
	}
	h, audit, _ := newTestHandlers(t, newFakeUserStore(user))

	w := postJSON(h.Login(), "/auth/login", loginRequest{
		Email: "alice@example.test", Password: "correct horse",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", resp)
	}
	if resp.User == nil || resp.User.ID != "u1" {
		t.Fatalf("user payload = %+v", resp.User)
	}
	if got := audit.byAction("auth.token_issued"); len(got) != 1 {
		t.Fatalf("audit events = %d, want 1", len(got))
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	user := &User{
		ID: "u1", Email: "a@b.test", PasswordHash: mustHash(t, "right"),
	}
	h, _, _ := newTestHandlers(t, newFakeUserStore(user))
	w := postJSON(h.Login(), "/auth/login", loginRequest{
		Email: "a@b.test", Password: "wrong",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestLogin_MissingUser_ReturnsSameShape(t *testing.T) {
	h, _, _ := newTestHandlers(t, newFakeUserStore())
	w := postJSON(h.Login(), "/auth/login", loginRequest{
		Email: "ghost@example.test", Password: "anything",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", w.Code)
	}
	// Same envelope as wrong-password case.
	if !strings.Contains(w.Body.String(), "invalid_credentials") {
		t.Fatalf("body = %s", w.Body.String())
	}
}

func TestRefresh_HappyPath(t *testing.T) {
	user := &User{ID: "u1", Email: "a@b.test", Role: "learner",
		PasswordHash: mustHash(t, "pw")}
	h, _, _ := newTestHandlers(t, newFakeUserStore(user))

	// Login first to obtain a refresh.
	w := postJSON(h.Login(), "/auth/login", loginRequest{Email: "a@b.test", Password: "pw"})
	if w.Code != 200 {
		t.Fatalf("login: %d", w.Code)
	}
	var first tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &first)

	// Refresh.
	w2 := postJSON(h.Refresh(), "/auth/refresh", refreshRequest{RefreshToken: first.RefreshToken})
	if w2.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body=%s", w2.Code, w2.Body.String())
	}
	var second tokenResponse
	_ = json.Unmarshal(w2.Body.Bytes(), &second)
	if second.AccessToken == "" || second.RefreshToken == "" {
		t.Fatalf("missing tokens after refresh: %+v", second)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatalf("refresh token did not rotate")
	}
}

func TestRefresh_RevokedSession(t *testing.T) {
	user := &User{ID: "u1", Email: "a@b.test", PasswordHash: mustHash(t, "pw")}
	h, _, sessions := newTestHandlers(t, newFakeUserStore(user))

	w := postJSON(h.Login(), "/auth/login", loginRequest{Email: "a@b.test", Password: "pw"})
	var tok tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tok)

	// Revoke every session for this user.
	if err := sessions.RevokeAll(user.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	w2 := postJSON(h.Refresh(), "/auth/refresh", refreshRequest{RefreshToken: tok.RefreshToken})
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", w2.Code)
	}
}

func TestLogout_Idempotent(t *testing.T) {
	user := &User{ID: "u1", Email: "a@b.test", PasswordHash: mustHash(t, "pw")}
	h, _, _ := newTestHandlers(t, newFakeUserStore(user))

	w := postJSON(h.Login(), "/auth/login", loginRequest{Email: "a@b.test", Password: "pw"})
	var tok tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tok)

	for i := 0; i < 3; i++ {
		w2 := postJSON(h.Logout(), "/auth/logout", refreshRequest{RefreshToken: tok.RefreshToken})
		if w2.Code != http.StatusNoContent {
			t.Fatalf("iteration %d status = %d", i, w2.Code)
		}
	}
}

func TestLogin_ThrottlingKicksIn(t *testing.T) {
	user := &User{ID: "u1", Email: "a@b.test", PasswordHash: mustHash(t, "pw")}
	store := newFakeUserStore(user)
	iss, _ := auth.NewIssuer(auth.IssuerConfig{
		SigningKey: []byte("k"), Issuer: "test",
		AccessTTL: time.Hour, RefreshTTL: time.Hour,
	})
	h, err := NewAuthHandlers(AuthDeps{
		Users:    store,
		Sessions: auth.NewMemorySessionStore(),
		Issuer:   iss,
		Pepper:   []byte(testPepper),
		LoginPad: time.Millisecond,
		Throttle: NewLoginThrottle(3, time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Three failures push count to the threshold.
	for i := 0; i < 3; i++ {
		w := postJSON(h.Login(), "/auth/login", loginRequest{
			Email: "a@b.test", Password: "wrong",
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("iter %d status = %d", i, w.Code)
		}
	}
	// Next attempt: throttled.
	w := postJSON(h.Login(), "/auth/login", loginRequest{
		Email: "a@b.test", Password: "wrong",
	})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", w.Code, w.Body.String())
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Fatalf("Retry-After header missing")
	}
}

func TestPasswordVerify_RejectMalformed(t *testing.T) {
	if _, err := auth.VerifyPassword("not-a-phc-string", "pw", []byte(testPepper)); !errors.Is(err, auth.ErrMalformedHash) {
		t.Fatalf("err = %v", err)
	}
}
