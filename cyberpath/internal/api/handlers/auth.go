// Authentication endpoints: login, refresh, logout, me.
//
// Wired via api.Options.Auth. The endpoints use the standard JSON
// error envelope and emit audit events for token issuance and logout.
//
// All login responses pad to a constant-ish duration (~300ms) — a
// dummy Argon2id hash runs even when the user does not exist, so a
// timing oracle cannot enumerate registered emails.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/auth"
)

// User is the minimal user record auth needs. Keeps the handler
// decoupled from the DB layer.
type User struct {
	ID           string
	TenantID     string
	Email        string
	DisplayName  string
	Locale       string
	Role         string
	PasswordHash string
	DeletedAt    *time.Time
}

// UserStore is the persistence dependency the auth handlers need.
// internal/db will satisfy this in v1.0.0 wire-up; tests use a fake.
type UserStore interface {
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id string) (*User, error)
	UpdatePasswordHash(ctx context.Context, userID, newHash string) error
}

// AuditSink records auth audit events. internal/db will provide the
// real implementation; tests pass a no-op.
type AuditSink interface {
	Record(ctx context.Context, event AuditEvent)
}

// AuditEvent is one row destined for audit_events.
type AuditEvent struct {
	TenantID      string
	ActorUserID   string
	ActorRole     string
	Action        string
	TargetType    string
	TargetID      string
	Outcome       string // "success" | "failure" | "denied"
	Metadata      map[string]any
	IPAddress     string
	UserAgent     string
	CorrelationID string
}

// ErrUserNotFound is returned by UserStore.FindBy* when no row matches.
var ErrUserNotFound = errors.New("auth: user not found")

// AuthDeps bundles the auth handler's collaborators.
type AuthDeps struct {
	Users          UserStore
	Sessions       auth.SessionStore
	Issuer         *auth.Issuer
	Audit          AuditSink
	Logger         *zerolog.Logger
	Pepper         []byte
	PepperPrevious []byte        // optional fallback pepper used during rotation
	LoginPad       time.Duration // padding floor for login responses; 0 disables
	Throttle       *LoginThrottle
}

// AuthHandlers groups the auth endpoints around a shared AuthDeps.
type AuthHandlers struct {
	deps AuthDeps
	// Pre-computed dummy hash used for timing-safe "user not found"
	// branches — VerifyPassword is run against this so the wall-clock
	// looks identical to a real verification.
	dummyHash string
}

// NewAuthHandlers constructs the handler set. A dummy argon2id hash
// is pre-computed so missing-user branches still pay the verification
// cost.
func NewAuthHandlers(deps AuthDeps) (*AuthHandlers, error) {
	if deps.Issuer == nil {
		return nil, errors.New("auth: issuer required")
	}
	if deps.Sessions == nil {
		return nil, errors.New("auth: session store required")
	}
	if deps.Users == nil {
		return nil, errors.New("auth: user store required")
	}
	if deps.LoginPad == 0 {
		deps.LoginPad = 300 * time.Millisecond
	}
	if deps.Throttle == nil {
		deps.Throttle = NewLoginThrottle(5, 15*time.Minute)
	}
	dummy, err := auth.HashPassword("__dummy__"+auth.NewSessionID(), deps.Pepper)
	if err != nil {
		return nil, err
	}
	return &AuthHandlers{deps: deps, dummyHash: dummy}, nil
}

// ── Request / response shapes ─────────────────────────────────────

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int          `json:"expires_in"`
	User         *userPayload `json:"user,omitempty"`
}

type userPayload struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Locale      string `json:"locale"`
	Role        string `json:"role"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// ── Handlers ──────────────────────────────────────────────────────

// Login handles POST /api/v1/auth/login.
func (h *AuthHandlers) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer h.padTo(start)

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return
		}
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "email and password required")
			return
		}

		// Per-email throttling — 429 BEFORE doing the expensive hash.
		if retry := h.deps.Throttle.RetryAfter(req.Email); retry > 0 {
			w.Header().Set("Retry-After", retryAfterHeader(retry))
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				"too many failed attempts; try again later")
			return
		}

		ctx := r.Context()
		u, err := h.deps.Users.FindByEmail(ctx, req.Email)
		if err != nil && !errors.Is(err, ErrUserNotFound) {
			h.log().Error().Err(err).Msg("auth: user lookup")
			writeError(w, http.StatusInternalServerError, "internal_error", "lookup failed")
			return
		}

		// Run a verification regardless of whether the user exists or
		// is soft-deleted, so timing does not leak existence.
		var (
			ok           bool
			vErr         error
			pepperRehash bool
			isLive       = u != nil && u.DeletedAt == nil
		)
		if isLive {
			ok, pepperRehash, vErr = auth.VerifyPasswordWithFallback(
				u.PasswordHash, req.Password, h.deps.Pepper, h.deps.PepperPrevious,
			)
		} else {
			_, _, _ = auth.VerifyPasswordWithFallback(
				h.dummyHash, req.Password, h.deps.Pepper, h.deps.PepperPrevious,
			)
		}

		if !isLive || vErr != nil || !ok {
			if vErr != nil {
				h.log().Warn().Err(vErr).Str("email", req.Email).Msg("auth: verify error")
			}
			h.deps.Throttle.RecordFailure(req.Email)
			h.audit(ctx, r, AuditEvent{
				Action:     "auth.login",
				TargetType: "user",
				TargetID:   safeID(u),
				Outcome:    "failure",
			})
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password incorrect")
			return
		}

		// Silent rehash if parameters drifted OR the user verified
		// under the previous pepper (rotation in flight). Best-effort:
		// log and continue on persist failure — login still succeeds.
		if auth.NeedsRehash(u.PasswordHash) || pepperRehash {
			if newHash, err := auth.HashPassword(req.Password, h.deps.Pepper); err == nil {
				if uerr := h.deps.Users.UpdatePasswordHash(ctx, u.ID, newHash); uerr != nil {
					h.log().Warn().Err(uerr).Str("user_id", u.ID).Msg("auth: rehash persist")
				}
			}
		}

		access, _, err := h.deps.Issuer.IssueAccessToken(u.ID, u.Role, u.TenantID)
		if err != nil {
			h.log().Error().Err(err).Msg("auth: issue access")
			writeError(w, http.StatusInternalServerError, "internal_error", "token issuance failed")
			return
		}
		sessionID := auth.NewSessionID()
		refresh, err := h.deps.Issuer.IssueRefreshToken(u.ID, sessionID)
		if err != nil {
			h.log().Error().Err(err).Msg("auth: issue refresh")
			writeError(w, http.StatusInternalServerError, "internal_error", "token issuance failed")
			return
		}
		now := time.Now().UTC()
		if err := h.deps.Sessions.Create(auth.Session{
			ID:               sessionID,
			UserID:           u.ID,
			RefreshTokenHash: auth.HashRefreshToken(refresh),
			IssuedAt:         now,
			ExpiresAt:        now.Add(h.deps.Issuer.RefreshTTL()),
			IPAddress:        clientIP(r),
			UserAgent:        r.UserAgent(),
		}); err != nil {
			h.log().Error().Err(err).Msg("auth: session create")
			writeError(w, http.StatusInternalServerError, "internal_error", "session create failed")
			return
		}

		h.deps.Throttle.RecordSuccess(req.Email)
		h.audit(ctx, r, AuditEvent{
			TenantID:    u.TenantID,
			ActorUserID: u.ID,
			ActorRole:   u.Role,
			Action:      "auth.token_issued",
			TargetType:  "user",
			TargetID:    u.ID,
			Outcome:     "success",
			Metadata:    map[string]any{"session_id": sessionID, "kind": "login"},
		})

		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken:  access,
			RefreshToken: refresh,
			TokenType:    "Bearer",
			ExpiresIn:    int(h.deps.Issuer.AccessTTL().Seconds()),
			User: &userPayload{
				ID: u.ID, Email: u.Email, DisplayName: u.DisplayName,
				Locale: u.Locale, Role: u.Role,
			},
		})
	}
}

// Refresh handles POST /api/v1/auth/refresh.
func (h *AuthHandlers) Refresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token required")
			return
		}
		ctx := r.Context()

		sub, sid, _, err := h.deps.Issuer.ParseRefresh(req.RefreshToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", "refresh token invalid")
			return
		}

		sess, err := h.deps.Sessions.Validate(req.RefreshToken)
		if err != nil || sess.UserID != sub || sess.ID != sid {
			writeError(w, http.StatusUnauthorized, "invalid_token", "session not active")
			return
		}

		u, err := h.deps.Users.FindByID(ctx, sub)
		if err != nil || u == nil || u.DeletedAt != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", "user not available")
			return
		}

		// Rotate: revoke the old session, mint a new pair.
		_ = h.deps.Sessions.Revoke(sess.ID)

		access, _, err := h.deps.Issuer.IssueAccessToken(u.ID, u.Role, u.TenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "token issuance failed")
			return
		}
		newSID := auth.NewSessionID()
		newRefresh, err := h.deps.Issuer.IssueRefreshToken(u.ID, newSID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "token issuance failed")
			return
		}
		now := time.Now().UTC()
		if err := h.deps.Sessions.Create(auth.Session{
			ID:               newSID,
			UserID:           u.ID,
			RefreshTokenHash: auth.HashRefreshToken(newRefresh),
			IssuedAt:         now,
			ExpiresAt:        now.Add(h.deps.Issuer.RefreshTTL()),
			IPAddress:        clientIP(r),
			UserAgent:        r.UserAgent(),
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "session create failed")
			return
		}

		h.audit(ctx, r, AuditEvent{
			TenantID:    u.TenantID,
			ActorUserID: u.ID,
			ActorRole:   u.Role,
			Action:      "auth.token_issued",
			TargetType:  "user",
			TargetID:    u.ID,
			Outcome:     "success",
			Metadata:    map[string]any{"session_id": newSID, "kind": "refresh"},
		})
		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken:  access,
			RefreshToken: newRefresh,
			TokenType:    "Bearer",
			ExpiresIn:    int(h.deps.Issuer.AccessTTL().Seconds()),
		})
	}
}

// Logout handles POST /api/v1/auth/logout. Idempotent: revoking an
// unknown token returns 204.
func (h *AuthHandlers) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.RefreshToken == "" {
			if c, err := r.Cookie("refresh_token"); err == nil {
				req.RefreshToken = c.Value
			}
		}
		if req.RefreshToken != "" {
			if sess, err := h.deps.Sessions.GetByRefreshToken(req.RefreshToken); err == nil && sess != nil {
				_ = h.deps.Sessions.Revoke(sess.ID)
				h.audit(r.Context(), r, AuditEvent{
					ActorUserID: sess.UserID,
					Action:      "auth.logout",
					TargetType:  "user",
					TargetID:    sess.UserID,
					Outcome:     "success",
					Metadata:    map[string]any{"session_id": sess.ID},
				})
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// Me returns the authenticated user from the bearer claims.
func (h *AuthHandlers) Me() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := auth.FromContext(r.Context())
		if !ok || c == nil {
			writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
			return
		}
		u, err := h.deps.Users.FindByID(r.Context(), c.Sub)
		if err != nil || u == nil {
			writeError(w, http.StatusNotFound, "user_not_found", "user no longer exists")
			return
		}
		writeJSON(w, http.StatusOK, userPayload{
			ID: u.ID, Email: u.Email, DisplayName: u.DisplayName,
			Locale: u.Locale, Role: u.Role,
		})
	}
}

// ── Helpers ───────────────────────────────────────────────────────

func (h *AuthHandlers) padTo(start time.Time) {
	if h.deps.LoginPad <= 0 {
		return
	}
	if d := time.Since(start); d < h.deps.LoginPad {
		time.Sleep(h.deps.LoginPad - d)
	}
}

func (h *AuthHandlers) audit(ctx context.Context, r *http.Request, ev AuditEvent) {
	if h.deps.Audit == nil {
		return
	}
	if ev.IPAddress == "" {
		ev.IPAddress = clientIP(r)
	}
	if ev.UserAgent == "" {
		ev.UserAgent = r.UserAgent()
	}
	h.deps.Audit.Record(ctx, ev)
}

func (h *AuthHandlers) log() *zerolog.Logger {
	if h.deps.Logger != nil {
		return h.deps.Logger
	}
	z := zerolog.Nop()
	return &z
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if i := strings.IndexByte(ip, ','); i > 0 {
			ip = ip[:i]
		}
		return strings.TrimSpace(ip)
	}
	return r.RemoteAddr
}

func safeID(u *User) string {
	if u == nil {
		return ""
	}
	return u.ID
}

func retryAfterHeader(d time.Duration) string {
	secs := int(d.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	return strings.TrimSpace(timeSecsString(secs))
}

func timeSecsString(secs int) string {
	// Avoid pulling strconv just for this — small int formatting.
	const digits = "0123456789"
	if secs < 10 {
		return string([]byte{digits[secs]})
	}
	var buf [20]byte
	i := len(buf)
	for secs > 0 {
		i--
		buf[i] = digits[secs%10]
		secs /= 10
	}
	return string(buf[i:])
}

// ── Login throttle ────────────────────────────────────────────────

// LoginThrottle applies per-email exponential backoff. Backoff resets
// on a successful login.
type LoginThrottle struct {
	mu       sync.Mutex
	failures map[string]*throttleEntry
	max      int
	window   time.Duration
	now      func() time.Time
}

type throttleEntry struct {
	count     int
	firstAt   time.Time
	blockedTo time.Time
}

// NewLoginThrottle returns a throttle that blocks an email for an
// exponentially-growing window after >= max failures inside the
// rolling window.
func NewLoginThrottle(max int, window time.Duration) *LoginThrottle {
	return &LoginThrottle{
		failures: make(map[string]*throttleEntry),
		max:      max,
		window:   window,
		now:      time.Now,
	}
}

// RetryAfter reports how long the caller must wait before another
// attempt. Zero means "go ahead".
func (l *LoginThrottle) RetryAfter(email string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.failures[email]
	if !ok {
		return 0
	}
	now := l.now()
	if now.After(e.blockedTo) {
		return 0
	}
	return e.blockedTo.Sub(now)
}

// RecordFailure increments the failure counter and computes the
// next blocked-until timestamp using exponential backoff.
func (l *LoginThrottle) RecordFailure(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.failures[email]
	if !ok || now.Sub(e.firstAt) > l.window {
		e = &throttleEntry{firstAt: now}
		l.failures[email] = e
	}
	e.count++
	if e.count >= l.max {
		// Exponential: 1m, 2m, 4m, 8m, capped at the window.
		over := e.count - l.max
		secs := int64(60) << uint(over)
		if max := int64(l.window.Seconds()); secs > max {
			secs = max
		}
		e.blockedTo = now.Add(time.Duration(secs) * time.Second)
	}
}

// RecordSuccess clears the failure counter for an email.
func (l *LoginThrottle) RecordSuccess(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, email)
}
