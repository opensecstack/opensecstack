package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
)

// loginMu guards loginFailures.
var (
	loginMu       sync.Mutex
	loginFailures = map[string][]time.Time{} // username -> timestamps of recent failed attempts
)

const (
	lockoutWindow   = 15 * time.Minute
	lockoutMaxFails = 5
)

// recordFailure appends now to the failure list for username, evicting stale entries.
func recordFailure(username string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	now := time.Now()
	recent := loginFailures[username]
	cutoff := now.Add(-lockoutWindow)
	pruned := recent[:0]
	for _, t := range recent {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	loginFailures[username] = append(pruned, now)
}

// clearFailures removes all recorded failures for username (called on successful login).
func clearFailures(username string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginFailures, username)
}

// isLockedOut returns true if username has >= lockoutMaxFails failures in the last lockoutWindow.
func isLockedOut(username string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	cutoff := time.Now().Add(-lockoutWindow)
	count := 0
	for _, t := range loginFailures[username] {
		if t.After(cutoff) {
			count++
		}
	}
	return count >= lockoutMaxFails
}

// recordSession inserts a new user_sessions row for the given user and token.
// It is safe to call after a successful login — duplicate token_hashes are silently ignored.
func recordSession(r *http.Request, d Deps, userID, rawToken string, expiresAt time.Time) {
	ua := r.Header.Get("User-Agent")
	if len(ua) > 200 {
		ua = ua[:200]
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	hash := tokenHash(rawToken)

	if _, err := d.Pool.Exec(r.Context(),
		`INSERT INTO user_sessions (user_id, token_hash, device_info, ip_address, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (token_hash) DO NOTHING`,
		userID, hash, ua, ip, expiresAt,
	); err != nil {
		slog.Error("recordSession: insert failed", "user_id", userID, "err", err)
	}
}

func Login(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TOTPCode string `json:"totp_code"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		hash := sha256Hash(d.Cfg.Pepper + ":" + req.Password)

		// Check config-hardcoded users first (these never have TOTP).
		var matchedRole string
		for _, u := range d.Cfg.Users {
			if u.Username == req.Username && u.Hash == hash {
				matchedRole = u.Role
				break
			}
		}
		if matchedRole != "" {
			// Ensure config users have a DB row so profile pages and user lookups work.
			if _, err := d.Pool.Exec(r.Context(),
				`INSERT INTO users (username, display_name, role)
				 VALUES ($1, $1, $2)
				 ON CONFLICT (username) DO UPDATE SET role = EXCLUDED.role`,
				req.Username, matchedRole); err != nil {
				slog.Error("Login: upsert config user failed", "username", req.Username, "err", err)
			}

			tok, claims, err := auth.Issue(d.Cfg.JWTSecret, d.Cfg.JWTIssuer, req.Username, matchedRole, d.Cfg.TokenTTL)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
				return
			}

			// Look up the user's UUID for the session record.
			var userID string
			if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username = $1`, req.Username).Scan(&userID); err != nil {
				slog.Error("Login: user id lookup failed", "username", req.Username, "err", err)
			}
			if userID != "" {
				recordSession(r, d, userID, tok, claims.ExpiresAt.Time)
			}

			writeJSON(w, http.StatusOK, map[string]any{
				"token":          tok,
				"role":           claims.Role,
				"sub":            claims.Sub,
				"expires_at":     claims.ExpiresAt.Format(time.RFC3339),
				"email_verified": false,
			})
			return
		}

		// Fallback: check DB-registered users.

		// Enforce per-account lockout before touching the DB password.
		if isLockedOut(req.Username) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "account temporarily locked due to too many failed attempts"})
			return
		}

		var dbRole, dbHash, dbTOTPSecret string
		var dbEmailVerified, dbTOTPEnabled bool
		var dbDeactivatedAt *time.Time
		row := d.Pool.QueryRow(r.Context(),
			`SELECT role,
			        COALESCE(password_hash,''),
			        COALESCE(email_verified, false),
			        deactivated_at,
			        COALESCE(totp_secret,''),
			        COALESCE(totp_enabled, false)
			 FROM users WHERE username=$1`,
			req.Username)
		if err := row.Scan(&dbRole, &dbHash, &dbEmailVerified, &dbDeactivatedAt, &dbTOTPSecret, &dbTOTPEnabled); err != nil || dbHash == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}

		// Password check with lazy bcrypt migration.
		var passwordOK bool
		if strings.HasPrefix(dbHash, "$2") {
			// Modern bcrypt hash.
			passwordOK = bcryptVerify(req.Password, dbHash)
		} else {
			// Legacy sha256 hash — check then migrate on success.
			if sha256Hash(d.Cfg.Pepper+":"+req.Password) == dbHash {
				passwordOK = true
				// Migrate: re-hash with bcrypt and update DB.
				if newHash, err := bcryptHash(req.Password); err == nil {
					if _, err := d.Pool.Exec(r.Context(),
						`UPDATE users SET password_hash=$1 WHERE username=$2`,
						newHash, req.Username,
					); err != nil {
						slog.Error("Login: bcrypt migration update failed", "username", req.Username, "err", err)
					}
				}
			}
		}

		if !passwordOK {
			recordFailure(req.Username)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}

		if dbDeactivatedAt != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "account deactivated"})
			return
		}

		// If TOTP is enabled, require a valid OTP before issuing a JWT.
		if dbTOTPEnabled {
			if req.TOTPCode == "" {
				// Tell the client to show the OTP input — do NOT issue a token yet.
				writeJSON(w, http.StatusOK, map[string]any{"require_totp": true})
				return
			}
			if !ConsumeTOTPCode(r.Context(), d.Pool, req.Username, req.TOTPCode, dbTOTPSecret) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid 2FA code"})
				return
			}
		}

		// Successful login — clear any recorded failures.
		clearFailures(req.Username)

		tok, claims, err := auth.Issue(d.Cfg.JWTSecret, d.Cfg.JWTIssuer, req.Username, dbRole, d.Cfg.TokenTTL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}

		// Record the new session.
		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username = $1`, req.Username).Scan(&userID); err != nil {
			slog.Error("Login: user id lookup failed", "username", req.Username, "err", err)
		}
		if userID != "" {
			recordSession(r, d, userID, tok, claims.ExpiresAt.Time)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"token":          tok,
			"role":           claims.Role,
			"sub":            claims.Sub,
			"expires_at":     claims.ExpiresAt.Format(time.RFC3339),
			"email_verified": dbEmailVerified,
		})
	}
}

// sha256Hash returns the hex-encoded SHA-256 digest of s.
// Used only for config-hardcoded user validation; DB users use bcrypt.
func sha256Hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// bcryptHash returns a bcrypt hash of password at cost 12.
func bcryptHash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// bcryptVerify returns true when password matches the stored bcrypt hash.
func bcryptVerify(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func requireRole(d Deps, r *http.Request, w http.ResponseWriter, role string) bool {
	claims := middleware.ClaimsFrom(r.Context())
	if claims == nil || !auth.HasRole(claims.Role, role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient role"})
		return false
	}
	return true
}
