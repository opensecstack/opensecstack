package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// googleIDTokenClaims holds the fields we extract from a Google ID token.
type googleIDTokenClaims struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// GoogleOAuthStart redirects the browser to Google's OAuth authorization page.
// GET /api/v1/auth/google
func GoogleOAuthStart(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate a random state token to prevent CSRF.
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		state := fmt.Sprintf("%x", b)

		// Store state in a short-lived HttpOnly cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "google_oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600, // 10 minutes
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   !d.Cfg.DevMode,
		})

		params := url.Values{}
		params.Set("client_id", d.Cfg.GoogleClientID)
		params.Set("redirect_uri", d.Cfg.GoogleRedirectURI)
		params.Set("response_type", "code")
		params.Set("scope", "openid email profile")
		params.Set("state", state)

		authURL := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// GoogleOAuthCallback handles the redirect back from Google.
// GET /api/v1/auth/google/callback
func GoogleOAuthCallback(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		frontendBase := d.Cfg.SiteURL

		redirectError := func(msg string) {
			http.Redirect(w, r, frontendBase+"/oauth/callback?error="+url.QueryEscape(msg), http.StatusFound)
		}

		// 1. Verify state cookie to prevent CSRF.
		stateCookie, err := r.Cookie("google_oauth_state")
		if err != nil || stateCookie.Value == "" {
			redirectError("missing state")
			return
		}

		// Clear the state cookie immediately, before validating it, so the
		// state token is single-use regardless of whether validation
		// succeeds or fails — a failed CSRF check must not leave a
		// still-valid state cookie sitting in the browser for the rest of
		// its MaxAge window.
		http.SetCookie(w, &http.Cookie{
			Name:     "google_oauth_state",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   !d.Cfg.DevMode,
		})

		if r.URL.Query().Get("state") != stateCookie.Value {
			redirectError("state mismatch")
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			redirectError("no code returned by Google")
			return
		}

		// 2. Exchange code for tokens.
		idToken, err := googleExchangeCode(r.Context(), d.Cfg.GoogleClientID, d.Cfg.GoogleClientSecret, d.Cfg.GoogleRedirectURI, code)
		if err != nil {
			redirectError("token exchange failed")
			return
		}

		// 3. Parse the ID token to extract user claims.
		claims, err := parseGoogleIDToken(r.Context(), d.Cfg.GoogleClientID, idToken)
		if err != nil {
			redirectError("failed to parse Google ID token")
			return
		}
		if claims.Email == "" || claims.Sub == "" {
			redirectError("incomplete Google profile")
			return
		}

		// 4. Find or create user.
		tok, err := findOrCreateGoogleUser(r.Context(), d, claims)
		if err != nil {
			redirectError("account error: " + err.Error())
			return
		}

		// Redirect to frontend with token.
		http.Redirect(w, r, frontendBase+"/oauth/callback?token="+url.QueryEscape(tok), http.StatusFound)
	}
}

// googleExchangeCode exchanges an authorization code for a Google ID token.
func googleExchangeCode(ctx context.Context, clientID, clientSecret, redirectURI, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("invalid token response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("google error: %s", result.Error)
	}
	if result.IDToken == "" {
		return "", fmt.Errorf("empty id_token")
	}
	return result.IDToken, nil
}

// parseGoogleIDToken validates an ID token by calling Google's tokeninfo endpoint,
// which verifies the signature, expiry, and returns claims only if the token is valid.
// It also checks that the token's audience matches clientID to prevent token substitution.
func parseGoogleIDToken(ctx context.Context, clientID, idToken string) (*googleIDTokenClaims, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://oauth2.googleapis.com/tokeninfo?id_token="+url.QueryEscape(idToken), nil)
	if err != nil {
		return nil, fmt.Errorf("build tokeninfo request: %w", err)
	}
	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tokeninfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tokeninfo rejected token: status %d", resp.StatusCode)
	}

	var info struct {
		Sub     string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
		Aud     string `json:"aud"`
		Error   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode tokeninfo: %w", err)
	}
	if info.Error != "" {
		return nil, fmt.Errorf("tokeninfo error: %s", info.Error)
	}
	if info.Aud != clientID {
		return nil, fmt.Errorf("token audience mismatch: got %q want %q", info.Aud, clientID)
	}
	if info.Sub == "" || info.Email == "" {
		return nil, fmt.Errorf("incomplete tokeninfo response")
	}

	return &googleIDTokenClaims{
		Sub:     info.Sub,
		Email:   info.Email,
		Name:    info.Name,
		Picture: info.Picture,
	}, nil
}

// findOrCreateGoogleUser looks up or creates the platform user and returns a signed JWT.
func findOrCreateGoogleUser(ctx context.Context, d Deps, claims *googleIDTokenClaims) (string, error) {
	// 1. Check if a user with this google_id already exists.
	var username, role string
	err := d.Pool.QueryRow(ctx,
		`SELECT username, role FROM users WHERE google_id = $1`,
		claims.Sub,
	).Scan(&username, &role)

	if err == nil {
		// Existing Google-linked account — issue JWT.
		return issueOAuthJWT(d, username, role)
	}

	// 2. No existing google_id match — check by email.
	err = d.Pool.QueryRow(ctx,
		`SELECT username, role FROM users WHERE email = $1`,
		claims.Email,
	).Scan(&username, &role)

	if err == nil {
		// Email already registered — link the Google account to it.
		_, err = d.Pool.Exec(ctx,
			`UPDATE users SET google_id = $1, oauth_provider = 'google', updated_at = now() WHERE username = $2`,
			claims.Sub, username,
		)
		if err != nil {
			return "", fmt.Errorf("failed to link Google account: %w", err)
		}
		return issueOAuthJWT(d, username, role)
	}

	// 3. New user — create an account.
	baseUsername := deriveGoogleUsername(claims)
	username = ensureUniqueUsername(ctx, d, baseUsername)

	displayName := strings.TrimSpace(claims.Name)
	if displayName == "" {
		displayName = strings.SplitN(claims.Email, "@", 2)[0]
	}

	_, err = d.Pool.Exec(ctx,
		`INSERT INTO users (username, display_name, avatar_url, email, email_verified, role, google_id, oauth_provider)
		 VALUES ($1, $2, $3, $4, true, 'author', $5, 'google')`,
		username, displayName, claims.Picture, claims.Email, claims.Sub,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	return issueOAuthJWT(d, username, "author")
}

// deriveGoogleUsername produces a sanitized username from a Google profile.
// Uses the local part of the email address as a base.
var googleUsernameRe = strings.NewReplacer(
	"-", "_",
	".", "_",
	"+", "_",
)

func deriveGoogleUsername(claims *googleIDTokenClaims) string {
	base := strings.SplitN(claims.Email, "@", 2)[0]
	base = googleUsernameRe.Replace(base)
	// Strip any character that is not alphanumeric or underscore.
	var sb strings.Builder
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			sb.WriteRune(r)
		}
	}
	s := sb.String()
	if len(s) > 30 {
		s = s[:30]
	}
	if len(s) < 3 {
		s = s + "___"
		s = s[:3]
	}
	return s
}
