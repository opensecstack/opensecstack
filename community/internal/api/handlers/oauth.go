package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/opensecstack/community/internal/auth"
)

// githubUser is the subset of fields returned by GET /user.
type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

// githubEmail is one entry from GET /user/emails.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

var githubUsernameRe = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// sanitizeGitHubLogin converts a GitHub login into a valid platform username.
// GitHub logins allow hyphens; we replace non-alphanumeric/underscore chars
// with underscores and truncate to 30 characters.
func sanitizeGitHubLogin(login string) string {
	s := githubUsernameRe.ReplaceAllString(login, "_")
	if len(s) > 30 {
		s = s[:30]
	}
	if len(s) < 3 {
		s = s + "___"
		s = s[:3]
	}
	return s
}

var oauthHTTPClient = &http.Client{Timeout: 10 * time.Second}

// GitHubOAuthStart redirects the browser to GitHub's OAuth authorization page.
// GET /api/v1/auth/github
func GitHubOAuthStart(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate a random state token to prevent CSRF.
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		state := hex.EncodeToString(b)

		// Store state in a short-lived HttpOnly cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600, // 10 minutes
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   !d.Cfg.DevMode,
		})

		authURL := fmt.Sprintf(
			"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=read%%3Auser%%2Cuser%%3Aemail&state=%s",
			url.QueryEscape(d.Cfg.GitHubClientID),
			url.QueryEscape(d.Cfg.GitHubCallbackURL),
			state,
		)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// GitHubOAuthCallback handles the redirect back from GitHub.
// GET /api/v1/auth/github/callback
func GitHubOAuthCallback(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		frontendBase := d.Cfg.SiteURL

		redirectError := func(msg string) {
			http.Redirect(w, r, frontendBase+"/oauth/callback?error="+url.QueryEscape(msg), http.StatusFound)
		}

		// 1. Verify state cookie to prevent CSRF.
		stateCookie, err := r.Cookie("oauth_state")
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
			Name:     "oauth_state",
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
			redirectError("no code returned by GitHub")
			return
		}

		// 2. Exchange code for access token.
		accessToken, err := githubExchangeCode(r.Context(), d.Cfg.GitHubClientID, d.Cfg.GitHubClientSecret, code, d.Cfg.GitHubCallbackURL)
		if err != nil {
			redirectError("token exchange failed")
			return
		}

		// 3. Fetch GitHub user profile.
		ghUser, err := githubFetchUser(r.Context(), accessToken)
		if err != nil {
			redirectError("failed to fetch GitHub user")
			return
		}

		// 4. Fetch GitHub emails and find primary verified one.
		primaryEmail, err := githubFetchPrimaryEmail(r.Context(), accessToken)
		if err != nil || primaryEmail == "" {
			redirectError("no verified email on GitHub account")
			return
		}

		// 5. Find or create user.
		tok, err := findOrCreateGitHubUser(r.Context(), d, ghUser, primaryEmail)
		if err != nil {
			redirectError("account error: " + err.Error())
			return
		}

		// Redirect to frontend with token.
		http.Redirect(w, r, frontendBase+"/oauth/callback?token="+url.QueryEscape(tok), http.StatusFound)
	}
}

// githubExchangeCode performs the code -> access_token exchange with GitHub.
func githubExchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("invalid token response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("github error: %s", result.Error)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return result.AccessToken, nil
}

// githubFetchUser fetches the authenticated user's profile from GitHub.
func githubFetchUser(ctx context.Context, token string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github /user returned %d", resp.StatusCode)
	}

	var u githubUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

// githubFetchPrimaryEmail returns the primary verified email from GitHub.
func githubFetchPrimaryEmail(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github /user/emails returned %d", resp.StatusCode)
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", nil
}

// findOrCreateGitHubUser looks up or creates the platform user and returns a signed JWT.
func findOrCreateGitHubUser(ctx context.Context, d Deps, ghUser *githubUser, email string) (string, error) {
	// Check if a user with this github_id already exists.
	var username, role string
	err := d.Pool.QueryRow(ctx,
		`SELECT username, role FROM users WHERE github_id = $1`,
		ghUser.ID,
	).Scan(&username, &role)

	if err == nil {
		// Existing GitHub-linked account — issue JWT.
		return issueOAuthJWT(d, username, role)
	}

	// No existing github_id match — check by email.
	err = d.Pool.QueryRow(ctx,
		`SELECT username, role FROM users WHERE email = $1`,
		email,
	).Scan(&username, &role)

	if err == nil {
		// Email already registered — link the GitHub account to it.
		_, err = d.Pool.Exec(ctx,
			`UPDATE users SET github_id = $1, oauth_provider = 'github', updated_at = now() WHERE username = $2`,
			ghUser.ID, username,
		)
		if err != nil {
			return "", fmt.Errorf("failed to link GitHub account: %w", err)
		}
		return issueOAuthJWT(d, username, role)
	}

	// New user — create an account.
	username = sanitizeGitHubLogin(ghUser.Login)
	username = ensureUniqueUsername(ctx, d, username)

	displayName := ghUser.Name
	if strings.TrimSpace(displayName) == "" {
		displayName = ghUser.Login
	}

	_, err = d.Pool.Exec(ctx,
		`INSERT INTO users (username, display_name, avatar_url, email, email_verified, role, github_id, oauth_provider)
		 VALUES ($1, $2, $3, $4, true, 'author', $5, 'github')`,
		username, displayName, ghUser.AvatarURL, email, ghUser.ID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	return issueOAuthJWT(d, username, "author")
}

// ensureUniqueUsername appends a suffix if the desired username is taken.
func ensureUniqueUsername(ctx context.Context, d Deps, base string) string {
	candidate := base
	for i := 2; i <= 999; i++ {
		var exists bool
		_ = d.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)`, candidate).Scan(&exists)
		if !exists {
			return candidate
		}
		candidate = fmt.Sprintf("%s_%d", base, i)
		if len(candidate) > 30 {
			candidate = fmt.Sprintf("%s_%d", base[:26], i)
		}
	}
	return candidate
}

// issueOAuthJWT creates and returns a signed JWT for the given user.
func issueOAuthJWT(d Deps, username, role string) (string, error) {
	tok, _, err := auth.Issue(d.Cfg.JWTSecret, d.Cfg.JWTIssuer, username, role, d.Cfg.TokenTTL)
	if err != nil {
		return "", fmt.Errorf("token error: %w", err)
	}
	return tok, nil
}
