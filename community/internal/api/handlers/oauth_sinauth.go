package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// sinauthUserInfo holds the fields returned by the sinauth userinfo endpoint.
type sinauthUserInfo struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// SinauthOAuthStart redirects to the sinauth authorization endpoint with PKCE.
// GET /api/v1/auth/sinauth
func SinauthOAuthStart(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate random state token to prevent CSRF.
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		state := fmt.Sprintf("%x", b)

		// PKCE: generate code_verifier and derive S256 code_challenge.
		vb := make([]byte, 32)
		if _, err := rand.Read(vb); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		codeVerifier := hex.EncodeToString(vb)
		sum := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

		secure := !d.Cfg.DevMode

		// Store state in short-lived HttpOnly cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "sinauth_oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
		})

		// Store PKCE verifier in short-lived HttpOnly cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "sinauth_pkce",
			Value:    codeVerifier,
			Path:     "/",
			MaxAge:   600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
		})

		params := url.Values{}
		params.Set("client_id", d.Cfg.SinauthClientID)
		params.Set("redirect_uri", d.Cfg.SinauthCallbackURL)
		params.Set("response_type", "code")
		params.Set("scope", "openid email profile")
		params.Set("state", state)
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")

		// Use the browser-facing sinauth origin for the authorize redirect: the
		// in-network SinauthURL (e.g. sinauth-api / host.docker.internal) is not
		// resolvable by the end user's browser. SinauthPublicURL falls back to
		// SinauthURL when unset (single-host deployments).
		authBase := d.Cfg.SinauthPublicURL
		if authBase == "" {
			authBase = d.Cfg.SinauthURL
		}
		authURL := authBase + "/oauth/authorize?" + params.Encode()
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// SinauthOAuthCallback handles the redirect back from sinauth.
// GET /api/v1/auth/sinauth/callback
func SinauthOAuthCallback(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		frontendBase := d.Cfg.SiteURL

		redirectError := func(msg string) {
			http.Redirect(w, r, frontendBase+"/oauth/callback?error="+url.QueryEscape(msg), http.StatusFound)
		}

		// 1. Verify state cookie to prevent CSRF.
		stateCookie, err := r.Cookie("sinauth_oauth_state")
		if err != nil || stateCookie.Value == "" {
			redirectError("missing state")
			return
		}

		// Clear state cookie immediately, before validating it, so the
		// state token is single-use regardless of whether validation
		// succeeds or fails — a failed CSRF check must not leave a
		// still-valid state cookie sitting in the browser for the rest of
		// its MaxAge window.
		http.SetCookie(w, &http.Cookie{
			Name:     "sinauth_oauth_state",
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

		// 2. Retrieve the PKCE code_verifier.
		pkceCookie, err := r.Cookie("sinauth_pkce")

		// Clear PKCE cookie immediately, before checking it, for the same
		// single-use reasoning as the state cookie above.
		http.SetCookie(w, &http.Cookie{
			Name:     "sinauth_pkce",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   !d.Cfg.DevMode,
		})

		if err != nil || pkceCookie.Value == "" {
			redirectError("missing pkce")
			return
		}
		codeVerifier := pkceCookie.Value

		code := r.URL.Query().Get("code")
		if code == "" {
			redirectError("no code returned by sinauth")
			return
		}

		// 3. Exchange code for access token using PKCE.
		accessToken, err := sinauthExchangeCode(
			r.Context(),
			d.Cfg.SinauthURL,
			d.Cfg.SinauthClientID,
			d.Cfg.SinauthClientSecret,
			d.Cfg.SinauthCallbackURL,
			code,
			codeVerifier,
		)
		if err != nil {
			slog.Error("sinauth token exchange failed", "err", err, "sinauth_url", d.Cfg.SinauthURL)
			redirectError("token exchange failed")
			return
		}

		// 4. Fetch userinfo from sinauth.
		info, err := sinauthFetchUserInfo(r.Context(), d.Cfg.SinauthURL, accessToken)
		if err != nil || info.Sub == "" {
			redirectError("failed to fetch sinauth user info")
			return
		}

		// 5. Find or create user and issue community JWT.
		tok, err := findOrCreateSinauthUser(r.Context(), d, info)
		if err != nil {
			redirectError("account error: " + err.Error())
			return
		}

		http.Redirect(w, r, frontendBase+"/oauth/callback?token="+url.QueryEscape(tok), http.StatusFound)
	}
}

// sinauthExchangeCode exchanges an authorization code (with PKCE verifier) for an access token.
func sinauthExchangeCode(ctx context.Context, sinauthURL, clientID, clientSecret, callbackURL, code, codeVerifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", callbackURL)
	form.Set("client_id", clientID)
	form.Set("code_verifier", codeVerifier)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sinauthURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("invalid token response: %w", err)
	}
	if result.Error != "" {
		slog.Error("sinauth token exchange rejected", "error", result.Error, "status", resp.StatusCode)
		return "", fmt.Errorf("sinauth error: %s", result.Error)
	}
	if result.AccessToken == "" {
		slog.Error("sinauth token exchange returned empty access_token", "status", resp.StatusCode, "body", string(body))
		return "", fmt.Errorf("empty access token")
	}
	return result.AccessToken, nil
}

// sinauthFetchUserInfo calls the sinauth userinfo endpoint and returns the claims.
func sinauthFetchUserInfo(ctx context.Context, sinauthURL, accessToken string) (*sinauthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sinauthURL+"/oauth/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.Error("sinauth userinfo request failed", "status", resp.StatusCode, "body", string(body), "url", sinauthURL+"/oauth/userinfo")
		return nil, fmt.Errorf("userinfo returned %d", resp.StatusCode)
	}

	var info sinauthUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// findOrCreateSinauthUser looks up or creates the platform user and returns a signed community JWT.
func findOrCreateSinauthUser(ctx context.Context, d Deps, info *sinauthUserInfo) (string, error) {
	// 1. Look up by sinauth_id.
	var username, role string
	err := d.Pool.QueryRow(ctx,
		`SELECT username, role FROM users WHERE sinauth_id = $1`, info.Sub,
	).Scan(&username, &role)
	if err == nil {
		return issueOAuthJWT(d, username, role)
	}

	// 2. Fall back to email match — link existing account.
	if info.Email != "" {
		err = d.Pool.QueryRow(ctx,
			`SELECT username, role FROM users WHERE email = $1`, info.Email,
		).Scan(&username, &role)
		if err == nil {
			_, _ = d.Pool.Exec(ctx,
				`UPDATE users SET sinauth_id=$1, oauth_provider='sinauth', updated_at=now() WHERE username=$2`,
				info.Sub, username,
			)
			return issueOAuthJWT(d, username, role)
		}
	}

	// 3. New user — derive username from sinauth sub and create account.
	base := strings.SplitN(info.Sub, "@", 2)[0]
	if base == "" {
		base = "user"
	}

	// Sanitize: keep only alphanumeric and underscore characters.
	var sb strings.Builder
	for _, ch := range base {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			sb.WriteRune(ch)
		}
	}
	cleanBase := sb.String()
	if len(cleanBase) < 3 {
		cleanBase = (cleanBase + "___")[:3]
	}
	if len(cleanBase) > 30 {
		cleanBase = cleanBase[:30]
	}
	username = ensureUniqueUsername(ctx, d, cleanBase)

	displayName := strings.TrimSpace(info.Name)
	if displayName == "" {
		displayName = username
	}

	_, err = d.Pool.Exec(ctx,
		`INSERT INTO users (username, display_name, avatar_url, email, email_verified, role, sinauth_id, oauth_provider)
		 VALUES ($1, $2, $3, $4, true, 'author', $5, 'sinauth')`,
		username, displayName, info.Picture, info.Email, info.Sub,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}
	return issueOAuthJWT(d, username, "author")
}
