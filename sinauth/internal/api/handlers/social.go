package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Ensure base64 standard encoding is used for oauth_return decoding.
var _ = base64.StdEncoding

// ── state helpers ────────────────────────────────────────────────────────────

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sinauth_oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // set true behind TLS
	})
}

func verifyStateCookie(r *http.Request, state string) bool {
	c, err := r.Cookie("sinauth_oauth_state")
	if err != nil || c.Value == "" || c.Value != state {
		return false
	}
	return true
}

func clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sinauth_oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// redirectWithToken sends the browser back to the SPA with the issued token.
func redirectWithToken(w http.ResponseWriter, r *http.Request, siteURL, token string) {
	base := strings.TrimRight(siteURL, "/")
	if base == "" {
		base = "http://localhost:5173"
	}
	http.Redirect(w, r, base+"/?social_token="+token, http.StatusFound)
}

// setOAuthReturnCookie stores the oauth_return param (base64 JSON of OAuth params) in a cookie
// so the social callback can complete the OAuth authorization code flow.
func setOAuthReturnCookie(w http.ResponseWriter, r *http.Request) {
	if val := r.URL.Query().Get("oauth_return"); val != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "sinauth_oauth_return",
			Value:    val,
			Path:     "/",
			MaxAge:   600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// oauthReturnParams holds the OAuth params stored by setOAuthReturnCookie.
type oauthReturnParams struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Nonce               string `json:"nonce"`
}

// completeOAuthFromSocial checks for a pending OAuth return cookie; if present, issues an
// auth code and redirects to redirect_uri — completing the OAuth flow via social login.
// Returns true if it handled the response (caller must not write anything further).
func completeOAuthFromSocial(w http.ResponseWriter, r *http.Request, d Deps, userID string) bool {
	c, err := r.Cookie("sinauth_oauth_return")
	if err != nil || c.Value == "" {
		return false
	}

	http.SetCookie(w, &http.Cookie{Name: "sinauth_oauth_return", Value: "", Path: "/", MaxAge: -1})

	raw, err := base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}
	var p oauthReturnParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return false
	}
	if p.ClientID == "" || p.RedirectURI == "" {
		return false
	}

	scopes := strings.Fields(p.Scope)
	// Social login has no organization-picker step; org context (if any) must
	// be established via the standard /oauth/authorize + organization_id flow.
	code, err := issueAuthCode(r.Context(), d, p.ClientID, userID, p.RedirectURI, scopes, p.CodeChallenge, p.CodeChallengeMethod, p.Nonce, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return true
	}

	redirect, _ := url.Parse(p.RedirectURI)
	q := redirect.Query()
	q.Set("code", code)
	if p.State != "" {
		q.Set("state", p.State)
	}
	redirect.RawQuery = q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
	return true
}

// ── Google ───────────────────────────────────────────────────────────────────

func GoogleOAuthStart(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Cfg.GoogleClientID == "" {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "Google OAuth not configured"})
			return
		}
		state, err := generateState()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		setStateCookie(w, state)
		setOAuthReturnCookie(w, r)

		params := url.Values{
			"client_id":     {d.Cfg.GoogleClientID},
			"redirect_uri":  {d.Cfg.GoogleRedirectURI},
			"response_type": {"code"},
			"scope":         {"openid email profile"},
			"state":         {state},
			"access_type":   {"online"},
			"prompt":        {"select_account"},
		}
		http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?"+params.Encode(), http.StatusFound)
	}
}

func GoogleOAuthCallback(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if !verifyStateCookie(r, state) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid state"})
			return
		}
		clearStateCookie(w)

		code := r.URL.Query().Get("code")
		if code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing code"})
			return
		}

		ctx := r.Context()
		accessToken, err := googleExchangeCode(ctx, d.Cfg.GoogleClientID, d.Cfg.GoogleClientSecret, d.Cfg.GoogleRedirectURI, code)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "google token exchange failed"})
			return
		}

		gUser, err := googleUserInfo(ctx, accessToken)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "google userinfo failed"})
			return
		}

		u, err := d.UserSvc.FindOrCreateBySocial(ctx, "google", gUser.Sub, gUser.Email, gUser.Name, gUser.Picture)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}

		if d.Audit != nil {
			d.Audit.Log("login.social", u.Username, "google", r.RemoteAddr, r.UserAgent(), nil)
		}

		// If this came from an OAuth popup flow, complete the auth code flow.
		if completeOAuthFromSocial(w, r, d, u.ID) {
			return
		}

		// Otherwise: direct admin dashboard login.
		token, err := d.Issuer.IssueAccessToken(u.Username, "sinauth-dashboard", []string{"openid", "profile", "email"}, d.Cfg.AccessTokenTTL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}
		redirectWithToken(w, r, d.Cfg.SiteURL, token)
	}
}

type googleUser struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func googleExchangeCode(ctx context.Context, clientID, clientSecret, redirectURI, code string) (string, error) {
	body := url.Values{
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token",
		strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var res struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	if res.Error != "" {
		return "", fmt.Errorf("google: %s", res.Error)
	}
	return res.AccessToken, nil
}

func googleUserInfo(ctx context.Context, accessToken string) (*googleUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var u googleUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	if u.Sub == "" {
		return nil, fmt.Errorf("google: empty sub")
	}
	return &u, nil
}

// ── GitHub ───────────────────────────────────────────────────────────────────

func GitHubOAuthStart(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Cfg.GitHubClientID == "" {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "GitHub OAuth not configured"})
			return
		}
		state, err := generateState()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		setStateCookie(w, state)
		setOAuthReturnCookie(w, r)

		params := url.Values{
			"client_id":    {d.Cfg.GitHubClientID},
			"redirect_uri": {d.Cfg.GitHubRedirectURI},
			"scope":        {"user:email read:user"},
			"state":        {state},
		}
		http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusFound)
	}
}

func GitHubOAuthCallback(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if !verifyStateCookie(r, state) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid state"})
			return
		}
		clearStateCookie(w)

		code := r.URL.Query().Get("code")
		if code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing code"})
			return
		}

		ctx := r.Context()
		accessToken, err := githubExchangeCode(ctx, d.Cfg.GitHubClientID, d.Cfg.GitHubClientSecret, d.Cfg.GitHubRedirectURI, code)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "github token exchange failed"})
			return
		}

		ghUser, err := githubUserInfo(ctx, accessToken)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "github userinfo failed"})
			return
		}

		u, err := d.UserSvc.FindOrCreateBySocial(ctx, "github", fmt.Sprintf("%d", ghUser.ID), ghUser.Email, ghUser.Name, ghUser.AvatarURL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}

		if d.Audit != nil {
			d.Audit.Log("login.social", u.Username, "github", r.RemoteAddr, r.UserAgent(), nil)
		}

		if completeOAuthFromSocial(w, r, d, u.ID) {
			return
		}

		token, err := d.Issuer.IssueAccessToken(u.Username, "sinauth-dashboard", []string{"openid", "profile", "email"}, d.Cfg.AccessTokenTTL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}
		redirectWithToken(w, r, d.Cfg.SiteURL, token)
	}
}

type githubUser struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func githubExchangeCode(ctx context.Context, clientID, clientSecret, redirectURI, code string) (string, error) {
	body := url.Values{
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURI},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token",
		strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var res struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	if res.Error != "" {
		return "", fmt.Errorf("github: %s", res.Error)
	}
	return res.AccessToken, nil
}

func githubUserInfo(ctx context.Context, accessToken string) (*githubUser, error) {
	doReq := func(urlStr string, out any) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return json.Unmarshal(b, out)
	}

	var u githubUser
	if err := doReq("https://api.github.com/user", &u); err != nil {
		return nil, err
	}
	if u.ID == 0 {
		return nil, fmt.Errorf("github: empty user response")
	}

	// GitHub may not expose email in the /user endpoint — fetch it separately.
	if u.Email == "" {
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := doReq("https://api.github.com/user/emails", &emails); err == nil {
			for _, e := range emails {
				if e.Primary && e.Verified {
					u.Email = e.Email
					break
				}
			}
			// fallback: first verified
			if u.Email == "" {
				for _, e := range emails {
					if e.Verified {
						u.Email = e.Email
						break
					}
				}
			}
		}
	}

	// Use login as name fallback.
	if u.Name == "" {
		u.Name = u.Login
	}

	// Generate placeholder email if still empty (private GitHub account).
	if u.Email == "" {
		u.Email = fmt.Sprintf("%s+%d@users.noreply.github.com", u.Login, u.ID)
	}

	return &u, nil
}
