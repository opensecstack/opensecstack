package federation

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

// OIDCUpstreamClaims holds the minimal claims we extract from upstream ID tokens.
type OIDCUpstreamClaims struct {
	Sub         string `json:"sub"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	PreferredUN string `json:"preferred_username"`
}

// OIDCDiscovery holds the minimal fields from the upstream provider's discovery doc.
type OIDCDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// DiscoverOIDC fetches the OIDC discovery document for an upstream provider.
func DiscoverOIDC(ctx context.Context, issuer string) (*OIDCDiscovery, error) {
	wellKnown := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	var doc OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// BuildAuthURL constructs the upstream authorization redirect URL.
func BuildAuthURL(discovery *OIDCDiscovery, p *Provider, state, nonce, redirectURI string) string {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {p.OIDCClientID},
		"redirect_uri":  {redirectURI},
		"scope":         {strings.Join(p.OIDCScopes, " ")},
		"state":         {state},
		"nonce":         {nonce},
	}
	return discovery.AuthorizationEndpoint + "?" + params.Encode()
}

// ExchangeOIDCCode exchanges the authorization code for tokens and returns user claims.
func ExchangeOIDCCode(ctx context.Context, discovery *OIDCDiscovery, p *Provider, code, redirectURI string) (*OIDCUpstreamClaims, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {p.OIDCClientID},
		"client_secret": {p.OIDCClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	// Fetch userinfo for authoritative claims.
	uiReq, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	uiReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	uiResp, err := http.DefaultClient.Do(uiReq)
	if err != nil {
		return nil, err
	}
	defer uiResp.Body.Close()

	body, _ := io.ReadAll(uiResp.Body)
	var claims OIDCUpstreamClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// GenerateState returns a cryptographically random state string.
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
