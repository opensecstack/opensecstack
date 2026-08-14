package client

import "testing"

func TestService_ValidateRedirectURI(t *testing.T) {
	s := NewService(nil)
	c := &Client{
		RedirectURIs: []string{
			"https://app.example.com/callback",
			"https://app.example.com/other",
		},
	}

	if err := s.ValidateRedirectURI(c, "https://app.example.com/callback"); err != nil {
		t.Errorf("ValidateRedirectURI(exact match) = %v, want nil", err)
	}

	if err := s.ValidateRedirectURI(c, "https://app.example.com/not-registered"); err != ErrInvalidRedirect {
		t.Errorf("ValidateRedirectURI(unregistered) = %v, want ErrInvalidRedirect", err)
	}
}

// TestService_ValidateRedirectURI_RequiresExactMatch is a security-relevant
// regression guard: OAuth redirect_uri validation must be an exact string
// match, never a prefix/substring match. A prefix match would let an
// attacker register (or abuse) a redirect_uri like
// "https://app.example.com/callback.attacker.com" or append arbitrary path
// segments/query strings to exfiltrate the authorization code.
func TestService_ValidateRedirectURI_RequiresExactMatch(t *testing.T) {
	s := NewService(nil)
	c := &Client{RedirectURIs: []string{"https://app.example.com/callback"}}

	cases := []string{
		"https://app.example.com/callback/",
		"https://app.example.com/callback?extra=1",
		"https://app.example.com/callbackxyz",
		"https://app.example.com/callback#frag",
		"http://app.example.com/callback", // scheme downgrade
	}
	for _, uri := range cases {
		if err := s.ValidateRedirectURI(c, uri); err != ErrInvalidRedirect {
			t.Errorf("ValidateRedirectURI(%q) = %v, want ErrInvalidRedirect (must be exact match, not prefix)", uri, err)
		}
	}
}

func TestService_ValidateScopes(t *testing.T) {
	s := NewService(nil)
	c := &Client{AllowedScopes: []string{"openid", "profile", "email"}}

	if err := s.ValidateScopes(c, []string{"openid", "email"}); err != nil {
		t.Errorf("ValidateScopes(subset) = %v, want nil", err)
	}

	if err := s.ValidateScopes(c, []string{"openid", "admin"}); err != ErrInvalidScope {
		t.Errorf("ValidateScopes(with disallowed scope) = %v, want ErrInvalidScope", err)
	}
}

func TestService_ValidateScopes_EmptyRequestedIsAlwaysValid(t *testing.T) {
	s := NewService(nil)
	c := &Client{AllowedScopes: []string{"openid"}}

	if err := s.ValidateScopes(c, nil); err != nil {
		t.Errorf("ValidateScopes(nil requested) = %v, want nil", err)
	}
}

// TestService_ValidateScopes_NoAllowedScopesRejectsAny proves a client with
// no configured AllowedScopes cannot be granted any scope at all — this is
// the fail-closed behavior a misconfigured/newly-created client should have,
// rather than accidentally allow-all.
func TestService_ValidateScopes_NoAllowedScopesRejectsAny(t *testing.T) {
	s := NewService(nil)
	c := &Client{}

	if err := s.ValidateScopes(c, []string{"openid"}); err != ErrInvalidScope {
		t.Errorf("ValidateScopes(client with no allowed scopes) = %v, want ErrInvalidScope", err)
	}
}
