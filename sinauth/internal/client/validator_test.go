package client

import "testing"

func TestValidateRedirectURIFormat(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"https allowed", "https://app.example.com/callback", false},
		{"http localhost allowed", "http://localhost:5173/callback", false},
		{"http 127.0.0.1 allowed", "http://127.0.0.1:5173/callback", false},
		{"http non-loopback rejected", "http://app.example.com/callback", true},
		// Regression test for a real bypass: a host that merely starts with
		// "localhost" (or "127.0.0.1") but resolves to an attacker-controlled
		// domain must NOT be treated as loopback. See fixed bug in
		// internal/client/validator.go (was using strings.HasPrefix on the
		// host instead of an exact hostname match).
		{"localhost-lookalike host rejected", "http://localhost.attacker.com/callback", true},
		{"127.0.0.1-lookalike host rejected", "http://127.0.0.1.evil.com/callback", true},
		{"malformed URI rejected", "http://%zz", true},
		{"empty string not rejected as http", "", false}, // url.Parse("") succeeds with empty scheme, not http
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURIFormat(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURIFormat(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
			}
		})
	}
}

// TestValidateRedirectURIFormat_HTTPSNeverRejected proves any well-formed
// https URI, regardless of host, is always accepted.
func TestValidateRedirectURIFormat_HTTPSNeverRejected(t *testing.T) {
	uris := []string{
		"https://a.b",
		"https://sub.domain.example.org/path?query=1",
		"https://192.168.1.1/callback",
	}
	for _, u := range uris {
		if err := ValidateRedirectURIFormat(u); err != nil {
			t.Errorf("ValidateRedirectURIFormat(%q) = %v, want nil", u, err)
		}
	}
}
