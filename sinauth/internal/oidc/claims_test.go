package oidc

import "testing"

func TestUserClaims_Filter_AlwaysIncludesSub(t *testing.T) {
	c := &UserClaims{Sub: "user-123"}
	out := c.Filter(nil)

	if len(out) != 1 {
		t.Fatalf("Filter(nil) = %v, want only {sub}", out)
	}
	if out["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", out["sub"])
	}
}

func TestUserClaims_Filter_ProfileScope(t *testing.T) {
	c := &UserClaims{
		Sub:     "user-123",
		Name:    "Alice",
		Picture: "https://example.com/pic.png",
		Email:   "alice@example.com",
	}
	out := c.Filter([]string{"profile"})

	if out["name"] != "Alice" {
		t.Errorf("name = %v, want Alice", out["name"])
	}
	if out["picture"] != "https://example.com/pic.png" {
		t.Errorf("picture = %v, want the picture URL", out["picture"])
	}
	if _, present := out["email"]; present {
		t.Errorf("email should not be present without the email scope, got %v", out["email"])
	}
}

func TestUserClaims_Filter_EmailScope(t *testing.T) {
	c := &UserClaims{
		Sub:           "user-123",
		Email:         "alice@example.com",
		EmailVerified: true,
	}
	out := c.Filter([]string{"email"})

	if out["email"] != "alice@example.com" {
		t.Errorf("email = %v, want alice@example.com", out["email"])
	}
	if out["email_verified"] != true {
		t.Errorf("email_verified = %v, want true", out["email_verified"])
	}
	if _, present := out["name"]; present {
		t.Errorf("name should not be present without the profile scope, got %v", out["name"])
	}
}

func TestUserClaims_Filter_UnknownScopeIgnored(t *testing.T) {
	c := &UserClaims{Sub: "user-123", Name: "Alice"}
	out := c.Filter([]string{"offline_access", "some_unknown_scope"})

	if len(out) != 1 {
		t.Fatalf("Filter with only unrecognized scopes = %v, want only {sub}", out)
	}
}

func TestUserClaims_Filter_BothScopes(t *testing.T) {
	c := &UserClaims{
		Sub:           "user-123",
		Name:          "Alice",
		Picture:       "pic-url",
		Email:         "alice@example.com",
		EmailVerified: false,
	}
	out := c.Filter([]string{"profile", "email"})

	want := []string{"sub", "name", "picture", "email", "email_verified"}
	if len(out) != len(want) {
		t.Fatalf("Filter(profile,email) = %v, want keys %v", out, want)
	}
	for _, k := range want {
		if _, present := out[k]; !present {
			t.Errorf("expected key %q to be present, out = %v", k, out)
		}
	}
	if out["email_verified"] != false {
		t.Errorf("email_verified = %v, want false", out["email_verified"])
	}
}
