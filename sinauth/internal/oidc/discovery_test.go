package oidc

import (
	"slices"
	"testing"
)

func TestBuild_EndpointsDerivedFromIssuer(t *testing.T) {
	doc := Build("https://auth.sin.to")

	cases := map[string]string{
		"Issuer":                doc.Issuer,
		"AuthorizationEndpoint": doc.AuthorizationEndpoint,
		"TokenEndpoint":         doc.TokenEndpoint,
		"UserinfoEndpoint":      doc.UserinfoEndpoint,
		"JWKSUri":               doc.JWKSUri,
		"EndSessionEndpoint":    doc.EndSessionEndpoint,
		"RevocationEndpoint":    doc.RevocationEndpoint,
		"IntrospectionEndpoint": doc.IntrospectionEndpoint,
	}
	want := map[string]string{
		"Issuer":                "https://auth.sin.to",
		"AuthorizationEndpoint": "https://auth.sin.to/oauth/authorize",
		"TokenEndpoint":         "https://auth.sin.to/oauth/token",
		"UserinfoEndpoint":      "https://auth.sin.to/oauth/userinfo",
		"JWKSUri":               "https://auth.sin.to/.well-known/jwks.json",
		"EndSessionEndpoint":    "https://auth.sin.to/oauth/endsession",
		"RevocationEndpoint":    "https://auth.sin.to/oauth/token/revoke",
		"IntrospectionEndpoint": "https://auth.sin.to/oauth/token/introspect",
	}
	for field, got := range cases {
		if got != want[field] {
			t.Errorf("%s = %q, want %q", field, got, want[field])
		}
	}
}

func TestBuild_RequiredCapabilitiesAdvertised(t *testing.T) {
	doc := Build("https://auth.sin.to")

	if !slices.Contains(doc.ScopesSupported, "openid") {
		t.Errorf("ScopesSupported = %v, want to include openid", doc.ScopesSupported)
	}
	if !slices.Contains(doc.GrantTypesSupported, "authorization_code") {
		t.Errorf("GrantTypesSupported = %v, want to include authorization_code", doc.GrantTypesSupported)
	}
	if !slices.Contains(doc.ResponseTypesSupported, "code") {
		t.Errorf("ResponseTypesSupported = %v, want to include code", doc.ResponseTypesSupported)
	}
	if !slices.Contains(doc.IDTokenSigningAlgValuesSupported, "RS256") {
		t.Errorf("IDTokenSigningAlgValuesSupported = %v, want to include RS256", doc.IDTokenSigningAlgValuesSupported)
	}
	// "none" auth method must only ever be advertised alongside real methods —
	// this locks in that public (PKCE) clients aren't the *only* supported flow.
	if !slices.Contains(doc.TokenEndpointAuthMethodsSupported, "client_secret_basic") {
		t.Errorf("TokenEndpointAuthMethodsSupported = %v, want to include client_secret_basic", doc.TokenEndpointAuthMethodsSupported)
	}
}
