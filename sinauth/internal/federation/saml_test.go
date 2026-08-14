package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// generateTestCert creates a self-signed cert and returns its PEM encoding.
func generateTestCert(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	var buf []byte
	buf = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(buf)
}

func TestParsePEMCertificate_PEM(t *testing.T) {
	pemStr := generateTestCert(t)
	cert, err := parsePEMCertificate(pemStr)
	if err != nil {
		t.Fatalf("parsePEMCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestParsePEMCertificate_Base64DER(t *testing.T) {
	pemStr := generateTestCert(t)
	block, _ := pem.Decode([]byte(pemStr))
	b64 := base64.StdEncoding.EncodeToString(block.Bytes)
	cert, err := parsePEMCertificate(b64)
	if err != nil {
		t.Fatalf("parsePEMCertificate(base64 DER): %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestParsePEMCertificate_Invalid(t *testing.T) {
	_, err := parsePEMCertificate("not-a-cert")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

// makeAssertion builds a minimal SAML assertion with the given attributes.
func makeAssertion(nameID string, attrs map[string]string) *saml.Assertion {
	a := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: nameID},
		},
	}
	if len(attrs) > 0 {
		stmt := saml.AttributeStatement{}
		for k, v := range attrs {
			stmt.Attributes = append(stmt.Attributes, saml.Attribute{
				Name:   k,
				Values: []saml.AttributeValue{{Value: v}},
			})
		}
		a.AttributeStatements = []saml.AttributeStatement{stmt}
	}
	return a
}

// extractAttributes replicates the attribute-extraction logic from ParseSAMLResponse
// so we can test it without a full HTTP round-trip.
func extractAttributes(assertion *saml.Assertion) (nameID, email, displayName string) {
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
	}

	emailNames := []string{
		"email", "mail", "Email",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"urn:oid:0.9.2342.19200300.100.1.3",
	}
	displayNames := []string{
		"displayName", "display_name", "cn",
		"http://schemas.microsoft.com/identity/claims/displayname",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"urn:oid:2.16.840.1.113730.3.1.241",
	}

	attrMap := make(map[string]string)
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) > 0 {
				attrMap[attr.Name] = attr.Values[0].Value
				if attr.FriendlyName != "" {
					attrMap[attr.FriendlyName] = attr.Values[0].Value
				}
			}
		}
	}

	for _, n := range emailNames {
		if v, ok := attrMap[n]; ok && v != "" {
			email = v
			break
		}
	}
	for _, n := range displayNames {
		if v, ok := attrMap[n]; ok && v != "" {
			displayName = v
			break
		}
	}

	if email == "" && len(nameID) > 0 {
		for _, ch := range nameID {
			if ch == '@' {
				email = nameID
				break
			}
		}
	}
	return
}

func TestExtractAttributes_Email(t *testing.T) {
	a := makeAssertion("uid123", map[string]string{"email": "alice@example.com", "displayName": "Alice"})
	nameID, email, dn := extractAttributes(a)
	if nameID != "uid123" {
		t.Errorf("nameID = %q, want %q", nameID, "uid123")
	}
	if email != "alice@example.com" {
		t.Errorf("email = %q, want %q", email, "alice@example.com")
	}
	if dn != "Alice" {
		t.Errorf("displayName = %q, want %q", dn, "Alice")
	}
}

func TestExtractAttributes_MSClaims(t *testing.T) {
	a := makeAssertion("user@corp.com", map[string]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "user@corp.com",
		"http://schemas.microsoft.com/identity/claims/displayname":           "Corp User",
	})
	_, email, dn := extractAttributes(a)
	if email != "user@corp.com" {
		t.Errorf("email = %q", email)
	}
	if dn != "Corp User" {
		t.Errorf("displayName = %q", dn)
	}
}

func TestExtractAttributes_NameIDFallback(t *testing.T) {
	a := makeAssertion("fallback@example.com", nil)
	_, email, _ := extractAttributes(a)
	if email != "fallback@example.com" {
		t.Errorf("email = %q, expected NameID fallback", email)
	}
}

func TestExtractAttributes_NoEmailInNameID(t *testing.T) {
	a := makeAssertion("opaqueUID42", nil)
	_, email, _ := extractAttributes(a)
	if email != "" {
		t.Errorf("email should be empty for opaque NameID, got %q", email)
	}
}

func TestBuildIDPMetadata_NoCert(t *testing.T) {
	p := &Provider{
		SAMLEntityID: "https://idp.example.com",
		SAMLSSOURI:   "https://idp.example.com/sso",
	}
	meta, err := buildIDPMetadata(p)
	if err != nil {
		t.Fatalf("buildIDPMetadata: %v", err)
	}
	if meta.EntityID != p.SAMLEntityID {
		t.Errorf("EntityID = %q, want %q", meta.EntityID, p.SAMLEntityID)
	}
	if len(meta.IDPSSODescriptors) == 0 {
		t.Fatal("expected at least one IDPSSODescriptor")
	}
}

// TestBuildSAMLSP_ManualFields proves BuildSAMLSP constructs a working
// ServiceProvider from individually-configured provider fields (the
// default path, used when no metadata URL/XML is supplied), with the ACS
// URL and entity ID wired through correctly.
func TestBuildSAMLSP_ManualFields(t *testing.T) {
	p := &Provider{
		SAMLEntityID: "https://idp.example.com",
		SAMLSSOURI:   "https://idp.example.com/sso",
	}
	sp, err := BuildSAMLSP(p, "https://sin.to/saml/acs", "https://sin.to")
	if err != nil {
		t.Fatalf("BuildSAMLSP: %v", err)
	}
	if sp.EntityID != "https://sin.to" {
		t.Errorf("EntityID = %q, want https://sin.to", sp.EntityID)
	}
	if sp.AcsURL.String() != "https://sin.to/saml/acs" {
		t.Errorf("AcsURL = %q, want https://sin.to/saml/acs", sp.AcsURL.String())
	}
	if sp.IDPMetadata == nil {
		t.Fatal("expected non-nil IDPMetadata")
	}
	if sp.IDPMetadata.EntityID != p.SAMLEntityID {
		t.Errorf("IDPMetadata.EntityID = %q, want %q", sp.IDPMetadata.EntityID, p.SAMLEntityID)
	}
	// Key/Certificate are intentionally left nil (unsigned AuthnRequests).
	if sp.Key != nil {
		t.Error("expected sp.Key to be nil (unsigned AuthnRequests)")
	}
	if sp.Certificate != nil {
		t.Error("expected sp.Certificate to be nil (unsigned AuthnRequests)")
	}
}

// TestBuildSAMLSP_ParsesMetadataXML proves the SAMLMetadataXML path parses
// IdP metadata directly rather than falling through to the manual-field
// builder or a network fetch.
func TestBuildSAMLSP_ParsesMetadataXML(t *testing.T) {
	metadataXML := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`
	p := &Provider{SAMLMetadataXML: metadataXML}
	sp, err := BuildSAMLSP(p, "https://sin.to/saml/acs", "https://sin.to")
	if err != nil {
		t.Fatalf("BuildSAMLSP: %v", err)
	}
	if sp.IDPMetadata.EntityID != "https://idp.example.com/metadata" {
		t.Errorf("IDPMetadata.EntityID = %q, want https://idp.example.com/metadata", sp.IDPMetadata.EntityID)
	}
}

// TestBuildSAMLSP_InvalidACSURL proves a malformed ACS URL is rejected
// rather than silently producing a broken ServiceProvider.
func TestBuildSAMLSP_InvalidACSURL(t *testing.T) {
	p := &Provider{SAMLEntityID: "https://idp.example.com", SAMLSSOURI: "https://idp.example.com/sso"}
	_, err := BuildSAMLSP(p, "http://%zz", "https://sin.to")
	if err == nil {
		t.Fatal("BuildSAMLSP: expected error for malformed acsURL, got nil")
	}
}

// TestBuildSAMLSP_InvalidCertificate proves a malformed SAML certificate on
// the provider surfaces as an error from BuildSAMLSP rather than a panic or
// a silently-empty KeyDescriptor (which would let responses go unverified).
func TestBuildSAMLSP_InvalidCertificate(t *testing.T) {
	p := &Provider{
		SAMLEntityID:    "https://idp.example.com",
		SAMLSSOURI:      "https://idp.example.com/sso",
		SAMLCertificate: "not-a-cert",
	}
	_, err := BuildSAMLSP(p, "https://sin.to/saml/acs", "https://sin.to")
	if err == nil {
		t.Fatal("BuildSAMLSP: expected error for invalid certificate, got nil")
	}
}

// TestInitiateSAMLLogin_ReturnsRedirectAndRelayState proves InitiateSAMLLogin
// builds a redirect URL pointing at the IdP's SSO endpoint and a non-empty,
// random relay state that isn't embedded verbatim as a query parameter
// value collision (basic sanity, not a full protocol conformance check).
func TestInitiateSAMLLogin_ReturnsRedirectAndRelayState(t *testing.T) {
	p := &Provider{
		SAMLEntityID: "https://idp.example.com",
		SAMLSSOURI:   "https://idp.example.com/sso",
	}
	sp, err := BuildSAMLSP(p, "https://sin.to/saml/acs", "https://sin.to")
	if err != nil {
		t.Fatalf("BuildSAMLSP: %v", err)
	}

	redirectURL, relayState, err := InitiateSAMLLogin(sp)
	if err != nil {
		t.Fatalf("InitiateSAMLLogin: %v", err)
	}
	if relayState == "" {
		t.Error("expected non-empty relay state")
	}
	if !strings.HasPrefix(redirectURL, "https://idp.example.com/sso?") {
		t.Errorf("redirectURL = %q, want prefix https://idp.example.com/sso?", redirectURL)
	}
	if !strings.Contains(redirectURL, "SAMLRequest=") {
		t.Errorf("redirectURL = %q, want it to contain a SAMLRequest param", redirectURL)
	}

	// Two calls must produce different relay states (each login attempt gets
	// its own, unguessable value — reusing one would let an attacker replay
	// or fixate a victim's SSO flow).
	_, relayState2, err := InitiateSAMLLogin(sp)
	if err != nil {
		t.Fatalf("InitiateSAMLLogin (2nd call): %v", err)
	}
	if relayState == relayState2 {
		t.Error("InitiateSAMLLogin produced identical relay states across calls (should be random per attempt)")
	}
}

func TestBuildIDPMetadata_WithCert(t *testing.T) {
	cert := generateTestCert(t)
	p := &Provider{
		SAMLEntityID:    "https://idp.example.com",
		SAMLSSOURI:      "https://idp.example.com/sso",
		SAMLCertificate: cert,
	}
	meta, err := buildIDPMetadata(p)
	if err != nil {
		t.Fatalf("buildIDPMetadata with cert: %v", err)
	}
	kds := meta.IDPSSODescriptors[0].SSODescriptor.RoleDescriptor.KeyDescriptors
	if len(kds) == 0 {
		t.Fatal("expected KeyDescriptor for signing cert")
	}
}
