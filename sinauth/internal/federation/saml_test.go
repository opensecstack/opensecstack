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
