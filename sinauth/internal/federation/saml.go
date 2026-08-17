package federation

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// BuildSAMLSP constructs a crewjam/saml ServiceProvider for the given provider config.
// acsURL is the full ACS endpoint URL; entityID is sinauth's SP entity ID.
func BuildSAMLSP(provider *Provider, acsURL, entityID string) (*saml.ServiceProvider, error) {
	parsedACS, err := url.Parse(acsURL)
	if err != nil {
		return nil, fmt.Errorf("invalid acsURL: %w", err)
	}

	var idpMeta *saml.EntityDescriptor

	switch {
	case provider.SAMLMetadataURL != "":
		metaURL, err := url.Parse(provider.SAMLMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("invalid metadata URL: %w", err)
		}
		idpMeta, err = samlsp.FetchMetadata(context.Background(), http.DefaultClient, *metaURL)
		if err != nil {
			return nil, fmt.Errorf("fetching IDP metadata: %w", err)
		}

	case provider.SAMLMetadataXML != "":
		idpMeta, err = samlsp.ParseMetadata([]byte(provider.SAMLMetadataXML))
		if err != nil {
			return nil, fmt.Errorf("parsing IDP metadata XML: %w", err)
		}

	default:
		// Build EntityDescriptor manually from individual fields.
		idpMeta, err = buildIDPMetadata(provider)
		if err != nil {
			return nil, fmt.Errorf("building IDP metadata: %w", err)
		}
	}

	sp := &saml.ServiceProvider{
		EntityID:    entityID,
		AcsURL:      *parsedACS,
		IDPMetadata: idpMeta,
		// Key and Certificate intentionally left nil — unsigned AuthnRequests.
	}
	return sp, nil
}

// buildIDPMetadata constructs a minimal saml.EntityDescriptor from provider fields.
func buildIDPMetadata(provider *Provider) (*saml.EntityDescriptor, error) {
	meta := &saml.EntityDescriptor{
		EntityID: provider.SAMLEntityID,
	}

	idpDesc := saml.IDPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{
			RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			},
		},
		SingleSignOnServices: []saml.Endpoint{
			{
				Binding:  saml.HTTPRedirectBinding,
				Location: provider.SAMLSSOURI,
			},
		},
	}

	if provider.SAMLCertificate != "" {
		cert, err := parsePEMCertificate(provider.SAMLCertificate)
		if err != nil {
			return nil, fmt.Errorf("parsing SAML certificate: %w", err)
		}
		certData := base64.StdEncoding.EncodeToString(cert.Raw)
		idpDesc.KeyDescriptors = []saml.KeyDescriptor{
			{
				Use: "signing",
				KeyInfo: saml.KeyInfo{
					X509Data: saml.X509Data{
						X509Certificates: []saml.X509Certificate{
							{Data: certData},
						},
					},
				},
			},
		}
	}

	meta.IDPSSODescriptors = []saml.IDPSSODescriptor{idpDesc}
	return meta, nil
}

// parsePEMCertificate decodes a PEM block and parses an x509 certificate.
func parsePEMCertificate(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		// Try base64-encoded DER directly (no PEM headers).
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pemStr))
		if err != nil {
			return nil, errors.New("certificate is neither valid PEM nor base64 DER")
		}
		return x509.ParseCertificate(der)
	}
	return x509.ParseCertificate(block.Bytes)
}

// InitiateSAMLLogin builds an AuthnRequest and returns the redirect URL and relay state.
func InitiateSAMLLogin(sp *saml.ServiceProvider) (redirectURL string, relayState string, err error) {
	relayState, err = GenerateState() // reuse existing hex-random helper
	if err != nil {
		return "", "", fmt.Errorf("generating relay state: %w", err)
	}

	ssoURL := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	authReq, err := sp.MakeAuthenticationRequest(ssoURL, saml.HTTPRedirectBinding, saml.HTTPArtifactBinding)
	if err != nil {
		return "", "", fmt.Errorf("building AuthnRequest: %w", err)
	}

	redirectu, err := authReq.Redirect(relayState, sp)
	if err != nil {
		return "", "", fmt.Errorf("encoding redirect URL: %w", err)
	}
	return redirectu.String(), relayState, nil
}

// ParseSAMLResponse validates the SAML response and extracts identity attributes.
func ParseSAMLResponse(sp *saml.ServiceProvider, r *http.Request) (nameID, email, displayName string, err error) {
	if err = r.ParseForm(); err != nil {
		return "", "", "", fmt.Errorf("parsing form: %w", err)
	}

	assertion, err := sp.ParseResponse(r, []string{})
	if err != nil {
		return "", "", "", fmt.Errorf("validating SAML response: %w", err)
	}

	// Extract NameID.
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
	}
	if nameID == "" {
		return "", "", "", errors.New("SAML assertion missing NameID")
	}

	// Extract email and displayName from AttributeStatements.
	emailNames := []string{
		"email",
		"mail",
		"Email",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"urn:oid:0.9.2342.19200300.100.1.3", // eduPerson mail
	}
	displayNames := []string{
		"displayName",
		"display_name",
		"cn",
		"http://schemas.microsoft.com/identity/claims/displayname",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"urn:oid:2.16.840.1.113730.3.1.241", // displayName OID
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

	for _, name := range emailNames {
		if v, ok := attrMap[name]; ok && v != "" {
			email = v
			break
		}
	}
	for _, name := range displayNames {
		if v, ok := attrMap[name]; ok && v != "" {
			displayName = v
			break
		}
	}

	// Fall back to NameID as email if not found.
	if email == "" && strings.Contains(nameID, "@") {
		email = nameID
	}

	return nameID, email, displayName, nil
}
