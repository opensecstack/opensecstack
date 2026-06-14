package federation

import (
	"context"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// LDAPUser holds the attributes returned by an LDAP bind+search.
type LDAPUser struct {
	Username    string
	Email       string
	DisplayName string
	ExternalID  string // DN
}

// AuthenticateLDAP binds with the user credentials and searches for their entry.
func AuthenticateLDAP(_ context.Context, p *Provider, username, password string) (*LDAPUser, error) {
	var conn *ldap.Conn
	var err error

	if p.LDAPTLS {
		conn, err = ldap.DialURL(p.LDAPUrl, ldap.DialWithTLSConfig(nil))
	} else {
		conn, err = ldap.DialURL(p.LDAPUrl)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	defer conn.Close()

	// Service account bind to search.
	if err := conn.Bind(p.LDAPBindDN, p.LDAPBindPassword); err != nil {
		return nil, fmt.Errorf("ldap service bind: %w", err)
	}

	filter := strings.ReplaceAll(p.LDAPUserFilter, "{username}", ldap.EscapeFilter(username))
	sr, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     p.LDAPBaseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     filter,
		Attributes: []string{p.LDAPAttrUsername, p.LDAPAttrEmail, p.LDAPAttrDisplay, "dn"},
	})
	if err != nil || len(sr.Entries) == 0 {
		return nil, fmt.Errorf("ldap user not found")
	}

	entry := sr.Entries[0]

	// Verify the user's own password via a second bind.
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, fmt.Errorf("ldap user bind failed: invalid credentials")
	}

	return &LDAPUser{
		Username:    entry.GetAttributeValue(p.LDAPAttrUsername),
		Email:       entry.GetAttributeValue(p.LDAPAttrEmail),
		DisplayName: entry.GetAttributeValue(p.LDAPAttrDisplay),
		ExternalID:  entry.DN,
	}, nil
}
