package client

import (
	"errors"
	"net/url"
)

// ValidateRedirectURIFormat checks that the URI is well-formed and uses https
// (or localhost http in dev).
func ValidateRedirectURIFormat(rawURI string) error {
	u, err := url.Parse(rawURI)
	if err != nil {
		return errors.New("invalid redirect_uri format")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" {
			return errors.New("redirect_uri must use https")
		}
	}
	return nil
}
