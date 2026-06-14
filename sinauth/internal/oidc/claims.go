package oidc

// ScopeProfile is the set of claims included when the "profile" scope is granted.
var ScopeProfile = []string{"name", "picture"}

// ScopeEmail is the set of claims included when the "email" scope is granted.
var ScopeEmail = []string{"email", "email_verified"}

// UserClaims holds all possible user claims for an ID token or userinfo response.
type UserClaims struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

// Filter returns only the claims permitted by the granted scopes.
// "sub" is always included. Additional claims are gated by "profile" and "email" scopes.
func (c *UserClaims) Filter(scopes []string) map[string]any {
	out := map[string]any{"sub": c.Sub}
	for _, s := range scopes {
		switch s {
		case "profile":
			out["name"] = c.Name
			out["picture"] = c.Picture
		case "email":
			out["email"] = c.Email
			out["email_verified"] = c.EmailVerified
		}
	}
	return out
}
