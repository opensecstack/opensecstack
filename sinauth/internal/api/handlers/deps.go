package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/sinauth/internal/audit"
	"github.com/opensecstack/sinauth/internal/authz"
	"github.com/opensecstack/sinauth/internal/client"
	"github.com/opensecstack/sinauth/internal/config"
	"github.com/opensecstack/sinauth/internal/consent"
	"github.com/opensecstack/sinauth/internal/email"
	"github.com/opensecstack/sinauth/internal/federation"
	"github.com/opensecstack/sinauth/internal/keys"
	"github.com/opensecstack/sinauth/internal/mfa"
	"github.com/opensecstack/sinauth/internal/oidc"
	"github.com/opensecstack/sinauth/internal/organization"
	"github.com/opensecstack/sinauth/internal/rbac"
	"github.com/opensecstack/sinauth/internal/session"
	"github.com/opensecstack/sinauth/internal/token"
	"github.com/opensecstack/sinauth/internal/user"
)

type Deps struct {
	Pool       *pgxpool.Pool
	Cfg        *config.Config
	Keys       *keys.Manager
	Issuer     *token.Issuer
	Verifier   *token.Verifier
	TokenStore *token.Store
	ClientSvc  *client.Service
	ConsentSvc *consent.Service
	SessionSvc *session.Service
	UserSvc    *user.Service
	Discovery  oidc.DiscoveryDocument
	Mailer     *email.Mailer
	WebAuthn   *webauthn.WebAuthn
	SMS        mfa.SMSProvider
	FedStore   *federation.Store
	RBAC       *rbac.Store
	Audit      *audit.Store
	OrgSvc     *organization.Store
	// Authz is the authorization-engine abstraction (Permify-backed, or a
	// NoopChecker fail-open stand-in when no engine is configured) used for
	// rbac.Evaluate's deny_role check and the per-organization delegation
	// check in organization.go. Never nil in a server built via NewServer —
	// handlers may still guard against nil for standalone unit tests that
	// build a Deps by hand without setting it.
	Authz authz.Checker
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
