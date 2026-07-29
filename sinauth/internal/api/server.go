package api

import (
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/sinauth/internal/api/handlers"
	"github.com/opensecstack/sinauth/internal/api/middleware"
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

func NewServer(cfg *config.Config, pool *pgxpool.Pool, km *keys.Manager) http.Handler {
	// build all stores and services
	clientStore  := client.NewStore(pool)
	clientSvc    := client.NewService(clientStore)
	consentStore := consent.NewStore(pool)
	consentSvc   := consent.NewService(consentStore)
	sessionStore := session.NewStore(pool)
	sessionSvc   := session.NewService(sessionStore)
	userStore    := user.NewStore(pool)
	userSvc      := user.NewService(userStore, cfg.BcryptCost)
	tokenStore   := token.NewStore(pool)
	issuer       := token.NewIssuer(km.PrivateKey(), km.KeyID(), cfg.Issuer)
	verifier     := token.NewVerifier(km.PublicKey(), cfg.Issuer)
	discovery    := oidc.Build(cfg.Issuer)
	fedStore     := federation.NewStore(pool)
	// authzChecker is the single authorization-engine handle used to sync
	// RBAC/organization relationship writes to Permify (best-effort — see
	// rbac.Store/organization.Store's syncWrite/syncDelete comments), and to
	// evaluate real per-resource permissions (rbac.Store.Evaluate, the
	// org-delegation check in organization.go). Construction is centralized
	// in authz.New(cfg): real Permify when configured, NoopChecker
	// (fail-open, no-op sync) otherwise — the same real-vs-noop pattern the
	// SMS provider below uses.
	authzChecker := authz.New(cfg)
	rbacStore    := rbac.NewStore(pool, authzChecker)
	auditStore   := audit.NewStore(pool)
	orgStore     := organization.NewStore(pool, authzChecker)

	mailer := email.New(email.Config{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
		SiteURL:  cfg.SiteURL,
	})

	// WebAuthn / FIDO2
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.WebAuthnRPDisplayName,
		RPID:          cfg.WebAuthnRPID,
		RPOrigins:     cfg.WebAuthnOrigins,
	})
	if err != nil {
		panic("sinauth: failed to init webauthn: " + err.Error())
	}

	// SMS provider: use Twilio when configured, fall back to noop in dev.
	var smsProvider mfa.SMSProvider
	if cfg.SMSEnabled {
		smsProvider = &mfa.TwilioProvider{
			AccountSID: cfg.TwilioSID,
			AuthToken:  cfg.TwilioToken,
			From:       cfg.TwilioFrom,
		}
	} else {
		smsProvider = &mfa.NoopSMSProvider{}
	}

	d := handlers.Deps{
		Pool:       pool,
		Cfg:        cfg,
		Keys:       km,
		Issuer:     issuer,
		Verifier:   verifier,
		TokenStore: tokenStore,
		ClientSvc:  clientSvc,
		ConsentSvc: consentSvc,
		SessionSvc: sessionSvc,
		UserSvc:    userSvc,
		Discovery:  discovery,
		Mailer:     mailer,
		WebAuthn:   wa,
		SMS:        smsProvider,
		FedStore:   fedStore,
		RBAC:       rbacStore,
		Audit:      auditStore,
		OrgSvc:     orgStore,
		Authz:      authzChecker,
	}

	mux := http.NewServeMux()

	// ── OIDC discovery ──────────────────────────────────────────────────────
	mux.HandleFunc("GET /.well-known/openid-configuration", handlers.Discovery(d))
	mux.HandleFunc("GET /.well-known/jwks.json",            handlers.JWKS(d))

	// ── OAuth2 / OIDC protocol endpoints ────────────────────────────────────
	mux.HandleFunc("GET /oauth/authorize",         handlers.AuthorizeGET(d))
	mux.HandleFunc("POST /oauth/authorize",        handlers.AuthorizePOST(d))
	mux.HandleFunc("POST /oauth/token",            handlers.Token(d))
	mux.Handle("GET /oauth/userinfo",              middleware.BearerAuth(verifier)(http.HandlerFunc(handlers.UserInfo(d))))
	mux.Handle("POST /oauth/userinfo",             middleware.BearerAuth(verifier)(http.HandlerFunc(handlers.UserInfo(d))))
	mux.HandleFunc("POST /oauth/token/revoke",     handlers.Revoke(d))
	mux.HandleFunc("POST /oauth/token/introspect", handlers.Introspect(d))
	mux.HandleFunc("GET /oauth/endsession",        handlers.EndSession(d))

	// ── Social OAuth ─────────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/auth/google",          handlers.GoogleOAuthStart(d))
	mux.HandleFunc("GET /api/v1/auth/google/callback", handlers.GoogleOAuthCallback(d))
	mux.HandleFunc("GET /api/v1/auth/github",          handlers.GitHubOAuthStart(d))
	mux.HandleFunc("GET /api/v1/auth/github/callback", handlers.GitHubOAuthCallback(d))

	// ── User auth (login / register / password) ──────────────────────────────
	authRL := middleware.RateLimit(cfg.RateLimitAuthPerMin, time.Minute, cfg.TrustedProxies...)
	mux.Handle("POST /api/v1/auth/login",           authRL(http.HandlerFunc(handlers.Login(d))))
	mux.Handle("POST /api/v1/auth/register",        authRL(http.HandlerFunc(handlers.Register(d))))
	mux.Handle("POST /api/v1/auth/forgot-password", authRL(http.HandlerFunc(handlers.ForgotPassword(d))))
	mux.Handle("POST /api/v1/auth/reset-password",  authRL(http.HandlerFunc(handlers.ResetPassword(d))))
	mux.HandleFunc("GET /api/v1/auth/verify-email",         handlers.VerifyEmail(d))
	mux.Handle("POST /api/v1/auth/resend-verification", authRL(http.HandlerFunc(handlers.ResendVerification(d))))

	// ── Admin (client management) ────────────────────────────────────────────
	// These routes require platform-admin standing (RequireAdmin), not just a
	// validly-signed token — see auth.go.
	adminAuth := middleware.BearerAuth(verifier)
	requireAdmin := middleware.RequireAdmin(verifier, userSvc)
	mux.Handle("GET /api/v1/admin/clients",          requireAdmin(http.HandlerFunc(handlers.ListClients(d))))
	mux.Handle("POST /api/v1/admin/clients",         requireAdmin(http.HandlerFunc(handlers.CreateClient(d))))
	mux.Handle("DELETE /api/v1/admin/clients/{id}",  requireAdmin(http.HandlerFunc(handlers.DeleteClient(d))))
	mux.Handle("GET /api/v1/admin/users",            requireAdmin(http.HandlerFunc(handlers.ListUsers(d))))
	mux.Handle("POST /api/v1/admin/users/{id}/deactivate", requireAdmin(http.HandlerFunc(handlers.DeactivateUser(d))))
	mux.Handle("GET /api/v1/admin/audit",            requireAdmin(http.HandlerFunc(handlers.ListAuditLog(d))))
	mux.Handle("GET /api/v1/admin/sessions",         requireAdmin(http.HandlerFunc(handlers.ListSessions(d))))
	mux.Handle("DELETE /api/v1/admin/sessions/{id}", requireAdmin(http.HandlerFunc(handlers.RevokeSession(d))))

	// ── MFA: WebAuthn / FIDO2 ────────────────────────────────────────────────
	mux.Handle("POST /api/v1/mfa/webauthn/register/begin",
		adminAuth(http.HandlerFunc(handlers.BeginWebAuthnRegister(d))))
	mux.Handle("POST /api/v1/mfa/webauthn/register/finish",
		adminAuth(http.HandlerFunc(handlers.FinishWebAuthnRegister(d))))
	mux.HandleFunc("POST /api/v1/mfa/webauthn/login/begin",  handlers.BeginWebAuthnLogin(d))
	mux.HandleFunc("POST /api/v1/mfa/webauthn/login/finish", handlers.FinishWebAuthnLogin(d))
	mux.Handle("GET /api/v1/mfa/webauthn/credentials",
		adminAuth(http.HandlerFunc(handlers.ListWebAuthnCredentials(d))))
	mux.Handle("DELETE /api/v1/mfa/webauthn/credentials/{id}",
		adminAuth(http.HandlerFunc(handlers.DeleteWebAuthnCredential(d))))

	// ── MFA: SMS OTP ─────────────────────────────────────────────────────────
	mux.Handle("POST /api/v1/mfa/sms/send",   adminAuth(http.HandlerFunc(handlers.SendSMSOTP(d))))
	mux.Handle("POST /api/v1/mfa/sms/verify", adminAuth(http.HandlerFunc(handlers.VerifySMSOTP(d))))

	// ── Federation (SSO / external IDPs) ────────────────────────────────────
	// Provider admin routes require platform-admin standing (RequireAdmin),
	// not just a validly-signed token — see auth.go.
	mux.HandleFunc("GET /api/v1/federation/providers",          handlers.ListIdentityProviders(d))
	mux.Handle("POST /admin/federation/providers",              requireAdmin(http.HandlerFunc(handlers.CreateIdentityProvider(d))))
	mux.Handle("DELETE /admin/federation/providers/{id}",       requireAdmin(http.HandlerFunc(handlers.DeleteIdentityProvider(d))))
	mux.HandleFunc("GET /federation/oidc/{slug}/authorize",     handlers.InitiateOIDCUpstream(d))
	mux.HandleFunc("GET /federation/oidc/{slug}/callback",      handlers.OIDCUpstreamCallback(d))
	mux.HandleFunc("POST /federation/ldap/{slug}/login",        handlers.LDAPLogin(d))
	mux.HandleFunc("GET /federation/saml/{slug}/login",         handlers.InitiateSAML(d))
	mux.HandleFunc("POST /federation/saml/{slug}/acs",          handlers.SAMLAcs(d))

	// ── RBAC admin ───────────────────────────────────────────────────────────
	// All /admin/rbac/* routes require platform-admin standing (RequireAdmin),
	// not just a validly-signed token — see auth.go.
	mux.Handle("GET /admin/rbac/groups",                          requireAdmin(http.HandlerFunc(handlers.ListGroups(d))))
	mux.Handle("POST /admin/rbac/groups",                         requireAdmin(http.HandlerFunc(handlers.CreateGroup(d))))
	mux.Handle("DELETE /admin/rbac/groups/{id}",                  requireAdmin(http.HandlerFunc(handlers.DeleteGroup(d))))
	mux.Handle("GET /admin/rbac/groups/{id}/members",             requireAdmin(http.HandlerFunc(handlers.ListGroupMembers(d))))
	mux.Handle("POST /admin/rbac/groups/{id}/members",            requireAdmin(http.HandlerFunc(handlers.AddGroupMember(d))))
	mux.Handle("DELETE /admin/rbac/groups/{id}/members/{userId}", requireAdmin(http.HandlerFunc(handlers.RemoveGroupMember(d))))
	mux.Handle("POST /admin/rbac/groups/{id}/roles",              requireAdmin(http.HandlerFunc(handlers.AssignGroupRole(d))))
	mux.Handle("GET /admin/rbac/clients/{clientId}/roles",        requireAdmin(http.HandlerFunc(handlers.ListClientRoles(d))))
	mux.Handle("POST /admin/rbac/clients/{clientId}/roles",       requireAdmin(http.HandlerFunc(handlers.CreateClientRole(d))))
	mux.Handle("DELETE /admin/rbac/roles/{id}",                   requireAdmin(http.HandlerFunc(handlers.DeleteClientRole(d))))
	mux.Handle("POST /admin/rbac/users/{userId}/roles",           requireAdmin(http.HandlerFunc(handlers.AssignUserRole(d))))
	mux.Handle("DELETE /admin/rbac/users/{userId}/roles",         requireAdmin(http.HandlerFunc(handlers.RevokeUserRole(d))))
	mux.Handle("GET /admin/rbac/users/{userId}/effective-roles",  requireAdmin(http.HandlerFunc(handlers.GetUserEffectiveRoles(d))))
	mux.Handle("GET /admin/rbac/policies",                        requireAdmin(http.HandlerFunc(handlers.ListPolicies(d))))
	mux.Handle("POST /admin/rbac/policies",                       requireAdmin(http.HandlerFunc(handlers.CreatePolicy(d))))
	mux.Handle("DELETE /admin/rbac/policies/{id}",                requireAdmin(http.HandlerFunc(handlers.DeletePolicy(d))))

	// ── Organizations admin ─────────────────────────────────────────────────
	// All routes require platform-admin standing (RequireAdmin), not just a
	// validly-signed token — see auth.go. This is the model documented in
	// SECURITY.md: organization membership/roles are platform-admin-managed
	// only in this fix; a finer per-org-owner permission model is future work.
	mux.Handle("GET /admin/organizations",                          requireAdmin(http.HandlerFunc(handlers.ListOrganizations(d))))
	mux.Handle("POST /admin/organizations",                         requireAdmin(http.HandlerFunc(handlers.CreateOrganization(d))))
	mux.Handle("GET /admin/organizations/{id}",                     requireAdmin(http.HandlerFunc(handlers.GetOrganization(d))))
	mux.Handle("DELETE /admin/organizations/{id}",                  requireAdmin(http.HandlerFunc(handlers.DeleteOrganization(d))))
	mux.Handle("GET /admin/organizations/{id}/members",             requireAdmin(http.HandlerFunc(handlers.ListOrganizationMembers(d))))
	mux.Handle("POST /admin/organizations/{id}/members",            requireAdmin(http.HandlerFunc(handlers.AddOrganizationMember(d))))
	mux.Handle("DELETE /admin/organizations/{id}/members/{userId}", requireAdmin(http.HandlerFunc(handlers.RemoveOrganizationMember(d))))

	// ── Organizations self-service delegation (Permify Phase 1) ────────────
	// Additive, NOT a replacement for the /admin/organizations/* routes
	// above: BearerAuth only at the route level, with the handler itself
	// enforcing "platform admin OR org owner/admin per authz.Checker" (see
	// handlers.callerCanManageOrg's doc comment for why this is a separate
	// route rather than a loosened admin route).
	mux.Handle("POST /api/v1/organizations/{id}/members",            adminAuth(http.HandlerFunc(handlers.AddOwnOrganizationMember(d))))
	mux.Handle("DELETE /api/v1/organizations/{id}/members/{userId}", adminAuth(http.HandlerFunc(handlers.RemoveOwnOrganizationMember(d))))

	// ── Users (self-service) ─────────────────────────────────────────────────
	mux.Handle("GET /api/v1/users/me/organizations",
		middleware.BearerAuth(verifier)(http.HandlerFunc(handlers.MyOrganizations(d))))

	// ── Health ───────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/health", handlers.Health(d))
	mux.HandleFunc("GET /api/v1/ready",  handlers.Ready(d))

	// Middleware chain: CORS → MaxBody → Logger → RateLimit(120/min) → mux
	allowedOrigins := cfg.AllowedOrigins
	if len(allowedOrigins) == 0 && cfg.SiteURL != "" {
		allowedOrigins = []string{cfg.SiteURL}
	}
	return middleware.CORS(allowedOrigins)(
		middleware.MaxBodySize(
			middleware.Logger(
				middleware.RateLimit(cfg.RateLimitGlobalPerMin, time.Minute, cfg.TrustedProxies...)(mux),
			),
		),
	)
}
