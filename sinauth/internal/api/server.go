package api

import (
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/sinauth/internal/api/handlers"
	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/audit"
	"github.com/opensecstack/sinauth/internal/client"
	"github.com/opensecstack/sinauth/internal/config"
	"github.com/opensecstack/sinauth/internal/consent"
	"github.com/opensecstack/sinauth/internal/email"
	"github.com/opensecstack/sinauth/internal/federation"
	"github.com/opensecstack/sinauth/internal/keys"
	"github.com/opensecstack/sinauth/internal/mfa"
	"github.com/opensecstack/sinauth/internal/oidc"
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
	rbacStore    := rbac.NewStore(pool)
	auditStore   := audit.NewStore(pool)

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
	adminAuth := middleware.BearerAuth(verifier)
	mux.Handle("GET /api/v1/admin/clients",          adminAuth(http.HandlerFunc(handlers.ListClients(d))))
	mux.Handle("POST /api/v1/admin/clients",         adminAuth(http.HandlerFunc(handlers.CreateClient(d))))
	mux.Handle("DELETE /api/v1/admin/clients/{id}",  adminAuth(http.HandlerFunc(handlers.DeleteClient(d))))
	mux.Handle("GET /api/v1/admin/users",            adminAuth(http.HandlerFunc(handlers.ListUsers(d))))
	mux.Handle("POST /api/v1/admin/users/{id}/deactivate", adminAuth(http.HandlerFunc(handlers.DeactivateUser(d))))
	mux.Handle("GET /api/v1/admin/audit",            adminAuth(http.HandlerFunc(handlers.ListAuditLog(d))))
	mux.Handle("GET /api/v1/admin/sessions",         adminAuth(http.HandlerFunc(handlers.ListSessions(d))))
	mux.Handle("DELETE /api/v1/admin/sessions/{id}", adminAuth(http.HandlerFunc(handlers.RevokeSession(d))))

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
	mux.HandleFunc("GET /api/v1/federation/providers",          handlers.ListIdentityProviders(d))
	mux.Handle("POST /admin/federation/providers",              adminAuth(http.HandlerFunc(handlers.CreateIdentityProvider(d))))
	mux.Handle("DELETE /admin/federation/providers/{id}",       adminAuth(http.HandlerFunc(handlers.DeleteIdentityProvider(d))))
	mux.HandleFunc("GET /federation/oidc/{slug}/authorize",     handlers.InitiateOIDCUpstream(d))
	mux.HandleFunc("GET /federation/oidc/{slug}/callback",      handlers.OIDCUpstreamCallback(d))
	mux.HandleFunc("POST /federation/ldap/{slug}/login",        handlers.LDAPLogin(d))
	mux.HandleFunc("GET /federation/saml/{slug}/login",         handlers.InitiateSAML(d))
	mux.HandleFunc("POST /federation/saml/{slug}/acs",          handlers.SAMLAcs(d))

	// ── RBAC admin ───────────────────────────────────────────────────────────
	mux.Handle("GET /admin/rbac/groups",                          adminAuth(http.HandlerFunc(handlers.ListGroups(d))))
	mux.Handle("POST /admin/rbac/groups",                         adminAuth(http.HandlerFunc(handlers.CreateGroup(d))))
	mux.Handle("DELETE /admin/rbac/groups/{id}",                  adminAuth(http.HandlerFunc(handlers.DeleteGroup(d))))
	mux.Handle("GET /admin/rbac/groups/{id}/members",             adminAuth(http.HandlerFunc(handlers.ListGroupMembers(d))))
	mux.Handle("POST /admin/rbac/groups/{id}/members",            adminAuth(http.HandlerFunc(handlers.AddGroupMember(d))))
	mux.Handle("DELETE /admin/rbac/groups/{id}/members/{userId}", adminAuth(http.HandlerFunc(handlers.RemoveGroupMember(d))))
	mux.Handle("POST /admin/rbac/groups/{id}/roles",              adminAuth(http.HandlerFunc(handlers.AssignGroupRole(d))))
	mux.Handle("GET /admin/rbac/clients/{clientId}/roles",        adminAuth(http.HandlerFunc(handlers.ListClientRoles(d))))
	mux.Handle("POST /admin/rbac/clients/{clientId}/roles",       adminAuth(http.HandlerFunc(handlers.CreateClientRole(d))))
	mux.Handle("DELETE /admin/rbac/roles/{id}",                   adminAuth(http.HandlerFunc(handlers.DeleteClientRole(d))))
	mux.Handle("POST /admin/rbac/users/{userId}/roles",           adminAuth(http.HandlerFunc(handlers.AssignUserRole(d))))
	mux.Handle("DELETE /admin/rbac/users/{userId}/roles",         adminAuth(http.HandlerFunc(handlers.RevokeUserRole(d))))
	mux.Handle("GET /admin/rbac/users/{userId}/effective-roles",  adminAuth(http.HandlerFunc(handlers.GetUserEffectiveRoles(d))))
	mux.Handle("GET /admin/rbac/policies",                        adminAuth(http.HandlerFunc(handlers.ListPolicies(d))))
	mux.Handle("POST /admin/rbac/policies",                       adminAuth(http.HandlerFunc(handlers.CreatePolicy(d))))
	mux.Handle("DELETE /admin/rbac/policies/{id}",                adminAuth(http.HandlerFunc(handlers.DeletePolicy(d))))

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
