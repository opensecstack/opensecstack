package config

import "time"

type Config struct {
	HTTPAddr      string
	Node          string
	DevMode       bool
	DBURL         string
	DBMaxConns    int32
	JWTSecret     string
	JWTIssuer     string
	TokenTTL      time.Duration
	Users         []UserEntry
	Pepper        string
	CitadelURL         string
	CitadelHMAC        []string
	CitadelKeyID       string
	CitadelDryRun      bool
	InviteOnly          bool
	NativeAuthEnabled   bool // when false, native email/password endpoints are disabled and SIN SSO is the only login
	AllowedEmailDomains []string
	MeilisearchURL      string
	MeilisearchKey      string
	UploadDir           string
	S3Endpoint          string
	S3Bucket            string
	S3AccessKey         string
	S3SecretKey         string
	S3PublicURL         string
	S3Region            string
	GitHubClientID     string
	GitHubClientSecret string
	GitHubCallbackURL  string
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string
	SinauthURL          string // sinauth base URL for SERVER-side calls (token, userinfo), e.g. "http://sinauth-api:8100"
	SinauthPublicURL    string // sinauth base URL the BROWSER is redirected to for /oauth/authorize, e.g. "http://localhost:8100". Falls back to SinauthURL when unset.
	SinauthClientID     string
	SinauthClientSecret string
	SinauthCallbackURL  string
	SMTPHost            string
	SMTPPort            int
	SMTPUsername        string
	SMTPPassword        string
	SMTPFrom            string
	SiteURL             string
	DigestEnabled   bool
	VAPIDPublicKey  string
	VAPIDPrivateKey string
	VAPIDEmail      string
	TrustedProxies []string
	AllowedOrigins []string
}

type UserEntry struct {
	Username string
	Role     string
	Hash     string
}
