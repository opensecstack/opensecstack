// Package meetings provides the Phase 4.3 meeting-platform integration
// scaffolding for Zoom, Microsoft Teams, and Cisco WebEx. OAuth2 flows,
// incoming webhook validation, and event parsing live here; HTTP handler
// wiring lives in internal/api/handlers/meetings.go.
package meetings

// MeetingPlatform is a type-safe identifier for each supported platform.
type MeetingPlatform string

const (
	PlatformZoom  MeetingPlatform = "zoom"
	PlatformTeams MeetingPlatform = "teams"
	PlatformWebEx MeetingPlatform = "webex"
)

// PlatformConfig holds the OAuth2 app credentials and webhook validation
// secret for a single meeting platform. One entry per platform; wired
// via VERTGUARD_MEETING_<PLATFORM>_* env vars (see internal/config).
type PlatformConfig struct {
	// Platform identifies which vendor this config applies to.
	Platform MeetingPlatform

	// ClientID is the OAuth2 app client ID issued by the platform developer
	// portal (Zoom Marketplace / Azure App Registration / Webex Developer).
	ClientID string

	// ClientSecret is the OAuth2 app client secret. Treat as a secret
	// credential — load from env, never hard-code.
	ClientSecret string

	// WebhookSecret is the HMAC shared secret used to validate inbound
	// platform webhook payloads. Zoom calls this the "Webhook Secret Token";
	// WebEx calls it the shared secret configured on the webhook resource.
	WebhookSecret string

	// Enabled gates route registration and token exchange for this platform.
	// When false the platform appears in /status with oauth_configured=false.
	Enabled bool
}
