package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/integrations/meetings"
)

// meetingsMaxBodyBytes caps inbound webhook bodies from meeting platforms.
// Events are small JSON payloads; anything larger is rejected with 413.
const meetingsMaxBodyBytes = 32 << 10 // 32 KiB

// stateEntry holds an OAuth2 state nonce and its expiry.
type stateEntry struct {
	platform meetings.MeetingPlatform
	expires  time.Time
}

// MeetingsHandler serves the /api/v1/integrations/meetings/* routes.
//
// Platforms is the slice of configured platform adapters; any platform
// with Enabled=false still appears in /status but refuses connect/callback.
// The handler is safe for concurrent use.
type MeetingsHandler struct {
	Platforms []meetings.PlatformConfig
	Logger    zerolog.Logger

	// RedirectBase is the public-facing base URL used to build the
	// redirect_uri forwarded to platform OAuth endpoints.
	// Example: "https://vertguard.example.com"
	RedirectBase string

	// stateMu guards the in-memory nonce store.
	stateMu sync.Mutex
	// states maps nonce → stateEntry; entries expire after 5 minutes.
	states map[string]stateEntry
}

// NewMeetingsHandler returns a MeetingsHandler ready to serve.
func NewMeetingsHandler(platforms []meetings.PlatformConfig, redirectBase string, logger zerolog.Logger) *MeetingsHandler {
	return &MeetingsHandler{
		Platforms:    platforms,
		RedirectBase: redirectBase,
		Logger:       logger.With().Str("handler", "meetings").Logger(),
		states:       make(map[string]stateEntry),
	}
}

// ─── Handlers ────────────────────────────────────────────────────────

// Connect handles GET /api/v1/integrations/meetings/connect/{platform}.
//
// Generates a random state nonce (stored in memory with a 5-minute TTL),
// builds the platform-specific OAuth2 authorize URL, and issues a 302
// redirect to the platform. JWT auth is required — the route is registered
// with auth.RequireRead in server.go.
func (h *MeetingsHandler) Connect(w http.ResponseWriter, r *http.Request) {
	platformStr := chi.URLParam(r, "platform")
	platform := meetings.MeetingPlatform(strings.ToLower(platformStr))

	cfg, ok := h.platformConfig(platform)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "platform_not_found",
			"platform "+platformStr+" is not configured")
		return
	}
	if !cfg.Enabled {
		writeJSONError(w, http.StatusServiceUnavailable, "platform_disabled",
			"platform "+platformStr+" is disabled — set VERTGUARD_MEETING_"+
				strings.ToUpper(platformStr)+"_CLIENT_ID to enable")
		return
	}

	// Generate a cryptographically random state nonce.
	state, err := generateState()
	if err != nil {
		h.Logger.Error().Err(err).Str("platform", platformStr).Msg("state nonce generation failed")
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "could not generate state nonce")
		return
	}

	// Store nonce with 5-minute TTL then GC any stale entries.
	h.stateMu.Lock()
	h.states[state] = stateEntry{platform: platform, expires: time.Now().Add(5 * time.Minute)}
	h.gcStatesLocked()
	h.stateMu.Unlock()

	redirectURI := h.RedirectBase + "/api/v1/integrations/meetings/callback"
	authorizeURL, err := meetings.AuthorizeURL(platform, cfg.ClientID, state, redirectURI)
	if err != nil {
		h.Logger.Error().Err(err).Str("platform", platformStr).Msg("build authorize URL failed")
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "could not build authorize URL")
		return
	}

	h.Logger.Info().
		Str("platform", platformStr).
		Str("state", state[:8]+"…").
		Msg("meeting OAuth connect initiated")

	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// Callback handles GET /api/v1/integrations/meetings/callback.
//
// Validates the state nonce, then attempts token exchange (Phase 4.3 stub).
// Returns HTTP 501 when the platform SDK keys are not yet provisioned.
// JWT auth is required — the route is registered with auth.RequireRead in
// server.go.
func (h *MeetingsHandler) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")
	errParam := q.Get("error")

	// Platform can send an error query param (e.g. access_denied).
	if errParam != "" {
		h.Logger.Warn().
			Str("error", errParam).
			Str("description", q.Get("error_description")).
			Msg("platform returned OAuth error")
		writeJSONError(w, http.StatusBadRequest, "oauth_error", errParam)
		return
	}

	if state == "" || code == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_params",
			"state and code query parameters are required")
		return
	}

	// Validate and consume the state nonce.
	h.stateMu.Lock()
	entry, found := h.states[state]
	if found {
		delete(h.states, state)
	}
	h.stateMu.Unlock()

	if !found {
		h.Logger.Warn().Str("state", state[:min8(state)]).Msg("OAuth callback with unknown or expired state nonce")
		writeJSONError(w, http.StatusBadRequest, "invalid_state",
			"state nonce not found or expired — restart the connect flow")
		return
	}
	if time.Now().After(entry.expires) {
		h.Logger.Warn().Str("platform", string(entry.platform)).Msg("OAuth state nonce expired")
		writeJSONError(w, http.StatusBadRequest, "state_expired",
			"state nonce expired — restart the connect flow")
		return
	}

	// Phase 4.3: implement token exchange once SDK keys are provisioned.
	// ExchangeCode currently returns ErrNotImplemented. When provisioned,
	// store the returned Token in the operator's secret manager and return
	// HTTP 200 with a confirmation payload.
	h.Logger.Info().
		Str("platform", string(entry.platform)).
		Str("state", state[:min8(state)]).
		Msg("OAuth callback received; token exchange deferred — SDK provisioning required")

	writeJSONError(w, http.StatusNotImplemented, "sdk_provisioning_required",
		"SDK provisioning required — token exchange not yet implemented for platform "+string(entry.platform))
}

// Webhook handles POST /api/v1/integrations/meetings/webhook/{platform}.
//
// Validates the HMAC signature for the platform, parses the event, and
// logs it. When the event type is "audio.chunk" and an audio ML pipeline
// is available, the chunk is forwarded for voice risk scoring.
//
// No JWT auth — validated by HMAC instead (registered without RequireRead
// in server.go so the platform can POST without a VertGuard JWT).
func (h *MeetingsHandler) Webhook(w http.ResponseWriter, r *http.Request) {
	platformStr := chi.URLParam(r, "platform")
	platform := meetings.MeetingPlatform(strings.ToLower(platformStr))

	cfg, ok := h.platformConfig(platform)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "platform_not_found",
			"platform "+platformStr+" is not configured")
		return
	}

	// Cap the body before reading.
	r.Body = http.MaxBytesReader(w, r.Body, meetingsMaxBodyBytes+1)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
				"request body exceeds maximum size")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "read_failed", "failed to read request body")
		return
	}
	if len(body) > meetingsMaxBodyBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
			"request body exceeds maximum size")
		return
	}

	// Validate the request's authenticity. Teams authenticates via a Bearer
	// JWT (credential = this bot's Azure app/client ID, used as the
	// expected audience); Zoom/WebEx authenticate via an HMAC shared
	// secret. Skip only when the relevant credential isn't configured
	// (dev/test convenience; log a warning) — never skip silently.
	credential := cfg.WebhookSecret
	if platform == meetings.PlatformTeams {
		credential = cfg.ClientID
	}
	if credential != "" {
		if !meetings.ValidateSignature(platform, credential, body, r.Header) {
			h.Logger.Warn().
				Str("platform", platformStr).
				Msg("meeting webhook: signature/token validation failed")
			writeJSONError(w, http.StatusUnauthorized, "invalid_signature",
				"signature or token validation failed — check the platform webhook configuration")
			return
		}
	} else {
		h.Logger.Warn().
			Str("platform", platformStr).
			Msg("meeting webhook: no webhook credential configured — auth check skipped (dev mode)")
	}

	// Parse event into normalised envelope.
	evt, err := meetings.ParseEvent(platform, body)
	if err != nil {
		h.Logger.Warn().Err(err).Str("platform", platformStr).Msg("meeting webhook: event parse failed")
		writeJSONError(w, http.StatusBadRequest, "parse_failed", "could not parse event payload")
		return
	}

	h.Logger.Info().
		Str("platform", platformStr).
		Str("event_type", evt.EventType).
		Str("meeting_id", evt.MeetingID).
		Str("participant_id", evt.ParticipantID).
		Time("event_ts", evt.Timestamp).
		Msg("meeting event received")

	// Phase 4.3: when event_type is "audio.chunk" and the audio ML pipeline
	// is available, forward the chunk payload to the voice risk scorer.
	// TODO: wire audio ML forwarder once audio.Scorer is implemented
	// (see internal/media or a future internal/audio package).
	if evt.EventType == "audio.chunk" {
		h.Logger.Debug().
			Str("platform", platformStr).
			Str("meeting_id", evt.MeetingID).
			Msg("audio.chunk event received — audio ML forwarding not yet implemented")
	}

	w.WriteHeader(http.StatusOK)
}

// Status handles GET /api/v1/integrations/meetings/status.
//
// Returns the configuration state of each known meeting platform.
// JWT auth is required — registered with auth.RequireRead in server.go.
func (h *MeetingsHandler) Status(w http.ResponseWriter, r *http.Request) {
	type platformStatus struct {
		Name           string `json:"name"`
		Enabled        bool   `json:"enabled"`
		OAuthConfigured bool  `json:"oauth_configured"`
	}

	// Report all three platforms; fall back to unconfigured defaults for
	// any that are not in h.Platforms.
	known := []meetings.MeetingPlatform{
		meetings.PlatformZoom,
		meetings.PlatformTeams,
		meetings.PlatformWebEx,
	}

	statuses := make([]platformStatus, 0, len(known))
	for _, p := range known {
		cfg, ok := h.platformConfig(p)
		if !ok {
			statuses = append(statuses, platformStatus{
				Name:           string(p),
				Enabled:        false,
				OAuthConfigured: false,
			})
			continue
		}
		statuses = append(statuses, platformStatus{
			Name:           string(p),
			Enabled:        cfg.Enabled,
			OAuthConfigured: cfg.ClientID != "" && cfg.ClientSecret != "",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"platforms": statuses})
}

// ─── Helpers ─────────────────────────────────────────────────────────

// platformConfig looks up a PlatformConfig by platform name.
func (h *MeetingsHandler) platformConfig(platform meetings.MeetingPlatform) (meetings.PlatformConfig, bool) {
	for _, cfg := range h.Platforms {
		if cfg.Platform == platform {
			return cfg, true
		}
	}
	return meetings.PlatformConfig{}, false
}

// gcStatesLocked removes expired state entries. Must be called with
// h.stateMu held.
func (h *MeetingsHandler) gcStatesLocked() {
	now := time.Now()
	for k, v := range h.states {
		if now.After(v.expires) {
			delete(h.states, k)
		}
	}
}

// generateState returns a 32-byte cryptographically random hex string
// suitable for use as an OAuth2 state nonce.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// min8 returns min(len(s), 8) for safe log truncation of nonces.
func min8(s string) int {
	if len(s) < 8 {
		return len(s)
	}
	return 8
}
