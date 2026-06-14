package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// WebhookEvent is the envelope for inbound CITADEL webhook events.
type WebhookEvent struct {
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	Timestamp time.Time       `json:"timestamp"`
}

// Webhooks handles inbound webhook events from CITADEL.
type Webhooks struct {
	logger       zerolog.Logger
	secret       string
	emergencyStop func() // called on citadel.hard_stop to cancel in-flight scans
}

// NewWebhooks creates a new Webhooks handler.
// secret is the HMAC-SHA256 shared secret used to verify the X-Webhook-Signature header.
// emergencyStop is called when a hard_stop event is received; pass s.shutdownCancel from
// the server to trigger a graceful shutdown and cancel all in-flight scans.
func NewWebhooks(logger zerolog.Logger, secret string, emergencyStop func()) *Webhooks {
	return &Webhooks{
		logger:        logger.With().Str("handler", "webhooks").Logger(),
		secret:        secret,
		emergencyStop: emergencyStop,
	}
}

// maxWebhookBodySize limits the request body to 1 MB to prevent abuse.
const maxWebhookBodySize = 1 << 20 // 1 MB

// HandleCITADEL receives inbound events from CITADEL.
// Events: citadel.hard_stop, citadel.vigil_red, citadel.vigil_amber
//
// The handler verifies the HMAC-SHA256 signature from the X-Webhook-Signature
// header (format: "sha256=<hex>"), parses the JSON event body, and routes by
// event_type. Unknown event types are accepted silently (200) to allow CITADEL
// to add new event types without requiring APIGuard changes.
func (wh *Webhooks) HandleCITADEL(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBodySize))
	if err != nil {
		wh.logger.Error().Err(err).Msg("failed to read webhook request body")
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Verify HMAC-SHA256 signature.
	sig := r.Header.Get("X-Webhook-Signature")
	if !wh.verifySignature(body, sig) {
		wh.logger.Warn().Str("signature", sig).Msg("webhook signature verification failed")
		writeError(w, http.StatusUnauthorized, "invalid webhook signature")
		return
	}

	// Parse event envelope.
	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		wh.logger.Warn().Err(err).Msg("malformed webhook event body")
		writeError(w, http.StatusBadRequest, "malformed event body")
		return
	}

	// Route by event type.
	switch event.EventType {
	case "citadel.hard_stop":
		wh.logger.Error().
			Str("event_type", event.EventType).
			RawJSON("payload", event.Payload).
			Time("event_timestamp", event.Timestamp).
			Msg("CRITICAL: CITADEL hard_stop received — cancelling all in-flight scans and initiating graceful shutdown")
		if wh.emergencyStop != nil {
			wh.emergencyStop()
		}

	case "citadel.vigil_red":
		wh.logger.Error().
			Str("event_type", event.EventType).
			RawJSON("payload", event.Payload).
			Time("event_timestamp", event.Timestamp).
			Msg("CITADEL VIGIL RED alert — flagged for operator attention")

	case "citadel.vigil_amber":
		wh.logger.Warn().
			Str("event_type", event.EventType).
			RawJSON("payload", event.Payload).
			Time("event_timestamp", event.Timestamp).
			Msg("CITADEL VIGIL AMBER alert")

	default:
		wh.logger.Info().
			Str("event_type", event.EventType).
			Time("event_timestamp", event.Timestamp).
			Msg("received unknown CITADEL webhook event type — acknowledged")
	}

	w.WriteHeader(http.StatusOK)
}

// verifySignature performs constant-time HMAC-SHA256 verification.
// The signature header must be in the format "sha256=<hex_digest>".
func (wh *Webhooks) verifySignature(body []byte, signature string) bool {
	if wh.secret == "" || signature == "" {
		return false
	}

	// Expect format: sha256=<hex>
	prefix := "sha256="
	if !strings.HasPrefix(signature, prefix) {
		return false
	}
	sigHex := signature[len(prefix):]

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(wh.secret))
	mac.Write(body)
	expected := mac.Sum(nil)

	return hmac.Equal(sigBytes, expected)
}
