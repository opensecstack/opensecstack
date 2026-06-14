package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/threatfeed/webhook"
)

// defaultThreatflowReplayWindow is the ±window in which the
// X-ThreatFlow-Timestamp header must fall relative to the receiver's
// wall clock. Matches the Stripe-style ±5min standard documented on
// the publisher side.
const defaultThreatflowReplayWindow = 5 * time.Minute

// maxThreatflowBodyBytes caps inbound webhook bodies. ThreatFlow events
// are small JSON envelopes; anything larger is rejected with 413.
const maxThreatflowBodyBytes = 8 << 10

// ThreatflowReceiver handles POST /api/v1/webhooks/threatflow.
//
// ThreatFlow signs every outbound webhook with:
//
//	X-ThreatFlow-Timestamp: <unix-seconds>
//	X-ThreatFlow-Signature: sha256=<hex(HMAC-SHA256(secret, "<ts>.<body>"))>
//
// This receiver verifies the signature and rejects requests outside
// the replay window before processing the event.
type ThreatflowReceiver struct {
	// HMACSecret is the shared secret configured on the ThreatFlow side.
	// When empty, signature verification is skipped (dev/test only).
	HMACSecret string
	// Publisher fan-outs verified IOC events to VertGuard subscribers.
	// May be nil — events are still accepted and logged.
	Publisher *webhook.Publisher
	Logger    zerolog.Logger
	// Citadel optionally emits a vertguard.detection.threatfeed_ingest
	// WORM event per accepted batch. Skipped silently when nil.
	Citadel WORMEmitter
	Tenant  string

	// ReplayWindow overrides the ±5min default replay window. Zero means
	// use defaultThreatflowReplayWindow.
	ReplayWindow time.Duration
	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time
}

// NewThreatflowReceiver returns a ready receiver.
func NewThreatflowReceiver(hmacSecret string, pub *webhook.Publisher, logger zerolog.Logger) *ThreatflowReceiver {
	return &ThreatflowReceiver{
		HMACSecret:   hmacSecret,
		Publisher:    pub,
		Logger:       logger.With().Str("handler", "webhook_threatflow").Logger(),
		ReplayWindow: defaultThreatflowReplayWindow,
		Now:          time.Now,
	}
}

// threatflowEvent mirrors the IOCEvent payload ThreatFlow emits.
type threatflowEvent struct {
	ID        string          `json:"id"`
	EventType string          `json:"event_type"`
	Source    string          `json:"source"`
	Severity  string          `json:"severity"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
}

// Receive handles POST /api/v1/webhooks/threatflow.
func (h *ThreatflowReceiver) Receive(w http.ResponseWriter, r *http.Request) {
	// Cap the body via MaxBytesReader so the connection short-circuits
	// before we allocate. +1 allows us to detect overflow deterministically.
	r.Body = http.MaxBytesReader(w, r.Body, maxThreatflowBodyBytes+1)
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
	if len(body) > maxThreatflowBodyBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
			"request body exceeds maximum size")
		return
	}

	// Signature verification — skip only in dev mode (empty secret).
	if h.HMACSecret != "" {
		ts := r.Header.Get("X-ThreatFlow-Timestamp")
		sig := r.Header.Get("X-ThreatFlow-Signature")
		if ts == "" || sig == "" {
			writeJSONError(w, http.StatusUnauthorized, "missing_signature",
				"X-ThreatFlow-Timestamp and X-ThreatFlow-Signature are required")
			return
		}
		// Replay-window check: timestamp must be within ±window of now.
		if err := h.checkReplayWindow(ts); err != nil {
			h.Logger.Warn().Err(err).Str("ts", ts).Msg("stale or future timestamp")
			writeJSONError(w, http.StatusUnauthorized, "stale_timestamp",
				"timestamp outside replay window")
			return
		}
		if err := verifyThreatFlowSig(h.HMACSecret, ts, body, sig); err != nil {
			h.Logger.Warn().Err(err).Str("sig", sig).Msg("signature verification failed")
			writeJSONError(w, http.StatusUnauthorized, "invalid_signature",
				"HMAC signature mismatch")
			return
		}
	}

	var evt threatflowEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json", "could not parse event payload")
		return
	}

	h.Logger.Info().
		Str("event_id", evt.ID).
		Str("event_type", evt.EventType).
		Str("source", evt.Source).
		Msg("threatflow event received")

	// Re-publish to VertGuard subscribers when publisher is wired.
	if h.Publisher != nil {
		iocEvt := webhook.IOCEvent{
			ID:        evt.ID,
			Type:      evt.EventType,
			Severity:  evt.Severity,
			Data:      evt.Data,
			Timestamp: evt.Timestamp,
			Source:    "threatflow",
		}
		results := h.Publisher.Publish(r.Context(), iocEvt)
		ok, fail := 0, 0
		for _, res := range results {
			if res.Err != nil {
				fail++
			} else {
				ok++
			}
		}
		h.Logger.Debug().
			Str("event_id", evt.ID).
			Int("delivered", ok).
			Int("failed", fail).
			Msg("re-published to vertguard subscribers")
	}

	// CITADEL emit per accepted batch (best-effort, async).
	if h.Citadel != nil {
		h.Citadel.EmitAsync(context.Background(), citadel.Evidence{
			EventType:     "vertguard.detection.threatfeed_ingest",
			Subject:       evt.ID,
			Verdict:       "ingested",
			Tenant:        h.Tenant,
			Timestamp:     time.Now().UTC(),
			CorrelationID: evt.ID,
		})
	}

	w.WriteHeader(http.StatusOK)
}

// checkReplayWindow rejects timestamps further than ReplayWindow from
// the receiver's wall clock (defaulting to ±5min).
func (h *ThreatflowReceiver) checkReplayWindow(tsHeader string) error {
	tsInt, err := strconv.ParseInt(strings.TrimSpace(tsHeader), 10, 64)
	if err != nil {
		return fmt.Errorf("malformed timestamp: %w", err)
	}
	window := h.ReplayWindow
	if window <= 0 {
		window = defaultThreatflowReplayWindow
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	delta := now().Unix() - tsInt
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > window {
		return fmt.Errorf("timestamp %d outside ±%s window", tsInt, window)
	}
	return nil
}

// verifyThreatFlowSig checks that sig == "sha256=hex(HMAC(secret, "<ts>.<body>"))".
func verifyThreatFlowSig(secret, ts string, body []byte, sig string) error {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s.", ts)
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison on the hex string to prevent timing attacks.
	if !hmac.Equal([]byte(expected), []byte(strings.TrimSpace(sig))) {
		return fmt.Errorf("signature mismatch: got %q", sig)
	}
	return nil
}
