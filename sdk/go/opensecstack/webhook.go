package opensecstack

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Event type constants for all opensecstack platforms.
const (
	EventAPIScanCompleted       = "apiguard.scan.completed"
	EventAPIScanFailed          = "apiguard.scan.failed"
	EventAPIFindingCritical     = "apiguard.finding.critical"
	EventNIS2ControlUpdated     = "nis2compass.control.updated"
	EventNIS2AssessmentCompleted = "nis2compass.assessment.completed"
	EventCITADELHardStop        = "citadel.hard_stop"
	EventCITADELVigilRed        = "citadel.vigil_red"
	EventCITADELVigilAmber      = "citadel.vigil_amber"
)

// ErrInvalidSignature is returned when webhook signature verification fails.
var ErrInvalidSignature = errors.New("invalid webhook signature")

// WebhookEvent is the envelope for all incoming platform events.
type WebhookEvent struct {
	ID        string          `json:"id"`
	EventType string          `json:"event_type"`
	Source    string          `json:"source"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// WebhookHandler is a function that handles a verified webhook event.
type WebhookHandler func(ctx context.Context, event WebhookEvent) error

// computeHMAC returns the hex-encoded HMAC-SHA256 of body using key.
func computeHMAC(body, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies the HMAC-SHA256 signature of a webhook request.
// body is the raw request body bytes. secret is the shared webhook secret.
// signature must be in the format "sha256=<hmac_hex>".
// Returns nil if valid, ErrInvalidSignature if not.
func VerifySignature(body []byte, signature, secret string) error {
	expected := "sha256=" + computeHMAC(body, []byte(secret))
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return ErrInvalidSignature
	}
	return nil
}

// WebhookRouter routes incoming webhook events to registered handlers.
// It implements http.Handler and can be mounted directly on any net/http mux.
//
// Example:
//
//	router := NewWebhookRouter(os.Getenv("WEBHOOK_SECRET"))
//	router.On(EventAPIScanCompleted, func(ctx context.Context, e WebhookEvent) error {
//	    fmt.Printf("scan done: %s\n", e.ID)
//	    return nil
//	})
//	http.Handle("/webhooks", router)
type WebhookRouter struct {
	secret   string
	handlers map[string]WebhookHandler
	catchAll WebhookHandler
}

// NewWebhookRouter creates a new router with the given shared secret.
func NewWebhookRouter(secret string) *WebhookRouter {
	return &WebhookRouter{
		secret:   secret,
		handlers: make(map[string]WebhookHandler),
	}
}

// On registers a handler for a specific event type.
// Use "*" to register a catch-all handler for all unmatched event types.
// Returns the router for method chaining.
func (r *WebhookRouter) On(eventType string, handler WebhookHandler) *WebhookRouter {
	if eventType == "*" {
		r.catchAll = handler
	} else {
		r.handlers[eventType] = handler
	}
	return r
}

// ServeHTTP implements http.Handler. It:
//  1. Reads the raw request body.
//  2. Verifies the HMAC-SHA256 signature from X-Citadel-Signature or
//     X-APIGuard-Signature (first non-empty header wins).
//  3. Parses the event envelope JSON.
//  4. Routes to the registered handler (exact match, then catch-all).
//  5. Returns 200 on success, 400 on bad/missing signature, 422 on parse
//     error, 500 on handler error.
func (r *WebhookRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusInternalServerError)
		return
	}

	// Accept signature from either platform header.
	sig := req.Header.Get("X-Citadel-Signature")
	if sig == "" {
		sig = req.Header.Get("X-APIGuard-Signature")
	}

	if err := VerifySignature(body, sig, r.secret); err != nil {
		http.Error(w, fmt.Sprintf("signature verification failed: %v", err), http.StatusBadRequest)
		return
	}

	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse event: %v", err), http.StatusUnprocessableEntity)
		return
	}

	handler, ok := r.handlers[event.EventType]
	if !ok {
		handler = r.catchAll
	}

	if handler == nil {
		// No handler registered — acknowledge receipt silently.
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := handler(req.Context(), event); err != nil {
		http.Error(w, fmt.Sprintf("handler error: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
