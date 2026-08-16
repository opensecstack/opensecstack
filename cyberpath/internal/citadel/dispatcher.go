// Package citadel — outbox dispatcher.
//
// Dispatch is destination-aware: rows whose `destination` is
// 'citadel' are submitted via the existing CITADEL HTTP client; rows
// targeting 'webhook' look up the registered subscriber, sign the
// body with the per-webhook HMAC secret and POST to the URL. Rows
// with destination 'both' fan out to both targets; failure of either
// leg is treated as a delivery failure for the row (the worker keeps
// at-least-once semantics by leaning on CITADEL's correlation_id
// dedupe and on idempotent webhook receivers).
package citadel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// httpDoer is the minimal interface used by webhook dispatch. The
// production code uses *http.Client; tests inject a fake.
type httpDoer struct {
	client *http.Client
}

// retryableError wraps a transport / 5xx error: errIsRetryable
// returns true for these.
type retryableError struct{ err error }

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

// nonRetryableError wraps a 4xx schema mismatch (excluding 408/429).
// errIsRetryable returns false for these.
type nonRetryableError struct{ err error }

func (e *nonRetryableError) Error() string { return e.err.Error() }
func (e *nonRetryableError) Unwrap() error { return e.err }

// errIsRetryable classifies a dispatch error. The worker uses the
// answer to decide whether MarkFailed should retry or flip the row
// to dlq immediately. Default policy: unknown errors are retryable
// (we'd rather over-retry than drop evidence).
func errIsRetryable(err error) bool {
	if err == nil {
		return false
	}
	var nr *nonRetryableError
	return !errors.As(err, &nr)
}

// dispatch is the destination-aware fan-out called by the worker.
func (w *Worker) dispatch(ctx context.Context, entry *OutboxEntry) error {
	switch entry.Destination {
	case "citadel":
		return w.dispatchCITADEL(ctx, entry)
	case "webhook":
		return w.dispatchWebhook(ctx, entry)
	case "both":
		if err := w.dispatchCITADEL(ctx, entry); err != nil {
			return err
		}
		return w.dispatchWebhook(ctx, entry)
	default:
		return &nonRetryableError{err: fmt.Errorf("unknown destination %q", entry.Destination)}
	}
}

// dispatchCITADEL submits a row to CITADEL via the existing HTTP
// client. The CITADEL client's Submit method already handles HMAC
// signing, the dry-run shortcut and 4xx vs 5xx classification — we
// re-classify its returned error so errIsRetryable can route it.
func (w *Worker) dispatchCITADEL(ctx context.Context, entry *OutboxEntry) error {
	if w.opts.Citadel == nil {
		return &retryableError{err: errors.New("citadel client not configured")}
	}

	var payload map[string]any
	if len(entry.Payload) > 0 {
		if err := json.Unmarshal(entry.Payload, &payload); err != nil {
			// Bad payload — never going to succeed. Park in DLQ.
			return &nonRetryableError{err: fmt.Errorf("decode payload: %w", err)}
		}
	}

	subject, _ := payload["subject"].(string)
	tenant, _ := payload["tenant"].(string)
	if tenant == "" {
		tenant = entry.TenantID
	}

	ev := Event{
		EventType:     entry.EventType,
		Subject:       subject,
		Tenant:        tenant,
		Timestamp:     time.Now().UTC(),
		CorrelationID: entry.CorrelationID,
		Payload:       payload,
	}

	if err := w.opts.Citadel.Submit(ctx, ev); err != nil {
		// Submit returns a 5xx-prefixed error or a 4xx-prefixed error;
		// in both cases we wrap. CITADEL 4xx is non-retryable per
		// docs/citadel-integration.md "schema mismatches surface in
		// the next CyberPath release".
		if isCitadel4xx(err) {
			return &nonRetryableError{err: err}
		}
		return &retryableError{err: err}
	}
	return nil
}

// isCitadel4xx checks the error string prefix the CITADEL client
// produces for non-5xx HTTP errors. The client's Submit returns
// `errors.New("citadel " + status + ": " + body)` for 4xx and a
// fmt.Errorf("citadel %d: …") for 5xx; we conservatively classify
// anything that does NOT carry the 5xx-style %d formatting as 4xx.
//
// 408 (Request Timeout) and 429 (Too Many Requests) ARE retryable —
// we re-classify them here.
func isCitadel4xx(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Retryable 4xxs we want to keep retrying.
	if containsCode(msg, " 408") || containsCode(msg, " 429") {
		return false
	}
	// 5xx — let it retry.
	for code := 500; code < 600; code++ {
		if containsCode(msg, " "+strconv.Itoa(code)) {
			return false
		}
	}
	// Looks like a 4xx.
	for code := 400; code < 500; code++ {
		if containsCode(msg, " "+strconv.Itoa(code)) {
			return true
		}
	}
	// Transport / connection errors — retryable.
	return false
}

func containsCode(s, code string) bool {
	if len(s) < len(code) {
		return false
	}
	for i := 0; i+len(code) <= len(s); i++ {
		if s[i:i+len(code)] == code {
			return true
		}
	}
	return false
}

// dispatchWebhook signs and POSTs the row body to the registered
// subscriber. Body shape: a small envelope `{"event_type": …,
// "correlation_id": …, "data": <raw payload>}` so receivers can
// route without parsing the whole evidence object. Headers follow
// the ecosystem-wide convention (X-CyberPath-Signature /
// X-CyberPath-Timestamp).
func (w *Worker) dispatchWebhook(ctx context.Context, entry *OutboxEntry) error {
	if w.opts.Webhooks == nil {
		return &retryableError{err: errors.New("webhook store not configured")}
	}
	if entry.WebhookID == "" {
		return &nonRetryableError{err: errors.New("webhook destination but no webhook_id")}
	}

	hook, err := w.opts.Webhooks.GetWebhook(ctx, entry.WebhookID)
	if err != nil {
		return &retryableError{err: fmt.Errorf("lookup webhook: %w", err)}
	}
	if hook == nil {
		return &nonRetryableError{err: fmt.Errorf("webhook %s not found", entry.WebhookID)}
	}
	if !hook.Active {
		return &nonRetryableError{err: fmt.Errorf("webhook %s inactive", entry.WebhookID)}
	}

	// Envelope. Falls back to passing the raw payload through if
	// it isn't valid JSON — should never happen given the outbox
	// `payload` column is JSONB, but be defensive.
	envelope := map[string]any{
		"event_type":     entry.EventType,
		"correlation_id": entry.CorrelationID,
	}
	var data any
	if json.Unmarshal(entry.Payload, &data) == nil {
		envelope["data"] = data
	} else {
		envelope["data"] = string(entry.Payload)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return &nonRetryableError{err: fmt.Errorf("marshal envelope: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return &nonRetryableError{err: err}
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CyberPath-Timestamp", ts)
	req.Header.Set("X-CyberPath-Signature", "sha256="+signWebhook(body, ts, hook.SecretHMAC))
	req.Header.Set("X-CyberPath-Event", entry.EventType)
	if entry.CorrelationID != "" {
		req.Header.Set("X-CyberPath-Correlation-Id", entry.CorrelationID)
	}

	client := w.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return &retryableError{err: fmt.Errorf("webhook POST: %w", err)}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// 408 / 429 / 5xx → retryable; everything else 4xx → not.
	if resp.StatusCode == http.StatusRequestTimeout ||
		resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode >= 500 {
		return &retryableError{err: fmt.Errorf("webhook %d", resp.StatusCode)}
	}
	return &nonRetryableError{err: fmt.Errorf("webhook %d", resp.StatusCode)}
}

// httpClient returns the configured doer or builds a default
// *http.Client honouring the worker's HTTPTimeout.
func (w *Worker) httpClient() *http.Client {
	if w.opts.HTTP != nil && w.opts.HTTP.client != nil {
		return w.opts.HTTP.client
	}
	return &http.Client{Timeout: w.opts.HTTPTimeout}
}

// signWebhook computes HMAC-SHA256 over (timestamp || "." || body).
// Same scheme as the CITADEL client (intentional ecosystem-wide
// convention).
func signWebhook(body []byte, timestamp, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
