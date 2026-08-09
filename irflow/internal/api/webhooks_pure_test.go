package api

import (
	"errors"
	"net/http"
	"testing"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"github.com/opensecstack/opensecstack/irflow/internal/webhook"
)

// webhookHTTPStatus maps webhook signature-verification failures to HTTP
// status codes. This mapping is security-relevant: a stale/forged signature
// must surface as 401 (client cannot silently retry into acceptance),
// whereas malformed request framing is a 400.
func TestWebhookHTTPStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"missing signature", webhook.ErrMissingSignature, http.StatusBadRequest},
		{"missing timestamp", webhook.ErrMissingTimestamp, http.StatusBadRequest},
		{"invalid timestamp", webhook.ErrInvalidTimestamp, http.StatusBadRequest},
		{"stale timestamp (replay window)", webhook.ErrStaleTimestamp, http.StatusUnauthorized},
		{"invalid signature (forged/wrong secret)", webhook.ErrInvalidSignature, http.StatusUnauthorized},
		{"unknown/wrapped error defaults to 400", errors.New("boom"), http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := webhookHTTPStatus(c.err); got != c.want {
				t.Errorf("webhookHTTPStatus(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

// webhookHTTPStatus must also unwrap errors.Is-compatible wrapped errors
// (verifier.Verify may wrap sentinel errors with additional context).
func TestWebhookHTTPStatus_UnwrapsWrappedError(t *testing.T) {
	wrapped := errors.New("verify: " + webhook.ErrStaleTimestamp.Error())
	// A plain string-wrapped error (not %w) does NOT satisfy errors.Is, so
	// this must fall through to the default 400 — this documents that
	// callers MUST use %w when wrapping, not string concatenation.
	if got := webhookHTTPStatus(wrapped); got != http.StatusBadRequest {
		t.Errorf("string-wrapped error: got %d, want %d (default, since errors.Is cannot match a plain string wrap)", got, http.StatusBadRequest)
	}

	fmtWrapped := fmtErrorf(webhook.ErrInvalidSignature)
	if got := webhookHTTPStatus(fmtWrapped); got != http.StatusUnauthorized {
		t.Errorf("%%w-wrapped ErrInvalidSignature: got %d, want %d", got, http.StatusUnauthorized)
	}
}

func fmtErrorf(inner error) error {
	return errFmtWrap{inner}
}

// errFmtWrap is a minimal errors.Is-compatible wrapper (equivalent to
// fmt.Errorf("...: %w", inner)) without importing fmt just for this.
type errFmtWrap struct{ inner error }

func (e errFmtWrap) Error() string { return "context: " + e.inner.Error() }
func (e errFmtWrap) Unwrap() error { return e.inner }

// ---------------------------------------------------------------------------
// mapAPIGuardSeverity
// ---------------------------------------------------------------------------

func TestMapAPIGuardSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want incident.Severity
	}{
		{"critical", incident.SeverityP1},
		{"CRITICAL", incident.SeverityP1}, // case-insensitive
		{"Critical", incident.SeverityP1},
		{"high", incident.SeverityP2},
		{"HIGH", incident.SeverityP2},
		{"medium", ""},
		{"low", ""},
		{"informational", ""},
		{"", ""},
		{"nonsense", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := mapAPIGuardSeverity(c.in); got != c.want {
				t.Errorf("mapAPIGuardSeverity(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
