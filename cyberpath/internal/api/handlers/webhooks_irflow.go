// IRFlow incoming webhook handler.
//
// Verifies an HMAC-SHA256 signature in the Stripe-style scheme
// (signed input = timestamp + "." + raw_body), looks up the
// incident-type → track-set mapping, creates or returns an existing
// `incident-<incident_id>` cohort, enrolls the affected users, and
// emits the audit + outbox events.
//
// HMAC scheme matches the rest of the ecosystem (CITADEL, ThreatFlow,
// IRFlow itself). Constant-time compare via hmac.Equal. Default skew
// tolerance is ±5 min — configurable via HandlerOptions.SkewTolerance.
//
// Wire in cmd/server/main.go via Options.IRFlowWebhookHandler — call
// h.Register(r) on the chi router. server.go is intentionally not
// touched here; the wire-up step plugs this in.
package handlers

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
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

// IncidentType is IRFlow's incident-type taxonomy.
type IncidentType string

// Default v1.0.0 incident-type → track-slugs mapping. Source:
// docs/irflow-integration.md (#incident-type --> track-set lookup).
// Empty list means "no training mapped" — the trigger is recorded
// but no enrolment happens.
var defaultIncidentTrackMap = map[IncidentType][]string{
	"phishing":                    {"phishing-recognition", "nis2-art21-awareness"},
	"business_email_compromise":   {"phishing-recognition"},
	"credential_compromise":       {"phishing-recognition", "nis2-art21-awareness"},
	"privilege_escalation":        {"linux-hardening", "secure-coding"},
	"web_app_compromise":          {"secure-coding", "api-security"},
	"api_abuse":                   {"api-security"},
	"malware_outbreak":            {"network-forensics", "incident-response-basics"},
	"supply_chain":                {"secure-coding"},
	"policy_violation":            {"nis2-art21-awareness"},
	"insider_threat":              {"nis2-art21-awareness"},
	"data_exfiltration":           {"network-forensics", "incident-response-basics"},
	"ransomware":                  {"incident-response-basics", "network-forensics", "linux-hardening"},
	"ddos":                        {},
	"physical_security":           {},
	"unknown":                     {"nis2-art21-awareness"},
}

// CohortStore is the minimal interface the IRFlow webhook handler
// needs from the cohort persistence layer. Sibling agents own the
// concrete implementation; declared locally so we don't block on it.
type CohortStore interface {
	// FindByName looks up a cohort by tenant + name. Returns
	// ("", nil) if not found.
	FindByName(ctx context.Context, tenant, name string) (cohortID string, err error)
	// Create persists a new cohort and returns its id.
	Create(ctx context.Context, tenant, name string, trackIDs []string) (cohortID string, err error)
	// Enroll associates the given user ids with the cohort.
	// Returns the count of users actually enrolled (excluding
	// duplicates).
	Enroll(ctx context.Context, cohortID string, userIDs []string) (enrolled int, err error)
}

// AuditEmitter emits a structured audit event into the local audit
// log (the `audit_event` row in CyberPath's DB).
type AuditEmitter interface {
	Emit(ctx context.Context, eventType string, payload map[string]any) error
}

// OutboxEnqueuer enqueues an event for downstream delivery (CITADEL
// in particular).
type OutboxEnqueuer interface {
	Enqueue(ctx context.Context, eventType string, payload map[string]any) error
}

// IRFlowWebhookOptions configures the webhook handler.
type IRFlowWebhookOptions struct {
	HMACSecret     string
	SkewTolerance  time.Duration
	Tenant         string // tenant to attribute incident cohorts to
	RetrainingSLA  time.Duration
	IncidentMap    map[IncidentType][]string
	Cohorts        CohortStore
	Audit          AuditEmitter
	Outbox         OutboxEnqueuer
	Logger         zerolog.Logger
	Now            func() time.Time
}

// IRFlowWebhookHandler is the registrable handler bundle.
type IRFlowWebhookHandler struct {
	opts IRFlowWebhookOptions
}

// NewIRFlowWebhookHandler returns a handler with sensible defaults.
func NewIRFlowWebhookHandler(opts IRFlowWebhookOptions) *IRFlowWebhookHandler {
	if opts.SkewTolerance <= 0 {
		opts.SkewTolerance = 5 * time.Minute
	}
	if opts.RetrainingSLA <= 0 {
		opts.RetrainingSLA = 14 * 24 * time.Hour
	}
	if opts.IncidentMap == nil {
		opts.IncidentMap = defaultIncidentTrackMap
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return &IRFlowWebhookHandler{opts: opts}
}

// Register attaches the handler to the chi router. The wire-up step
// in cmd/server/main.go is responsible for calling this.
func (h *IRFlowWebhookHandler) Register(r chi.Router) {
	r.Post("/api/v1/webhooks/irflow/incident_trigger", h.handleIncidentTrigger())
}

// incidentTriggerBody is the IRFlow→CyberPath wire shape.
type incidentTriggerBody struct {
	IncidentID       string       `json:"incident_id"`
	Type             IncidentType `json:"type"`
	Severity         string       `json:"severity"`
	AffectedUsers    []string     `json:"affected_users"`
	SuggestedTracks  []string     `json:"suggested_tracks"`
	OccurredAt       time.Time    `json:"occurred_at"`
	CorrelationID    string       `json:"correlation_id"`
}

func (h *IRFlowWebhookHandler) handleIncidentTrigger() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if h.opts.HMACSecret == "" {
			writeError(w, http.StatusServiceUnavailable, "irflow_disabled", "irflow webhook secret not configured")
			return
		}

		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "read_body", err.Error())
			return
		}

		ts := r.Header.Get("X-IRFlow-Timestamp")
		sig := r.Header.Get("X-IRFlow-Signature")
		if err := verifyIRFlowSignature(raw, ts, sig, h.opts.HMACSecret, h.opts.SkewTolerance, h.opts.Now()); err != nil {
			h.opts.Logger.Warn().Err(err).Msg("irflow webhook signature rejected")
			writeError(w, http.StatusUnauthorized, "bad_signature", err.Error())
			return
		}

		var body incidentTriggerBody
		if err := json.Unmarshal(raw, &body); err != nil {
			writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
			return
		}
		if body.IncidentID == "" {
			writeError(w, http.StatusBadRequest, "missing_incident_id", "incident_id required")
			return
		}
		if len(body.AffectedUsers) == 0 {
			writeError(w, http.StatusBadRequest, "missing_affected_users", "affected_users required and non-empty")
			return
		}

		// Resolve track set: caller's suggestion wins, otherwise the
		// static map. Unknown incident type with no suggested tracks
		// falls back to the "unknown" entry.
		tracks := body.SuggestedTracks
		if len(tracks) == 0 {
			mapped, ok := h.opts.IncidentMap[body.Type]
			if !ok {
				mapped = h.opts.IncidentMap["unknown"]
			}
			tracks = mapped
		}

		cohortName := "incident-" + body.IncidentID
		tenant := h.opts.Tenant

		// Idempotency: existing cohort short-circuits.
		cohortID, err := h.opts.Cohorts.FindByName(ctx, tenant, cohortName)
		if err != nil {
			h.opts.Logger.Error().Err(err).Msg("cohort lookup failed")
			writeError(w, http.StatusServiceUnavailable, "store_error", err.Error())
			return
		}

		var enrolled int
		if cohortID == "" {
			cohortID, err = h.opts.Cohorts.Create(ctx, tenant, cohortName, tracks)
			if err != nil {
				h.opts.Logger.Error().Err(err).Msg("cohort create failed")
				writeError(w, http.StatusServiceUnavailable, "store_error", err.Error())
				return
			}
			enrolled, err = h.opts.Cohorts.Enroll(ctx, cohortID, body.AffectedUsers)
			if err != nil {
				h.opts.Logger.Error().Err(err).Msg("cohort enroll failed")
				if errors.Is(err, ErrUnknownUser) {
					writeError(w, http.StatusUnprocessableEntity, "unknown_user", err.Error())
					return
				}
				writeError(w, http.StatusServiceUnavailable, "store_error", err.Error())
				return
			}

			payload := map[string]any{
				"incident_id":          body.IncidentID,
				"incident_type":        string(body.Type),
				"incident_severity":    body.Severity,
				"cohort_id":            cohortID,
				"tracks_assigned":      tracks,
				"enrolled_user_count":  enrolled,
				"correlation_id":       body.CorrelationID,
			}
			if h.opts.Audit != nil {
				if err := h.opts.Audit.Emit(ctx, "cyberpath.incident_triggered_enrollment", payload); err != nil {
					h.opts.Logger.Warn().Err(err).Msg("audit emit failed (non-fatal)")
				}
			}
			if h.opts.Outbox != nil {
				if err := h.opts.Outbox.Enqueue(ctx, "cyberpath.incident_triggered_enrollment", payload); err != nil {
					h.opts.Logger.Warn().Err(err).Msg("outbox enqueue failed (non-fatal)")
				}
			}
		}

		recommendedBy := h.opts.Now().Add(h.opts.RetrainingSLA).UTC()
		writeJSON(w, http.StatusOK, map[string]any{
			"cohort_id":                  cohortID,
			"enrolled_user_count":        enrolled,
			"recommended_completion_by":  recommendedBy.Format(time.RFC3339),
			"tracks_assigned":            tracks,
		})
	}
}

// ErrUnknownUser is returned by CohortStore.Enroll when one or more
// affected users could not be resolved.
var ErrUnknownUser = errors.New("one or more affected users not found")

// verifyIRFlowSignature implements the Stripe-style scheme.
func verifyIRFlowSignature(body []byte, timestamp, signatureHeader, secret string, skew time.Duration, now time.Time) error {
	if timestamp == "" || signatureHeader == "" {
		return fmt.Errorf("missing signature headers")
	}
	tsInt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	if delta := now.Sub(time.Unix(tsInt, 0)); delta > skew || delta < -skew {
		return fmt.Errorf("timestamp outside ±%s window", skew)
	}
	want := computeIRFlowSignature(body, timestamp, secret)
	got := strings.TrimPrefix(signatureHeader, "sha256=")
	gotBytes, err := hex.DecodeString(got)
	if err != nil {
		return fmt.Errorf("signature not hex: %w", err)
	}
	wantBytes, _ := hex.DecodeString(want)
	if !hmac.Equal(gotBytes, wantBytes) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func computeIRFlowSignature(body []byte, timestamp, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
