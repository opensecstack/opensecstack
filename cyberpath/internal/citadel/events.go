// Package citadel — typed outbox event constructors.
//
// Handlers should never hand-build the JSON for an outbox row.
// Instead, call the typed enqueue helpers below: they marshal the
// canonical shape from `docs/citadel-integration.md` and forward to
// the outbox store. This keeps the wire format under static review
// and out of handler code.
package citadel

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// OutboxEnqueuer is the narrow store contract these helpers need.
// The real *db.OutboxStore satisfies it by structural typing.
type OutboxEnqueuer interface {
	Enqueue(ctx context.Context, req EnqueueRequest) (id int64, err error)
}

// EnqueueRequest matches the fields the (sibling) outbox store
// accepts. Mirrored here so the citadel package doesn't have to
// import db (which would be a circular dependency once db imports
// citadel for typed shapes).
type EnqueueRequest struct {
	TenantID      string
	Destination   string // 'citadel' | 'webhook' | 'both'
	WebhookID     string // optional
	EventType     string
	Payload       []byte
	CorrelationID string
}

// CohortCreated carries the minimum fields needed to render the
// `cyberpath.cohort.created` event.
type CohortCreated struct {
	CohortID      string
	TenantID      string
	Name          string
	TrackID       string
	CreatedBy     string
	CreatedAt     time.Time
	CorrelationID string
}

// EnqueueCohortCreated enqueues a cohort-created CITADEL event.
// Returns the outbox row id so the caller can stitch it into its
// own audit log.
func EnqueueCohortCreated(ctx context.Context, store OutboxEnqueuer, ev CohortCreated) (int64, error) {
	payload := map[string]any{
		"event_type":     "cyberpath.cohort.created",
		"subject":        "cohort:" + ev.CohortID,
		"tenant":         ev.TenantID,
		"timestamp":      tsOrNow(ev.CreatedAt),
		"correlation_id": ev.CorrelationID,
		"cyberpath": map[string]any{
			"cohort_id":  ev.CohortID,
			"name":       ev.Name,
			"track_id":   ev.TrackID,
			"created_by": ev.CreatedBy,
		},
	}
	return enqueueJSON(ctx, store, EnqueueRequest{
		TenantID:      ev.TenantID,
		Destination:   "citadel",
		EventType:     "cyberpath.cohort.created",
		CorrelationID: ev.CorrelationID,
	}, payload)
}

// CompletionWORM is the headline NIS2-evidence event. Field shape
// matches `docs/citadel-integration.md § Event schema`.
type CompletionWORM struct {
	CompletionID        string
	UserID              string
	TenantID            string
	TrackID             string
	TrackVersion        string
	ContentVersionID    string
	CompletionTimestamp time.Time
	EvidenceHash        string // "blake3:<hex>"
	SignedBy            string // "ed25519:<key id>"
	CertificationLevel  string // 'lesson' | 'module' | 'track-cert' | 'path-cert'
	NIS2Measures        []string
	Score               float64
	Categories          []string
	Patterns            []string
	CorrelationID       string
}

// EnqueueCompletionWORM enqueues the cyberpath.completion event for
// CITADEL's WORM ledger. This is the audit cornerstone for NIS2
// Article 21 evidence; callers must NOT skip this on completion
// success.
func EnqueueCompletionWORM(ctx context.Context, store OutboxEnqueuer, ev CompletionWORM) (int64, error) {
	if ev.UserID == "" || ev.CompletionID == "" {
		return 0, fmt.Errorf("EnqueueCompletionWORM: user_id and completion_id are required")
	}
	categories := ev.Categories
	if categories == nil {
		categories = make([]string, 0, len(ev.NIS2Measures))
		for _, m := range ev.NIS2Measures {
			categories = append(categories, "nis2."+m)
		}
	}
	patterns := ev.Patterns
	if patterns == nil {
		patterns = []string{"track:" + ev.TrackID}
	}

	payload := map[string]any{
		"event_type":     "cyberpath.completion",
		"subject":        "user:" + ev.UserID,
		"verdict":        "completed",
		"score":          ev.Score,
		"categories":     categories,
		"patterns":       patterns,
		"tenant":         ev.TenantID,
		"timestamp":      tsOrNow(ev.CompletionTimestamp),
		"correlation_id": ev.CorrelationID,
		"cyberpath": map[string]any{
			"completion_id":        ev.CompletionID,
			"user_id":              ev.UserID,
			"track_id":             ev.TrackID,
			"track_version":        ev.TrackVersion,
			"content_version_id":   ev.ContentVersionID,
			"completion_timestamp": tsOrNow(ev.CompletionTimestamp),
			"evidence_hash":        ev.EvidenceHash,
			"signed_by":            ev.SignedBy,
			"certification_level":  ev.CertificationLevel,
			"nis2_measures":        ev.NIS2Measures,
		},
	}
	return enqueueJSON(ctx, store, EnqueueRequest{
		TenantID:      ev.TenantID,
		Destination:   "citadel",
		EventType:     "cyberpath.completion",
		CorrelationID: ev.CorrelationID,
	}, payload)
}

// CertificationIssued is the `cyberpath.certification.issued` event.
type CertificationIssued struct {
	CertificateID      string
	UserID             string
	TenantID           string
	TrackID            string
	CertificationLevel string
	IssuedAt           time.Time
	ExpiresAt          *time.Time
	SignedBy           string
	CorrelationID      string
}

// EnqueueCertificationIssued enqueues a certification-issued event.
func EnqueueCertificationIssued(ctx context.Context, store OutboxEnqueuer, ev CertificationIssued) (int64, error) {
	cb := map[string]any{
		"certificate_id":      ev.CertificateID,
		"user_id":             ev.UserID,
		"track_id":            ev.TrackID,
		"certification_level": ev.CertificationLevel,
		"issued_at":           tsOrNow(ev.IssuedAt),
		"signed_by":           ev.SignedBy,
	}
	if ev.ExpiresAt != nil {
		cb["expires_at"] = ev.ExpiresAt.UTC().Format(time.RFC3339)
	}
	payload := map[string]any{
		"event_type":     "cyberpath.certification.issued",
		"subject":        "user:" + ev.UserID,
		"tenant":         ev.TenantID,
		"timestamp":      tsOrNow(ev.IssuedAt),
		"correlation_id": ev.CorrelationID,
		"cyberpath":      cb,
	}
	return enqueueJSON(ctx, store, EnqueueRequest{
		TenantID:      ev.TenantID,
		Destination:   "citadel",
		EventType:     "cyberpath.certification.issued",
		CorrelationID: ev.CorrelationID,
	}, payload)
}

// CertificationRevoked is the `cyberpath.certification.revoked` event.
// Unlike CertificationIssued, revocation is a discretionary admin
// action (not automatic/score-gated) — the WORM entry it produces is
// the immutable record of who revoked which credential, independent
// of the MARSHAL governance outcome recorded separately.
type CertificationRevoked struct {
	CertificateID string
	TenantID      string
	RevokedBy     string // admin user_id who performed the revocation
	RevokedAt     time.Time
	Reason        string
	CorrelationID string
}

// EnqueueCertificationRevoked enqueues a certification-revoked event.
func EnqueueCertificationRevoked(ctx context.Context, store OutboxEnqueuer, ev CertificationRevoked) (int64, error) {
	if ev.CertificateID == "" {
		return 0, fmt.Errorf("EnqueueCertificationRevoked: certificate_id is required")
	}
	cb := map[string]any{
		"certificate_id": ev.CertificateID,
		"revoked_by":     ev.RevokedBy,
		"revoked_at":     tsOrNow(ev.RevokedAt),
	}
	if ev.Reason != "" {
		cb["reason"] = ev.Reason
	}
	payload := map[string]any{
		"event_type":     "cyberpath.certification.revoked",
		"subject":        "certification:" + ev.CertificateID,
		"tenant":         ev.TenantID,
		"timestamp":      tsOrNow(ev.RevokedAt),
		"correlation_id": ev.CorrelationID,
		"cyberpath":      cb,
	}
	return enqueueJSON(ctx, store, EnqueueRequest{
		TenantID:      ev.TenantID,
		Destination:   "citadel",
		EventType:     "cyberpath.certification.revoked",
		CorrelationID: ev.CorrelationID,
	}, payload)
}

// LabCompleted is the `cyberpath.lab.completed` event.
type LabCompleted struct {
	LabSessionID  string
	LabID         string
	UserID        string
	TenantID      string
	StartedAt     time.Time
	CompletedAt   time.Time
	Outcome       string // 'pass' | 'fail' | 'abandoned'
	Score         float64
	EvidenceHash  string
	CorrelationID string
}

// EnqueueLabCompleted enqueues a lab-completion event.
func EnqueueLabCompleted(ctx context.Context, store OutboxEnqueuer, ev LabCompleted) (int64, error) {
	payload := map[string]any{
		"event_type":     "cyberpath.lab.completed",
		"subject":        "user:" + ev.UserID,
		"tenant":         ev.TenantID,
		"timestamp":      tsOrNow(ev.CompletedAt),
		"correlation_id": ev.CorrelationID,
		"cyberpath": map[string]any{
			"lab_session_id": ev.LabSessionID,
			"lab_id":         ev.LabID,
			"user_id":        ev.UserID,
			"started_at":     tsOrNow(ev.StartedAt),
			"completed_at":   tsOrNow(ev.CompletedAt),
			"outcome":        ev.Outcome,
			"score":          ev.Score,
			"evidence_hash":  ev.EvidenceHash,
		},
	}
	return enqueueJSON(ctx, store, EnqueueRequest{
		TenantID:      ev.TenantID,
		Destination:   "citadel",
		EventType:     "cyberpath.lab.completed",
		CorrelationID: ev.CorrelationID,
	}, payload)
}

// enqueueJSON marshals payload + forwards to the store.
func enqueueJSON(ctx context.Context, store OutboxEnqueuer, req EnqueueRequest, payload map[string]any) (int64, error) {
	if store == nil {
		return 0, fmt.Errorf("nil outbox store")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal payload: %w", err)
	}
	req.Payload = body
	return store.Enqueue(ctx, req)
}

// tsOrNow returns t formatted as RFC 3339 UTC, or now() if t is the
// zero value.
func tsOrNow(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format(time.RFC3339)
}
