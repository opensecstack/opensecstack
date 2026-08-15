// Package wireup hosts thin adapter types that bridge the small
// interfaces declared by individual handler / worker packages onto the
// concrete *db.* stores. Sibling packages were authored against
// stripped-down structural interfaces (string IDs, narrow method sets)
// while internal/db ships strongly-typed pgx-backed stores with
// uuid.UUID columns and richer per-call shapes; the adapters here are
// the only place those impedance mismatches are paid.
//
// Each adapter is a tiny struct + ≤4 methods. None of them carries
// state of its own — they just translate types and forward the call.
package wireup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apihandlers "github.com/opensecstack/cyberpath/internal/api/handlers"
	"github.com/opensecstack/cyberpath/internal/citadel"
	"github.com/opensecstack/cyberpath/internal/db"
	"github.com/opensecstack/cyberpath/internal/metrics"
)

// ── Auth handler adapter ──────────────────────────────────────────────

// AuthUserAdapter wraps *db.UserStore so it satisfies
// handlers.UserStore. The handler talks pure strings (id and email);
// the store works in uuid.UUID. db.User → handlers.User mapping is
// straightforward — fields with no DB column today (DeletedAt) round-
// trip as nil.
type AuthUserAdapter struct {
	Inner *db.UserStore
}

// AuthUsers is a convenience constructor.
func AuthUsers(s *db.UserStore) *AuthUserAdapter {
	return &AuthUserAdapter{Inner: s}
}

func dbUserToHandler(u *db.User) *apihandlers.User {
	if u == nil {
		return nil
	}
	return &apihandlers.User{
		ID:           u.ID.String(),
		TenantID:     u.TenantID.String(),
		Email:        u.Email,
		DisplayName:  u.DisplayName,
		Locale:       u.Locale,
		Role:         u.Role,
		PasswordHash: u.PasswordHash,
		DeletedAt:    u.DeletedAt,
	}
}

// FindByEmail implements handlers.UserStore.
func (a *AuthUserAdapter) FindByEmail(ctx context.Context, email string) (*apihandlers.User, error) {
	u, err := a.Inner.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return nil, apihandlers.ErrUserNotFound
		}
		return nil, err
	}
	return dbUserToHandler(u), nil
}

// FindByID implements handlers.UserStore.
func (a *AuthUserAdapter) FindByID(ctx context.Context, id string) (*apihandlers.User, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil, apihandlers.ErrUserNotFound
	}
	u, err := a.Inner.FindByID(ctx, parsed)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return nil, apihandlers.ErrUserNotFound
		}
		return nil, err
	}
	return dbUserToHandler(u), nil
}

// UpdatePasswordHash implements handlers.UserStore.
func (a *AuthUserAdapter) UpdatePasswordHash(ctx context.Context, id, newHash string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return apihandlers.ErrUserNotFound
	}
	return a.Inner.UpdatePasswordHash(ctx, parsed, newHash)
}

// ── CITADEL outbox worker adapters ────────────────────────────────────

// WorkerOutboxAdapter wraps *db.OutboxStore so it satisfies
// citadel.OutboxStore. Bridges:
//   - []db.OutboxEntry  → []citadel.OutboxEntry  (uuid.UUID → string)
//   - db.MarkFailed(id, errMsg) → citadel.MarkFailed(id, errMsg, retryable)
//     returning movedToDLQ. The dlq flag is recovered with a follow-up
//     SELECT on the row's status because db.MarkFailed does not surface
//     the post-update status itself.
type WorkerOutboxAdapter struct {
	Inner *db.OutboxStore
}

// WorkerOutbox is a convenience constructor.
func WorkerOutbox(s *db.OutboxStore) *WorkerOutboxAdapter {
	return &WorkerOutboxAdapter{Inner: s}
}

// Claim implements citadel.OutboxStore.
func (a *WorkerOutboxAdapter) Claim(ctx context.Context, batchSize int) ([]citadel.OutboxEntry, error) {
	rows, err := a.Inner.Claim(ctx, batchSize)
	if err != nil {
		return nil, err
	}
	out := make([]citadel.OutboxEntry, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		entry := citadel.OutboxEntry{
			ID:            r.ID,
			TenantID:      uuidPtrToString(r.TenantID),
			Destination:   r.Destination,
			WebhookID:     uuidPtrToString(r.WebhookID),
			EventType:     r.EventType,
			Payload:       []byte(r.Payload),
			CorrelationID: r.CorrelationID,
			Attempts:      r.Attempts,
			CreatedAt:     r.CreatedAt,
		}
		out = append(out, entry)
	}
	return out, nil
}

// MarkDelivered implements citadel.OutboxStore (passthrough).
func (a *WorkerOutboxAdapter) MarkDelivered(ctx context.Context, id int64) error {
	return a.Inner.MarkDelivered(ctx, id)
}

// MarkFailed implements citadel.OutboxStore. The retryable flag is
// observed but not forwarded — db.MarkFailed always reschedules until
// the per-row attempt cap (10) is reached, at which point the row
// auto-flips to status='dlq'. We re-read the row status to derive the
// movedToDLQ return value the worker uses for metrics + logging.
func (a *WorkerOutboxAdapter) MarkFailed(ctx context.Context, id int64, errMsg string, retryable bool) (bool, error) {
	_ = retryable
	if err := a.Inner.MarkFailed(ctx, id, errMsg); err != nil {
		return false, err
	}
	var status string
	err := a.Inner.Pool.QueryRow(ctx, `SELECT status FROM outbox WHERE id = $1`, id).Scan(&status)
	if err != nil {
		// Row vanished or transient read error: not fatal — the worker
		// just won't bump the dlq metric this round.
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, nil
	}
	return status == "dlq", nil
}

// WorkerWebhookAdapter wraps *db.WebhookStore so it satisfies
// citadel.WebhookStore. Bridges string id → uuid.UUID and
// *db.Webhook → *citadel.WebhookRecord.
type WorkerWebhookAdapter struct {
	Inner *db.WebhookStore
}

// WorkerWebhooks is a convenience constructor.
func WorkerWebhooks(s *db.WebhookStore) *WorkerWebhookAdapter {
	return &WorkerWebhookAdapter{Inner: s}
}

// GetWebhook implements citadel.WebhookStore.
func (a *WorkerWebhookAdapter) GetWebhook(ctx context.Context, id string) (*citadel.WebhookRecord, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("wireup/webhook: bad id %q: %w", id, err)
	}
	w, err := a.Inner.Get(ctx, parsed)
	if err != nil {
		return nil, err
	}
	return &citadel.WebhookRecord{
		ID:         w.ID.String(),
		URL:        w.URL,
		SecretHMAC: w.SecretHMAC,
		Active:     w.Active,
	}, nil
}

// WorkerMetricsAdapter wraps *metrics.Registry so it satisfies
// citadel.Metrics. Each method delegates to the matching collector.
type WorkerMetricsAdapter struct {
	Inner *metrics.Registry
}

// WorkerMetrics is a convenience constructor.
func WorkerMetrics(r *metrics.Registry) *WorkerMetricsAdapter {
	return &WorkerMetricsAdapter{Inner: r}
}

// IncEnqueued implements citadel.Metrics.
func (a *WorkerMetricsAdapter) IncEnqueued(destination, eventType string) {
	if a == nil || a.Inner == nil {
		return
	}
	a.Inner.OutboxEnqueuedTotal.WithLabelValues(destination, eventType).Inc()
}

// IncDelivered implements citadel.Metrics.
func (a *WorkerMetricsAdapter) IncDelivered(destination, eventType string) {
	if a == nil || a.Inner == nil {
		return
	}
	a.Inner.OutboxDeliveredTotal.WithLabelValues(destination, eventType).Inc()
}

// IncFailed implements citadel.Metrics.
func (a *WorkerMetricsAdapter) IncFailed(destination, eventType string, retryable bool) {
	if a == nil || a.Inner == nil {
		return
	}
	tag := "false"
	if retryable {
		tag = "true"
	}
	a.Inner.OutboxFailedTotal.WithLabelValues(destination, eventType, tag).Inc()
}

// IncDLQ implements citadel.Metrics.
func (a *WorkerMetricsAdapter) IncDLQ() {
	if a == nil || a.Inner == nil {
		return
	}
	a.Inner.OutboxDLQDepth.Inc()
}

// IncInFlight implements citadel.Metrics.
func (a *WorkerMetricsAdapter) IncInFlight() {
	if a == nil || a.Inner == nil {
		return
	}
	a.Inner.OutboxInFlight.Inc()
}

// DecInFlight implements citadel.Metrics.
func (a *WorkerMetricsAdapter) DecInFlight() {
	if a == nil || a.Inner == nil {
		return
	}
	a.Inner.OutboxInFlight.Dec()
}

// ObserveDeliveryDuration implements citadel.Metrics.
func (a *WorkerMetricsAdapter) ObserveDeliveryDuration(destination, eventType string, seconds float64) {
	if a == nil || a.Inner == nil {
		return
	}
	a.Inner.OutboxDeliveryDuration.WithLabelValues(destination, eventType).Observe(seconds)
}

// ── IRFlow webhook handler adapters ───────────────────────────────────

// IRFlowCohortAdapter wraps *db.CohortStore + *db.EnrollmentStore so it
// satisfies handlers.CohortStore. The handler's interface speaks pure
// strings — adapters parse them as UUIDs.
//
// Multi-track cohorts: as of migration 0007 a cohort can carry N tracks
// via the cohort_tracks join table. Create leaves cohorts.track_id NULL
// and records every supplied track in cohort_tracks (UUIDs go into
// track_id, non-UUID slugs go into track_slug). The legacy
// single-track shape (cohorts.track_id != NULL, no rows in
// cohort_tracks) remains valid for older rows.
type IRFlowCohortAdapter struct {
	Cohorts     *db.CohortStore
	Enrollments *db.EnrollmentStore
	// Users resolves the system actor Create attributes cohorts to
	// (cohorts.created_by is NOT NULL REFERENCES users(id), and this
	// adapter has no authenticated human caller — see systemUserID).
	Users *db.UserStore
	// Tenant is the fallback tenant UUID used when the handler passes
	// an empty tenant string (the IRFlowWebhookOptions.Tenant field is
	// optional and may be unset). uuid.Nil disables the fallback.
	Tenant uuid.UUID
}

// IRFlowCohorts is a convenience constructor. tenantOverride may be
// uuid.Nil; when non-nil it is used whenever the handler passes an
// empty tenant string.
func IRFlowCohorts(cohorts *db.CohortStore, enrollments *db.EnrollmentStore, users *db.UserStore, tenantOverride uuid.UUID) *IRFlowCohortAdapter {
	return &IRFlowCohortAdapter{Cohorts: cohorts, Enrollments: enrollments, Users: users, Tenant: tenantOverride}
}

// systemUserEmail identifies the per-tenant service account cohorts
// created via the IRFlow incident-trigger webhook are attributed to.
// There is no authenticated human caller on this path (see Create).
const systemUserEmail = "irflow-system@cyberpath.internal"

// systemUserID finds or lazily creates the per-tenant IRFlow system user
// and returns its id. cohorts.created_by is NOT NULL REFERENCES
// users(id) and users.email is UNIQUE per (tenant_id, email), so this is
// idempotent and safe under concurrent callers within the same tenant —
// a duplicate-key race on Create is treated as "someone else created it
// first" and resolved with a follow-up lookup.
//
// This looks up by (tenant_id, email) directly against a.Users.Pool
// rather than through UserStore.FindByEmail, which matches by email
// alone with no tenant filter — since the same system-user email is
// reused across every tenant, that lookup could return an arbitrary
// tenant's row instead of this one.
func (a *IRFlowCohortAdapter) systemUserID(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	if a.Users == nil || a.Users.Pool == nil {
		return uuid.Nil, fmt.Errorf("wireup/cohort: no UserStore configured for system-user resolution")
	}
	find := func() (uuid.UUID, error) {
		var id uuid.UUID
		err := a.Users.Pool.QueryRow(ctx,
			`SELECT id FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL LIMIT 1`,
			tenantID, systemUserEmail,
		).Scan(&id)
		return id, err
	}

	if id, err := find(); err == nil {
		return id, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("wireup/cohort: lookup system user: %w", err)
	}

	created := &db.User{
		TenantID:    tenantID,
		Email:       systemUserEmail,
		DisplayName: "IRFlow (system)",
		Role:        "system",
	}
	if cerr := a.Users.Create(ctx, created); cerr != nil {
		// Lost a create race against another concurrent webhook call for
		// the same tenant — the row now exists, so look it up instead
		// of failing.
		if id, ferr := find(); ferr == nil {
			return id, nil
		}
		return uuid.Nil, fmt.Errorf("wireup/cohort: create system user: %w", cerr)
	}
	return created.ID, nil
}

func (a *IRFlowCohortAdapter) tenantUUID(tenant string) (uuid.UUID, error) {
	if tenant == "" {
		if a.Tenant == uuid.Nil {
			return uuid.Nil, fmt.Errorf("wireup/cohort: empty tenant and no override configured")
		}
		return a.Tenant, nil
	}
	return uuid.Parse(tenant)
}

// FindByName implements handlers.CohortStore. Returns ("", nil) when
// no row matches — same contract as the handler's interface.
func (a *IRFlowCohortAdapter) FindByName(ctx context.Context, tenant, name string) (string, error) {
	tid, err := a.tenantUUID(tenant)
	if err != nil {
		return "", err
	}
	rows, err := a.Cohorts.ListByTenant(ctx, tid, "")
	if err != nil {
		return "", err
	}
	for i := range rows {
		if rows[i].Name == name {
			return rows[i].ID.String(), nil
		}
	}
	return "", nil
}

// Create implements handlers.CohortStore. Each entry in trackIDs is
// classified as UUID or slug and persisted as a row in cohort_tracks;
// the cohorts.track_id column is left NULL so callers always read
// multi-track cohorts through the join table.
func (a *IRFlowCohortAdapter) Create(ctx context.Context, tenant, name string, trackIDs []string) (string, error) {
	tid, err := a.tenantUUID(tenant)
	if err != nil {
		return "", err
	}
	createdBy, err := a.systemUserID(ctx, tid)
	if err != nil {
		return "", err
	}
	c := &db.Cohort{
		TenantID:  tid,
		Name:      name,
		Status:    "active",
		CreatedBy: createdBy,
		Metadata:  json.RawMessage(`{"source":"irflow"}`),
		// TrackID intentionally left nil — multi-track refs live in
		// cohort_tracks (migration 0007).
	}
	out, err := a.Cohorts.Create(ctx, c)
	if err != nil {
		return "", err
	}

	// Classify each ref. Parseable as UUID → track_id; otherwise the
	// raw string becomes a track_slug for later reconciliation.
	var (
		uuids []uuid.UUID
		slugs []string
	)
	for _, raw := range trackIDs {
		if raw == "" {
			continue
		}
		if parsed, perr := uuid.Parse(raw); perr == nil {
			uuids = append(uuids, parsed)
			continue
		}
		slugs = append(slugs, raw)
	}
	if len(uuids) > 0 || len(slugs) > 0 {
		if err := a.Cohorts.LinkTracks(ctx, out.ID, uuids, slugs); err != nil {
			return "", fmt.Errorf("wireup/cohort: link tracks: %w", err)
		}
	}
	return out.ID.String(), nil
}

// Enroll implements handlers.CohortStore. Returns the count of users
// successfully enrolled (errors on individual rows are swallowed and
// excluded from the count, matching the handler's "duplicates skipped"
// contract).
func (a *IRFlowCohortAdapter) Enroll(ctx context.Context, cohortID string, userIDs []string) (int, error) {
	cid, err := uuid.Parse(cohortID)
	if err != nil {
		return 0, fmt.Errorf("wireup/cohort: bad cohort id: %w", err)
	}
	cohort, err := a.Cohorts.Get(ctx, cid)
	if err != nil {
		return 0, fmt.Errorf("wireup/cohort: resolve cohort for enroll: %w", err)
	}
	byUserID, err := a.systemUserID(ctx, cohort.TenantID)
	if err != nil {
		return 0, err
	}
	enrolled := 0
	for _, raw := range userIDs {
		uid, perr := uuid.Parse(raw)
		if perr != nil {
			// Non-UUID user reference — count as unknown user.
			return enrolled, apihandlers.ErrUnknownUser
		}
		if _, err := a.Enrollments.Enroll(ctx, cid, uid, byUserID); err != nil {
			// Duplicate active enrollment violates the partial unique
			// index — skip silently. Other errors propagate.
			continue
		}
		enrolled++
	}
	return enrolled, nil
}

// IRFlowAuditAdapter wraps *db.AuditEventStore so it satisfies
// handlers.AuditEmitter. The handler-side shape is (eventType, payload);
// db.AuditEvent is richer — fields not surfaced by the handler are left
// at their zero values.
type IRFlowAuditAdapter struct {
	Inner *db.AuditEventStore
}

// IRFlowAudit is a convenience constructor.
func IRFlowAudit(s *db.AuditEventStore) *IRFlowAuditAdapter {
	return &IRFlowAuditAdapter{Inner: s}
}

// Emit implements handlers.AuditEmitter.
func (a *IRFlowAuditAdapter) Emit(ctx context.Context, eventType string, payload map[string]any) error {
	meta, _ := json.Marshal(payload)
	ev := &db.AuditEvent{
		Action:   eventType,
		Outcome:  "success",
		Metadata: meta,
	}
	if v, ok := payload["correlation_id"].(string); ok {
		ev.CorrelationID = v
	}
	if v, ok := payload["cohort_id"].(string); ok {
		ev.TargetType = "cohort"
		ev.TargetID = v
	}
	return a.Inner.Append(ctx, ev)
}

// IRFlowOutboxAdapter wraps *db.OutboxStore so it satisfies
// handlers.OutboxEnqueuer. CITADEL is the default destination.
type IRFlowOutboxAdapter struct {
	Inner *db.OutboxStore
}

// IRFlowOutbox is a convenience constructor.
func IRFlowOutbox(s *db.OutboxStore) *IRFlowOutboxAdapter {
	return &IRFlowOutboxAdapter{Inner: s}
}

// Enqueue implements handlers.OutboxEnqueuer.
func (a *IRFlowOutboxAdapter) Enqueue(ctx context.Context, eventType string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("wireup/outbox: marshal payload: %w", err)
	}
	entry := &db.OutboxEntry{
		Destination: "citadel",
		EventType:   eventType,
		Payload:     body,
	}
	if v, ok := payload["correlation_id"].(string); ok {
		entry.CorrelationID = v
	}
	_, err = a.Inner.Enqueue(ctx, entry)
	return err
}

// ── Certification outbox adapter ──────────────────────────────────────

// CertOutboxAdapter wraps *db.OutboxStore so it satisfies
// citadel.OutboxEnqueuer. Bridges citadel.EnqueueRequest → *db.OutboxEntry.
type CertOutboxAdapter struct {
	Inner *db.OutboxStore
}

// CertOutbox is a convenience constructor.
func CertOutbox(s *db.OutboxStore) *CertOutboxAdapter {
	return &CertOutboxAdapter{Inner: s}
}

// Enqueue implements citadel.OutboxEnqueuer.
func (a *CertOutboxAdapter) Enqueue(ctx context.Context, req citadel.EnqueueRequest) (int64, error) {
	var tenantID *uuid.UUID
	if req.TenantID != "" {
		parsed, err := uuid.Parse(req.TenantID)
		if err == nil {
			tenantID = &parsed
		}
	}
	var webhookID *uuid.UUID
	if req.WebhookID != "" {
		parsed, err := uuid.Parse(req.WebhookID)
		if err == nil {
			webhookID = &parsed
		}
	}
	entry := &db.OutboxEntry{
		TenantID:      tenantID,
		Destination:   req.Destination,
		WebhookID:     webhookID,
		EventType:     req.EventType,
		Payload:       req.Payload,
		CorrelationID: req.CorrelationID,
	}
	return a.Inner.Enqueue(ctx, entry)
}

// ── helpers ───────────────────────────────────────────────────────────

func uuidPtrToString(p *uuid.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}
