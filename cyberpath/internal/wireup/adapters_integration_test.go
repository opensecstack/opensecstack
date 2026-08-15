//go:build integration

// Integration coverage for the DB-backed wireup adapters — the methods
// in adapters.go that forward to *db.XStore and can't be exercised
// without a real Postgres connection (no interface seam on the store
// fields; they're concrete pgx-backed types).
//
// Requires CYBERPATH_TEST_DB_URL pointing at a fully-migrated cyberpath
// schema; skipped otherwise. Run with:
//
//	go test -tags integration -p 1 -count=1 ./internal/wireup/...
package wireup

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	apihandlers "github.com/opensecstack/cyberpath/internal/api/handlers"
	"github.com/opensecstack/cyberpath/internal/citadel"
	"github.com/opensecstack/cyberpath/internal/db"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedTenant(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "t-"+tenantID.String()[:8], "wireup-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})
	return tenantID
}

func seedUser(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID, role string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, role_id) VALUES ($1, $2, $3, $4)`,
		userID, tenantID, userID.String()+"@wireup-test.local", role); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

// ── AuthUserAdapter ─────────────────────────────────────────────────

func TestAuthUserAdapter_FindByEmail_Success(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	userID := seedUser(t, pool, tenantID, "learner")

	adapter := AuthUsers(db.NewUserStore(pool))
	ctx := context.Background()

	var email string
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
		t.Fatalf("read back seeded email: %v", err)
	}

	got, err := adapter.FindByEmail(ctx, email)
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}
	if got.ID != userID.String() {
		t.Errorf("ID: got %q, want %q", got.ID, userID.String())
	}
	if got.TenantID != tenantID.String() {
		t.Errorf("TenantID: got %q, want %q", got.TenantID, tenantID.String())
	}
}

func TestAuthUserAdapter_FindByEmail_NotFound(t *testing.T) {
	pool := testPool(t)
	adapter := AuthUsers(db.NewUserStore(pool))

	_, err := adapter.FindByEmail(context.Background(), "nobody-wireup-test@example.com")
	if err != apihandlers.ErrUserNotFound {
		t.Fatalf("FindByEmail: got err %v, want apihandlers.ErrUserNotFound", err)
	}
}

func TestAuthUserAdapter_FindByID_Success(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	userID := seedUser(t, pool, tenantID, "learner")

	adapter := AuthUsers(db.NewUserStore(pool))
	got, err := adapter.FindByID(context.Background(), userID.String())
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != userID.String() {
		t.Errorf("ID: got %q, want %q", got.ID, userID.String())
	}
}

func TestAuthUserAdapter_FindByID_BadUUID(t *testing.T) {
	pool := testPool(t)
	adapter := AuthUsers(db.NewUserStore(pool))

	_, err := adapter.FindByID(context.Background(), "not-a-uuid")
	if err != apihandlers.ErrUserNotFound {
		t.Fatalf("FindByID: got err %v, want apihandlers.ErrUserNotFound", err)
	}
}

func TestAuthUserAdapter_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	adapter := AuthUsers(db.NewUserStore(pool))

	_, err := adapter.FindByID(context.Background(), uuid.New().String())
	if err != apihandlers.ErrUserNotFound {
		t.Fatalf("FindByID: got err %v, want apihandlers.ErrUserNotFound", err)
	}
}

func TestAuthUserAdapter_UpdatePasswordHash_Success(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	userID := seedUser(t, pool, tenantID, "learner")

	adapter := AuthUsers(db.NewUserStore(pool))
	if err := adapter.UpdatePasswordHash(context.Background(), userID.String(), "$argon2id$new"); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}

	var hash string
	if err := pool.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&hash); err != nil {
		t.Fatalf("read back hash: %v", err)
	}
	if hash != "$argon2id$new" {
		t.Errorf("password_hash: got %q, want $argon2id$new", hash)
	}
}

func TestAuthUserAdapter_UpdatePasswordHash_BadUUID(t *testing.T) {
	pool := testPool(t)
	adapter := AuthUsers(db.NewUserStore(pool))

	err := adapter.UpdatePasswordHash(context.Background(), "not-a-uuid", "x")
	if err != apihandlers.ErrUserNotFound {
		t.Fatalf("UpdatePasswordHash: got err %v, want apihandlers.ErrUserNotFound", err)
	}
}

// ── WorkerOutboxAdapter ─────────────────────────────────────────────

func TestWorkerOutboxAdapter_ClaimMarkDeliveredMarkFailed(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)

	outboxAdapter := WorkerOutbox(db.NewOutboxStore(pool))
	ctx := context.Background()

	id, err := db.NewOutboxStore(pool).Enqueue(ctx, &db.OutboxEntry{
		TenantID:    &tenantID,
		Destination: "citadel",
		EventType:   "lesson_completed",
		Payload:     []byte(`{"foo":"bar"}`),
	})
	if err != nil {
		t.Fatalf("seed enqueue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM outbox WHERE id = $1`, id)
	})

	entries, err := outboxAdapter.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.ID == id {
			found = true
			if e.TenantID != tenantID.String() {
				t.Errorf("TenantID: got %q, want %q", e.TenantID, tenantID.String())
			}
			if e.EventType != "lesson_completed" {
				t.Errorf("EventType: got %q", e.EventType)
			}
		}
	}
	if !found {
		t.Fatalf("Claim: expected to find outbox entry %d among %d claimed rows", id, len(entries))
	}

	if err := outboxAdapter.MarkDelivered(ctx, id); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM outbox WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatalf("read back status: %v", err)
	}
	if status != "delivered" {
		t.Errorf("status after MarkDelivered: got %q, want delivered", status)
	}
}

func TestWorkerOutboxAdapter_MarkFailed_MovesToDLQAfterCap(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	store := db.NewOutboxStore(pool)
	id, err := store.Enqueue(ctx, &db.OutboxEntry{
		TenantID:    &tenantID,
		Destination: "citadel",
		EventType:   "lesson_completed",
		Payload:     []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("seed enqueue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM outbox WHERE id = $1`, id)
	})
	// Push attempts to 10 directly so the next MarkFailed call trips the DLQ threshold.
	if _, err := pool.Exec(ctx, `UPDATE outbox SET attempts = 10 WHERE id = $1`, id); err != nil {
		t.Fatalf("bump attempts: %v", err)
	}

	adapter := WorkerOutbox(store)
	movedToDLQ, err := adapter.MarkFailed(ctx, id, "boom", true)
	if err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	if !movedToDLQ {
		t.Errorf("MarkFailed: expected movedToDLQ=true after 11th attempt")
	}
}

func TestWorkerOutboxAdapter_MarkFailed_StaysPendingBelowCap(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	store := db.NewOutboxStore(pool)
	id, err := store.Enqueue(ctx, &db.OutboxEntry{
		TenantID:    &tenantID,
		Destination: "citadel",
		EventType:   "lesson_completed",
		Payload:     []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("seed enqueue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM outbox WHERE id = $1`, id)
	})

	adapter := WorkerOutbox(store)
	movedToDLQ, err := adapter.MarkFailed(ctx, id, "transient", true)
	if err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	if movedToDLQ {
		t.Errorf("MarkFailed: expected movedToDLQ=false on first failure")
	}
}

func TestWorkerOutboxAdapter_MarkFailed_RowVanished(t *testing.T) {
	pool := testPool(t)
	adapter := WorkerOutbox(db.NewOutboxStore(pool))

	// A non-existent id: MarkFailed's UPDATE affects 0 rows (no error),
	// then the follow-up SELECT finds no row → pgx.ErrNoRows branch.
	movedToDLQ, err := adapter.MarkFailed(context.Background(), -1, "boom", false)
	if err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	if movedToDLQ {
		t.Errorf("MarkFailed: expected movedToDLQ=false for vanished row")
	}
}

// ── WorkerWebhookAdapter ────────────────────────────────────────────

func TestWorkerWebhookAdapter_GetWebhook_Success(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	store := db.NewWebhookStore(pool)
	w, err := store.Create(ctx, &db.Webhook{
		TenantID:   tenantID,
		Name:       "wireup-test-hook",
		URL:        "https://example.com/hook",
		SecretHMAC: "s3cret",
		Active:     true,
	})
	if err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhooks WHERE id = $1`, w.ID)
	})

	adapter := WorkerWebhooks(store)
	got, err := adapter.GetWebhook(ctx, w.ID.String())
	if err != nil {
		t.Fatalf("GetWebhook: %v", err)
	}
	if got.ID != w.ID.String() {
		t.Errorf("ID: got %q, want %q", got.ID, w.ID.String())
	}
	if got.URL != "https://example.com/hook" {
		t.Errorf("URL: got %q", got.URL)
	}
	if got.SecretHMAC != "s3cret" {
		t.Errorf("SecretHMAC: got %q", got.SecretHMAC)
	}
	if !got.Active {
		t.Errorf("Active: got false, want true")
	}
}

func TestWorkerWebhookAdapter_GetWebhook_BadID(t *testing.T) {
	pool := testPool(t)
	adapter := WorkerWebhooks(db.NewWebhookStore(pool))

	_, err := adapter.GetWebhook(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatalf("GetWebhook: expected error for malformed id")
	}
}

func TestWorkerWebhookAdapter_GetWebhook_NotFound(t *testing.T) {
	pool := testPool(t)
	adapter := WorkerWebhooks(db.NewWebhookStore(pool))

	_, err := adapter.GetWebhook(context.Background(), uuid.New().String())
	if err == nil {
		t.Fatalf("GetWebhook: expected error for missing row")
	}
}

// ── IRFlowCohortAdapter ─────────────────────────────────────────────

func TestIRFlowCohortAdapter_CreateFindByNameEnroll(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	learner := seedUser(t, pool, tenantID, "learner")
	ctx := context.Background()

	cohorts := db.NewCohortStore(pool)
	enrollments := db.NewEnrollmentStore(pool)
	adapter := IRFlowCohorts(cohorts, enrollments, db.NewUserStore(pool), uuid.Nil)

	trackUUID := uuid.New()
	cohortID, err := adapter.Create(ctx, tenantID.String(), "wireup-irflow-cohort", []string{trackUUID.String(), "some-slug"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM cohort_tracks WHERE cohort_id = $1`, cohortID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM cohorts WHERE id = $1`, cohortID)
	})
	if cohortID == "" {
		t.Fatalf("Create: expected non-empty cohort id")
	}

	found, err := adapter.FindByName(ctx, tenantID.String(), "wireup-irflow-cohort")
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	if found != cohortID {
		t.Errorf("FindByName: got %q, want %q", found, cohortID)
	}

	notFound, err := adapter.FindByName(ctx, tenantID.String(), "does-not-exist")
	if err != nil {
		t.Fatalf("FindByName (miss): %v", err)
	}
	if notFound != "" {
		t.Errorf("FindByName (miss): got %q, want empty string", notFound)
	}

	n, err := adapter.Enroll(ctx, cohortID, []string{learner.String()})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if n != 1 {
		t.Errorf("Enroll: got %d enrolled, want 1", n)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM cohort_enrollments WHERE cohort_id::text = $1`, cohortID)
	})

	// Re-enrolling the same user hits the partial unique index and is
	// skipped silently — count should stay at 0 successful enrollments.
	n2, err := adapter.Enroll(ctx, cohortID, []string{learner.String()})
	if err != nil {
		t.Fatalf("Enroll (duplicate): %v", err)
	}
	if n2 != 0 {
		t.Errorf("Enroll (duplicate): got %d, want 0 (duplicate skipped)", n2)
	}
}

func TestIRFlowCohortAdapter_Enroll_BadCohortID(t *testing.T) {
	pool := testPool(t)
	adapter := IRFlowCohorts(db.NewCohortStore(pool), db.NewEnrollmentStore(pool), db.NewUserStore(pool), uuid.Nil)

	_, err := adapter.Enroll(context.Background(), "not-a-uuid", []string{uuid.New().String()})
	if err == nil {
		t.Fatalf("Enroll: expected error for malformed cohort id")
	}
}

func TestIRFlowCohortAdapter_Enroll_UnknownUser(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	cohorts := db.NewCohortStore(pool)
	adapter := IRFlowCohorts(cohorts, db.NewEnrollmentStore(pool), db.NewUserStore(pool), uuid.Nil)

	cohortID, err := adapter.Create(ctx, tenantID.String(), "wireup-irflow-cohort-2", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM cohorts WHERE id = $1`, cohortID)
	})

	_, err = adapter.Enroll(ctx, cohortID, []string{"not-a-uuid"})
	if err != apihandlers.ErrUnknownUser {
		t.Fatalf("Enroll: got err %v, want apihandlers.ErrUnknownUser", err)
	}
}

func TestIRFlowCohortAdapter_Create_EmptyTenant_NoOverride(t *testing.T) {
	pool := testPool(t)
	adapter := IRFlowCohorts(db.NewCohortStore(pool), db.NewEnrollmentStore(pool), db.NewUserStore(pool), uuid.Nil)

	_, err := adapter.Create(context.Background(), "", "should-fail", nil)
	if err == nil {
		t.Fatalf("Create: expected error for empty tenant with no override")
	}
}

// ── IRFlowAuditAdapter ──────────────────────────────────────────────

func TestIRFlowAuditAdapter_Emit(t *testing.T) {
	pool := testPool(t)
	adapter := IRFlowAudit(db.NewAuditEventStore(pool))
	ctx := context.Background()

	correlationID := uuid.New().String()
	cohortID := uuid.New().String()
	err := adapter.Emit(ctx, "cohort.created", map[string]any{
		"correlation_id": correlationID,
		"cohort_id":      cohortID,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE correlation_id = $1`, correlationID)
	})

	var action, outcome, targetType, targetID string
	err = pool.QueryRow(ctx, `
		SELECT action, outcome, target_type, target_id FROM audit_events
		WHERE correlation_id = $1`, correlationID,
	).Scan(&action, &outcome, &targetType, &targetID)
	if err != nil {
		t.Fatalf("read back audit event: %v", err)
	}
	if action != "cohort.created" {
		t.Errorf("action: got %q", action)
	}
	if outcome != "success" {
		t.Errorf("outcome: got %q", outcome)
	}
	if targetType != "cohort" {
		t.Errorf("target_type: got %q, want cohort", targetType)
	}
	if targetID != cohortID {
		t.Errorf("target_id: got %q, want %q", targetID, cohortID)
	}
}

func TestIRFlowAuditAdapter_Emit_NoOptionalFields(t *testing.T) {
	pool := testPool(t)
	adapter := IRFlowAudit(db.NewAuditEventStore(pool))
	ctx := context.Background()

	err := adapter.Emit(ctx, "generic.event", map[string]any{"other": "value"})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE action = 'generic.event'`)
	})
}

// ── IRFlowOutboxAdapter ─────────────────────────────────────────────

func TestIRFlowOutboxAdapter_Enqueue(t *testing.T) {
	pool := testPool(t)
	adapter := IRFlowOutbox(db.NewOutboxStore(pool))
	ctx := context.Background()

	correlationID := uuid.New().String()
	err := adapter.Enqueue(ctx, "cohort.created", map[string]any{
		"correlation_id": correlationID,
		"foo":            "bar",
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM outbox WHERE correlation_id = $1`, correlationID)
	})

	var destination, eventType string
	err = pool.QueryRow(ctx, `
		SELECT destination, event_type FROM outbox WHERE correlation_id = $1`, correlationID,
	).Scan(&destination, &eventType)
	if err != nil {
		t.Fatalf("read back outbox row: %v", err)
	}
	if destination != "citadel" {
		t.Errorf("destination: got %q, want citadel", destination)
	}
	if eventType != "cohort.created" {
		t.Errorf("event_type: got %q", eventType)
	}
}

// ── CertOutboxAdapter ───────────────────────────────────────────────

func TestCertOutboxAdapter_Enqueue_WithTenantAndWebhook(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	webhookStore := db.NewWebhookStore(pool)
	w, err := webhookStore.Create(ctx, &db.Webhook{
		TenantID:   tenantID,
		Name:       "cert-outbox-hook",
		URL:        "https://example.com/cert-hook",
		SecretHMAC: "s3cret",
		Active:     true,
	})
	if err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhooks WHERE id = $1`, w.ID)
	})

	adapter := CertOutbox(db.NewOutboxStore(pool))
	correlationID := uuid.New().String()
	id, err := adapter.Enqueue(ctx, citadel.EnqueueRequest{
		TenantID:      tenantID.String(),
		Destination:   "both",
		WebhookID:     w.ID.String(),
		EventType:     "cert.issued",
		Payload:       []byte(`{}`),
		CorrelationID: correlationID,
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM outbox WHERE id = $1`, id)
	})

	var gotTenant, gotWebhook uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id, webhook_id FROM outbox WHERE id = $1`, id).Scan(&gotTenant, &gotWebhook); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if gotTenant != tenantID {
		t.Errorf("tenant_id: got %s, want %s", gotTenant, tenantID)
	}
	if gotWebhook != w.ID {
		t.Errorf("webhook_id: got %s, want %s", gotWebhook, w.ID)
	}
}

func TestCertOutboxAdapter_Enqueue_BadIDsIgnored(t *testing.T) {
	pool := testPool(t)
	adapter := CertOutbox(db.NewOutboxStore(pool))
	ctx := context.Background()

	// Malformed TenantID/WebhookID are silently dropped (left nil) rather
	// than erroring — matches the adapter's `if err == nil` guard.
	id, err := adapter.Enqueue(ctx, citadel.EnqueueRequest{
		TenantID:      "not-a-uuid",
		Destination:   "citadel",
		WebhookID:     "also-not-a-uuid",
		EventType:     "cert.issued",
		Payload:       []byte(`{}`),
		CorrelationID: uuid.New().String(),
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM outbox WHERE id = $1`, id)
	})

	var gotTenant, gotWebhook *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id, webhook_id FROM outbox WHERE id = $1`, id).Scan(&gotTenant, &gotWebhook); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if gotTenant != nil {
		t.Errorf("tenant_id: got %v, want nil", gotTenant)
	}
	if gotWebhook != nil {
		t.Errorf("webhook_id: got %v, want nil", gotWebhook)
	}
}
