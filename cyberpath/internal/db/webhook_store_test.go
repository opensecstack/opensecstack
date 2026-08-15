//go:build integration

// Integration tests for WebhookStore. Requires CYBERPATH_TEST_DB_URL
// pointing at a fully-migrated cyberpath schema; otherwise skipped.
package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func webhookTestPool(t *testing.T) *pgxpool.Pool {
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

func seedWebhookTenant(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "w-"+tenantID.String()[:8], "webhook-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})
	return tenantID
}

func TestWebhookStore_CreateGetUpdate(t *testing.T) {
	pool := webhookTestPool(t)
	ctx := context.Background()
	tenantID := seedWebhookTenant(t, pool)
	store := NewWebhookStore(pool)

	w := &Webhook{
		TenantID:   tenantID,
		Name:       "NIS2 Compass push",
		URL:        "https://nis2compass.example.test/hooks/cyberpath",
		EventTypes: []string{"cohort.completed", "certification.issued"},
		SecretHMAC: "s3cr3t-hmac-key",
		Active:     true,
	}
	created, err := store.Create(ctx, w)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("Create: id not populated")
	}
	if created.SecretVersion != 1 {
		t.Fatalf("Create: expected default secret_version 1, got %d", created.SecretVersion)
	}
	if len(created.EventTypes) != 2 {
		t.Fatalf("Create: event_types not persisted, got %v", created.EventTypes)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhooks WHERE id = $1`, created.ID)
	})

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.URL != w.URL || got.Name != w.Name {
		t.Fatalf("Get: mismatch, got %+v", got)
	}
	if got.SecretHMAC != w.SecretHMAC {
		t.Fatalf("Get: secret_hmac mismatch got %q want %q", got.SecretHMAC, w.SecretHMAC)
	}

	got.Name = "NIS2 Compass push (renamed)"
	got.URL = "https://nis2compass.example.test/hooks/cyberpath/v2"
	got.EventTypes = []string{"cohort.completed"}
	got.Active = false
	updated, err := store.Update(ctx, got)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != got.Name || updated.URL != got.URL || updated.Active != false {
		t.Fatalf("Update: mismatch, got %+v", updated)
	}
	if len(updated.EventTypes) != 1 {
		t.Fatalf("Update: event_types not updated, got %v", updated.EventTypes)
	}
	// Secret must be untouched by Update (rotation is a separate path).
	if updated.SecretHMAC != w.SecretHMAC {
		t.Fatalf("Update: secret_hmac must not change, got %q", updated.SecretHMAC)
	}
	if !updated.UpdatedAt.After(created.UpdatedAt) && !updated.UpdatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("Update: updated_at did not advance: created=%v updated=%v", created.UpdatedAt, updated.UpdatedAt)
	}
}

func TestWebhookStore_Get_NotFound(t *testing.T) {
	pool := webhookTestPool(t)
	ctx := context.Background()
	store := NewWebhookStore(pool)

	_, err := store.Get(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected error for unknown webhook id, got nil")
	}
}

func TestWebhookStore_ListByTenant(t *testing.T) {
	pool := webhookTestPool(t)
	ctx := context.Background()
	tenantID := seedWebhookTenant(t, pool)
	store := NewWebhookStore(pool)

	active, err := store.Create(ctx, &Webhook{
		TenantID: tenantID, Name: "active-hook", URL: "https://a.test/hook",
		SecretHMAC: "s1", Active: true,
	})
	if err != nil {
		t.Fatalf("Create active: %v", err)
	}
	inactive, err := store.Create(ctx, &Webhook{
		TenantID: tenantID, Name: "inactive-hook", URL: "https://b.test/hook",
		SecretHMAC: "s2", Active: false,
	})
	if err != nil {
		t.Fatalf("Create inactive: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhooks WHERE id = ANY($1)`,
			[]uuid.UUID{active.ID, inactive.ID})
	})

	all, err := store.ListByTenant(ctx, tenantID, false)
	if err != nil {
		t.Fatalf("ListByTenant(all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListByTenant(all): expected 2, got %d", len(all))
	}

	activeOnly, err := store.ListByTenant(ctx, tenantID, true)
	if err != nil {
		t.Fatalf("ListByTenant(activeOnly): %v", err)
	}
	if len(activeOnly) != 1 || activeOnly[0].ID != active.ID {
		t.Fatalf("ListByTenant(activeOnly): expected only %s, got %+v", active.ID, activeOnly)
	}

	other, err := store.ListByTenant(ctx, uuid.New(), false)
	if err != nil {
		t.Fatalf("ListByTenant(unknown tenant): %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("ListByTenant(unknown tenant): expected 0, got %d", len(other))
	}
}

func TestWebhookStore_RecordSuccessAndFailure(t *testing.T) {
	pool := webhookTestPool(t)
	ctx := context.Background()
	tenantID := seedWebhookTenant(t, pool)
	store := NewWebhookStore(pool)

	w, err := store.Create(ctx, &Webhook{
		TenantID: tenantID, Name: "flaky-hook", URL: "https://flaky.test/hook",
		SecretHMAC: "s1", Active: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhooks WHERE id = $1`, w.ID)
	})

	if err := store.RecordFailure(ctx, w.ID, "connection refused"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := store.RecordFailure(ctx, w.ID, "timeout"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	afterFailures, err := store.Get(ctx, w.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if afterFailures.ConsecutiveFailures != 2 {
		t.Fatalf("expected consecutive_failures=2, got %d", afterFailures.ConsecutiveFailures)
	}
	if afterFailures.LastFailureAt == nil {
		t.Fatal("expected last_failure_at to be set")
	}

	if err := store.RecordSuccess(ctx, w.ID); err != nil {
		t.Fatalf("RecordSuccess: %v", err)
	}
	afterSuccess, err := store.Get(ctx, w.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if afterSuccess.ConsecutiveFailures != 0 {
		t.Fatalf("RecordSuccess should reset consecutive_failures to 0, got %d", afterSuccess.ConsecutiveFailures)
	}
	if afterSuccess.LastSuccessAt == nil {
		t.Fatal("expected last_success_at to be set")
	}
	// The failure timestamp is retained (RecordSuccess does not clear it,
	// only the counter) — assert the actual documented behavior.
	if afterSuccess.LastFailureAt == nil {
		t.Fatal("expected last_failure_at to remain set after RecordSuccess")
	}
}

func TestWebhookStore_RotateSecret(t *testing.T) {
	pool := webhookTestPool(t)
	ctx := context.Background()
	tenantID := seedWebhookTenant(t, pool)
	store := NewWebhookStore(pool)

	w, err := store.Create(ctx, &Webhook{
		TenantID: tenantID, Name: "rotating-hook", URL: "https://rotate.test/hook",
		SecretHMAC: "old-secret", Active: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhooks WHERE id = $1`, w.ID)
	})
	if w.SecretVersion != 1 {
		t.Fatalf("expected initial secret_version 1, got %d", w.SecretVersion)
	}

	if err := store.RotateSecret(ctx, w.ID, "new-secret"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	got, err := store.Get(ctx, w.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SecretHMAC != "new-secret" {
		t.Fatalf("RotateSecret: secret not updated, got %q", got.SecretHMAC)
	}
	if got.SecretVersion != 2 {
		t.Fatalf("RotateSecret: expected secret_version 2, got %d", got.SecretVersion)
	}
}
