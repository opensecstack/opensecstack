//go:build integration

// Integration tests for AuditEventStore. Requires CYBERPATH_TEST_DB_URL
// pointing at a fully-migrated cyberpath schema; otherwise skipped.
package db

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func auditTestPool(t *testing.T) *pgxpool.Pool {
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

func seedAuditTenantAndUser(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "a-"+tenantID.String()[:8], "audit-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, role) VALUES ($1,$2,$3,'instructor')`,
		userID, tenantID, userID.String()+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	return tenantID, userID
}

func TestAuditEventStore_AppendAndQuery(t *testing.T) {
	pool := auditTestPool(t)
	ctx := context.Background()
	tenantID, userID := seedAuditTenantAndUser(t, pool)
	store := NewAuditEventStore(pool)

	corrID := "corr-" + uuid.NewString()[:8]
	e := &AuditEvent{
		TenantID:      &tenantID,
		ActorUserID:   &userID,
		ActorRole:     "instructor",
		Action:        "track.publish",
		TargetType:    "track",
		TargetID:      uuid.NewString(),
		Outcome:       "success",
		Metadata:      json.RawMessage(`{"reason":"test"}`),
		CorrelationID: corrID,
		IPAddress:     "203.0.113.7",
		UserAgent:     "go-test/1.0",
	}
	if err := store.Append(ctx, e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e.ID == uuid.Nil {
		t.Fatal("Append: id not populated")
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE id = $1`, e.ID)
	})

	list2, err := store.Query(ctx, AuditFilter{TenantID: &tenantID, Action: "track.publish"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(list2) != 1 {
		t.Fatalf("Query: expected 1 row, got %d", len(list2))
	}
	got := list2[0]
	if got.ID != e.ID {
		t.Fatalf("Query: id mismatch got %s want %s", got.ID, e.ID)
	}
	if got.CorrelationID != corrID {
		t.Fatalf("Query: correlation_id mismatch got %q want %q", got.CorrelationID, corrID)
	}
	if got.IPAddress != "203.0.113.7" {
		t.Fatalf("Query: ip_address mismatch got %q", got.IPAddress)
	}
	if got.TargetType != "track" {
		t.Fatalf("Query: target_type mismatch got %q", got.TargetType)
	}

	count, err := store.Count(ctx, AuditFilter{TenantID: &tenantID, Action: "track.publish"})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Fatalf("Count: expected 1, got %d", count)
	}

	// Filter that matches nothing.
	empty, err := store.Query(ctx, AuditFilter{TenantID: &tenantID, Action: "no.such.action"})
	if err != nil {
		t.Fatalf("Query (no match): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("Query (no match): expected 0 rows, got %d", len(empty))
	}
}

func TestAuditEventStore_Append_DefaultsAndTimeWindow(t *testing.T) {
	pool := auditTestPool(t)
	ctx := context.Background()
	tenantID, _ := seedAuditTenantAndUser(t, pool)
	store := NewAuditEventStore(pool)

	// No metadata, no explicit CreatedAt, no actor -> system event.
	e := &AuditEvent{
		TenantID:  &tenantID,
		ActorRole: "system",
		Action:    "cron.sweep",
		Outcome:   "success",
	}
	before := time.Now().Add(-2 * time.Second)
	if err := store.Append(ctx, e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE id = $1`, e.ID)
	})
	after := time.Now().Add(2 * time.Second)

	got, err := store.Query(ctx, AuditFilter{TenantID: &tenantID, Action: "cron.sweep"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	row := got[0]
	if string(row.Metadata) != "{}" {
		t.Fatalf("expected default metadata '{}', got %q", string(row.Metadata))
	}
	if row.ActorUserID != nil {
		t.Fatal("expected nil ActorUserID for system event")
	}
	if row.CreatedAt.Before(before) || row.CreatedAt.After(after) {
		t.Fatalf("CreatedAt %v not in expected window [%v, %v]", row.CreatedAt, before, after)
	}

	// From/To range filtering.
	from := before
	to := after
	ranged, err := store.Query(ctx, AuditFilter{TenantID: &tenantID, From: &from, To: &to})
	if err != nil {
		t.Fatalf("Query with range: %v", err)
	}
	found := false
	for _, r := range ranged {
		if r.ID == e.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("range query did not return the seeded event")
	}

	// A "To" before the event's created_at excludes it.
	tooEarly := before
	excluded, err := store.Query(ctx, AuditFilter{TenantID: &tenantID, To: &tooEarly})
	if err != nil {
		t.Fatalf("Query with excluding range: %v", err)
	}
	for _, r := range excluded {
		if r.ID == e.ID {
			t.Fatal("range query with To before created_at incorrectly included the event")
		}
	}
}

func TestAuditEventStore_Query_LimitClampingAndOffset(t *testing.T) {
	pool := auditTestPool(t)
	ctx := context.Background()
	tenantID, _ := seedAuditTenantAndUser(t, pool)
	store := NewAuditEventStore(pool)

	action := "bulk.action." + uuid.NewString()[:8]
	var ids []uuid.UUID
	for i := 0; i < 3; i++ {
		e := &AuditEvent{TenantID: &tenantID, ActorRole: "system", Action: action, Outcome: "success"}
		if err := store.Append(ctx, e); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
		ids = append(ids, e.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE id = $1`, id)
		}
	})

	// Negative limit clamps to default (100), so all 3 rows come back.
	all, err := store.Query(ctx, AuditFilter{TenantID: &tenantID, Action: action, Limit: -5})
	if err != nil {
		t.Fatalf("Query (negative limit): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rows with clamped limit, got %d", len(all))
	}

	// Limit=1 + Offset=1 returns exactly one row, distinct from the first page.
	page1, err := store.Query(ctx, AuditFilter{TenantID: &tenantID, Action: action, Limit: 1})
	if err != nil {
		t.Fatalf("Query page1: %v", err)
	}
	page2, err := store.Query(ctx, AuditFilter{TenantID: &tenantID, Action: action, Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("Query page2: %v", err)
	}
	if len(page1) != 1 || len(page2) != 1 {
		t.Fatalf("expected 1 row per page, got %d and %d", len(page1), len(page2))
	}
	if page1[0].ID == page2[0].ID {
		t.Fatal("expected distinct rows across offset pages")
	}

	count, err := store.Count(ctx, AuditFilter{TenantID: &tenantID, Action: action})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 3 {
		t.Fatalf("Count: expected 3, got %d", count)
	}
}
