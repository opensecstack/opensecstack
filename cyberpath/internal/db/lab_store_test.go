//go:build integration

// Integration tests for LabStore. Requires CYBERPATH_TEST_DB_URL pointing at
// a fully-migrated cyberpath schema; otherwise skipped.
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

func labTestPool(t *testing.T) *pgxpool.Pool {
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

// seedLabTenantUser seeds a tenant + learner user, registering cleanup.
func seedLabTenantUser(t *testing.T, pool *pgxpool.Pool) (tenantID, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tenantID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "lb-"+tenantID.String()[:8], "lab-store-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	userID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, role_id) VALUES ($1, $2, $3, 'learner')`,
		userID, tenantID, userID.String()+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return tenantID, userID
}

// seedLabDefinition inserts a bare lab_definitions row and registers cleanup.
func seedLabDefinition(t *testing.T, pool *pgxpool.Pool, id string, trackID *uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO lab_definitions (id, track_id, runtime, image, entry_command)
		VALUES ($1, $2, 'wasmtime', 'ghcr.io/cyberpath/lab:1', '/entry')`,
		id, trackID); err != nil {
		t.Fatalf("seed lab_definitions: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM lab_definitions WHERE id = $1`, id)
	})
}

func TestLabStore_GetDefinitionAndListByTrack(t *testing.T) {
	pool := labTestPool(t)
	ctx := context.Background()
	store := NewLabStore(pool)

	trackID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tracks (id, slug, title) VALUES ($1, $2, $3)`,
		trackID, "lab-trk-"+trackID.String()[:8], "Lab Track"); err != nil {
		t.Fatalf("seed track: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tracks WHERE id = $1`, trackID) })

	labID := "phishing/spear-" + uuid.NewString()[:8]
	seedLabDefinition(t, pool, labID, &trackID)

	got, err := store.GetDefinition(ctx, labID)
	if err != nil {
		t.Fatalf("GetDefinition: %v", err)
	}
	if got.Runtime != "wasmtime" || got.Image != "ghcr.io/cyberpath/lab:1" {
		t.Fatalf("GetDefinition: unexpected row %+v", got)
	}
	if got.TrackID == nil || *got.TrackID != trackID {
		t.Fatalf("GetDefinition: track_id mismatch: %+v", got.TrackID)
	}

	list, err := store.ListDefinitionsByTrack(ctx, trackID)
	if err != nil {
		t.Fatalf("ListDefinitionsByTrack: %v", err)
	}
	found := false
	for _, d := range list {
		if d.ID == labID {
			found = true
		}
	}
	if !found {
		t.Fatal("ListDefinitionsByTrack: missing our lab")
	}

	// Soft-deleted defs are excluded.
	if _, err := pool.Exec(ctx, `UPDATE lab_definitions SET deleted_at = now() WHERE id = $1`, labID); err != nil {
		t.Fatalf("soft delete def: %v", err)
	}
	list2, err := store.ListDefinitionsByTrack(ctx, trackID)
	if err != nil {
		t.Fatalf("ListDefinitionsByTrack (after delete): %v", err)
	}
	for _, d := range list2 {
		if d.ID == labID {
			t.Fatal("ListDefinitionsByTrack: soft-deleted lab still listed")
		}
	}
}

func TestLabStore_GetDefinition_NotFound(t *testing.T) {
	pool := labTestPool(t)
	ctx := context.Background()
	store := NewLabStore(pool)

	if _, err := store.GetDefinition(ctx, "no-such-lab-"+uuid.NewString()); err == nil {
		t.Fatal("GetDefinition(unknown id): expected error, got nil")
	}
}

func TestLabStore_StartSession_UnknownLab(t *testing.T) {
	pool := labTestPool(t)
	ctx := context.Background()
	tenantID, userID := seedLabTenantUser(t, pool)
	store := NewLabStore(pool)

	_, err := store.StartSession(ctx, "no-such-lab-"+uuid.NewString(), userID, nil, tenantID)
	if err == nil {
		t.Fatal("StartSession with unknown lab id: expected error, got nil")
	}
}

func TestLabStore_SessionLifecycle(t *testing.T) {
	pool := labTestPool(t)
	ctx := context.Background()
	tenantID, userID := seedLabTenantUser(t, pool)
	store := NewLabStore(pool)

	labID := "lifecycle-" + uuid.NewString()[:8]
	seedLabDefinition(t, pool, labID, nil)

	sess, err := store.StartSession(ctx, labID, userID, nil, tenantID)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM lab_sessions WHERE id = $1`, sess.ID)
	})
	if sess.Status != "starting" {
		t.Fatalf("StartSession: expected status starting, got %q", sess.Status)
	}
	if sess.Runtime != "wasmtime" {
		t.Fatalf("StartSession: runtime not copied from definition, got %q", sess.Runtime)
	}

	got, err := store.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != sess.ID {
		t.Fatalf("GetSession: id mismatch")
	}

	meta := json.RawMessage(`{"progress":50}`)
	if err := store.UpdateMetadata(ctx, sess.ID, meta); err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	afterMeta, err := store.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession after metadata: %v", err)
	}
	var gotMeta map[string]int
	if err := json.Unmarshal(afterMeta.Metadata, &gotMeta); err != nil {
		t.Fatalf("UpdateMetadata: unmarshal persisted metadata: %v", err)
	}
	if gotMeta["progress"] != 50 {
		t.Fatalf("UpdateMetadata: not persisted, got %s", afterMeta.Metadata)
	}

	score := 92
	result := json.RawMessage(`{"flag":"found"}`)
	if err := store.EndSession(ctx, sess.ID, "completed", result, &score, "s3://audit/log", "deadbeef"); err != nil {
		t.Fatalf("EndSession: %v", err)
	}

	final, err := store.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession after end: %v", err)
	}
	if final.Status != "completed" {
		t.Fatalf("EndSession: expected status completed, got %q", final.Status)
	}
	if final.EndedAt == nil {
		t.Fatal("EndSession: ended_at not stamped")
	}
	if final.OutcomeScore == nil || *final.OutcomeScore != 92 {
		t.Fatalf("EndSession: outcome_score mismatch: %+v", final.OutcomeScore)
	}
	if final.AuditLogURL != "s3://audit/log" || final.AuditHash != "deadbeef" {
		t.Fatalf("EndSession: audit fields mismatch: %+v", final)
	}

	list, err := store.ListSessionsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	found := false
	for _, s := range list {
		if s.ID == sess.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("ListSessionsByUser: missing our session")
	}
}

func TestLabStore_EndSession_InvalidScoreRejected(t *testing.T) {
	pool := labTestPool(t)
	ctx := context.Background()
	tenantID, userID := seedLabTenantUser(t, pool)
	store := NewLabStore(pool)

	labID := "badscore-" + uuid.NewString()[:8]
	seedLabDefinition(t, pool, labID, nil)

	sess, err := store.StartSession(ctx, labID, userID, nil, tenantID)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM lab_sessions WHERE id = $1`, sess.ID)
	})

	bad := 150 // outside 0-100 CHECK
	if err := store.EndSession(ctx, sess.ID, "completed", nil, &bad, "", ""); err == nil {
		t.Fatal("EndSession with out-of-range score: expected CHECK violation, got nil")
	}
}

func TestLabStore_GetSession_NotFound(t *testing.T) {
	pool := labTestPool(t)
	ctx := context.Background()
	store := NewLabStore(pool)

	if _, err := store.GetSession(ctx, uuid.New()); err == nil {
		t.Fatal("GetSession(unknown id): expected error, got nil")
	}
}
