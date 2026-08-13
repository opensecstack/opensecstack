package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAuditStoreLive_InsertPersists(t *testing.T) {
	pool := liveDB(t)
	s := NewAuditStore(pool)
	ctx := context.Background()

	a := &AuditEntry{ActorRole: "admin", Action: "test.live.insert", Metadata: map[string]any{"k": "v"}}
	if err := s.Insert(ctx, a); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM audit_log WHERE id = $1`, a.ID) })

	var action string
	if err := pool.QueryRow(ctx, `SELECT action FROM audit_log WHERE id = $1`, a.ID).Scan(&action); err != nil {
		t.Fatalf("verify insert: %v", err)
	}
	if action != "test.live.insert" {
		t.Errorf("action = %q, want %q", action, "test.live.insert")
	}
}

func TestIOCIngestStoreLive_InsertAndLastForSource(t *testing.T) {
	pool := liveDB(t)
	s := NewIOCIngestStore(pool)
	ctx := context.Background()

	source := "threatflow-" + uuid.NewString()
	e := &IOCIngestEntry{Source: source, BundleSHA256: "abc", Count: 5}
	if err := s.Insert(ctx, e); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM ioc_ingest_log WHERE id = $1`, e.ID) })

	got, err := s.LastForSource(ctx, source)
	if err != nil {
		t.Fatalf("LastForSource: %v", err)
	}
	if got.BundleSHA256 != "abc" || got.Count != 5 {
		t.Errorf("LastForSource = %+v, want BundleSHA256=abc Count=5", got)
	}
}
