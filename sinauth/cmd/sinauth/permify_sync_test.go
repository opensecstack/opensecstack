package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// TestGroupMemberTuples_QueriesWithoutError proves groupMemberTuples issues
// a valid SELECT against group_members and maps every row into a
// group#member relationship tuple with non-empty entity/subject IDs. This
// intentionally does not assume any particular rows exist (the table is
// shared with other parallel test suites against the same database) — it
// only asserts the query succeeds and every row it does see is shaped
// correctly, which is what the mapping logic in permify_sync.go is
// responsible for.
func TestGroupMemberTuples_QueriesWithoutError(t *testing.T) {
	pool := requireDB(t)
	tuples, err := groupMemberTuples(context.Background(), pool)
	if err != nil {
		t.Fatalf("groupMemberTuples: %v", err)
	}
	for _, rel := range tuples {
		if rel.Entity.Type != "group" || rel.Entity.ID == "" {
			t.Errorf("group tuple has bad entity: %+v", rel.Entity)
		}
		if rel.Relation != "member" {
			t.Errorf("group tuple relation = %q, want member", rel.Relation)
		}
		if rel.Subject.Type != "user" || rel.Subject.ID == "" {
			t.Errorf("group tuple has bad subject: %+v", rel.Subject)
		}
	}
}

func TestUserClientRoleTuples_QueriesWithoutError(t *testing.T) {
	pool := requireDB(t)
	tuples, err := userClientRoleTuples(context.Background(), pool)
	if err != nil {
		t.Fatalf("userClientRoleTuples: %v", err)
	}
	for _, rel := range tuples {
		if rel.Entity.Type != "client_role" || rel.Entity.ID == "" {
			t.Errorf("role tuple has bad entity: %+v", rel.Entity)
		}
		if rel.Relation != "assignee" {
			t.Errorf("role tuple relation = %q, want assignee", rel.Relation)
		}
		if rel.Subject.Type != "user" || rel.Subject.ID == "" {
			t.Errorf("role tuple has bad subject: %+v", rel.Subject)
		}
	}
}

func TestOrganizationMemberTuples_QueriesWithoutError(t *testing.T) {
	pool := requireDB(t)
	tuples, err := organizationMemberTuples(context.Background(), pool)
	if err != nil {
		t.Fatalf("organizationMemberTuples: %v", err)
	}
	for _, rel := range tuples {
		if rel.Entity.Type != "organization" || rel.Entity.ID == "" {
			t.Errorf("org tuple has bad entity: %+v", rel.Entity)
		}
		if rel.Relation == "" {
			t.Error("org tuple relation is empty, want the row's own org_role")
		}
		if rel.Subject.Type != "user" || rel.Subject.ID == "" {
			t.Errorf("org tuple has bad subject: %+v", rel.Subject)
		}
	}
}

// TestRunPermifySync_NoopCheckerSucceeds exercises the full runPermifySync
// path against the real DB with Permify left unconfigured (SINAUTH_PERMIFY_URL
// unset), which is the same real-vs-noop pattern internal/api/server.go
// documents for the SMS provider: authz.New(cfg) falls back to
// authz.NoopChecker, whose WriteRelationship always succeeds without making
// any network call, so this only reads existing rows and performs no-op
// writes — it does not mutate the shared test database.
func TestRunPermifySync_NoopCheckerSucceeds(t *testing.T) {
	dbURL := requireDBURL(t)
	t.Setenv("SINAUTH_DB_URL", dbURL)
	t.Setenv("SINAUTH_ISSUER", "https://sinauth.test")
	t.Setenv("SINAUTH_SIGNING_KEY_PATH", filepath.Join(t.TempDir(), "sinauth.pem"))
	t.Setenv("SINAUTH_PERMIFY_URL", "")
	t.Setenv("SINAUTH_DEV_MODE", "")

	cmd := &cobra.Command{Use: "permify-sync"}
	if err := runPermifySync(cmd, nil); err != nil {
		t.Fatalf("runPermifySync: %v", err)
	}
}

// TestRunPermifySync_ConfigError proves a missing required config value
// aborts before any DB or Permify interaction.
func TestRunPermifySync_ConfigError(t *testing.T) {
	t.Setenv("SINAUTH_DB_URL", "postgres://ignored/ignored")
	t.Setenv("SINAUTH_ISSUER", "")
	t.Setenv("SINAUTH_SIGNING_KEY_PATH", "")
	t.Setenv("SINAUTH_DEV_MODE", "")

	cmd := &cobra.Command{Use: "permify-sync"}
	err := runPermifySync(cmd, nil)
	if err == nil {
		t.Fatal("runPermifySync: expected a config error, got nil")
	}
}
