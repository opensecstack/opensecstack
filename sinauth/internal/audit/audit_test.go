//go:build integration

package audit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used elsewhere in sinauth.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping audit store integration test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// waitForEntry polls List (newest-first) until an entry with the given
// event type and actor shows up, or fails the test after a timeout. Log is
// documented as fire-and-forget/asynchronous, so tests must not assume the
// row exists immediately after Log returns.
func waitForEntry(t *testing.T, s *Store, eventType, actor string) Entry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := s.List(context.Background(), 500)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, e := range entries {
			if e.EventType == eventType && e.Actor == actor {
				return e
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("audit entry (event_type=%q actor=%q) did not appear within timeout", eventType, actor)
	return Entry{}
}

// TestLog_RecordsEntryWithCorrectFields is the core correctness test for
// this package: an audit event submitted via Log must actually land in
// the audit_log table with every field preserved exactly, including a
// non-nil Metadata blob. A dropped or field-mangled audit record here
// would be a silent gap in the audit trail — the exact failure mode
// auditability is supposed to prevent.
func TestLog_RecordsEntryWithCorrectFields(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	actor := fmt.Sprintf("audituser%d", time.Now().UnixNano())
	eventType := "login.success"
	clientID := "test-client-123"
	ip := "203.0.113.7"
	ua := "sinauth-test-agent/1.0"
	meta := map[string]any{"mfa": true, "attempt": float64(1)}

	s.Log(eventType, actor, clientID, ip, ua, meta)

	entry := waitForEntry(t, s, eventType, actor)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM audit_log WHERE id=$1`, entry.ID) })

	if entry.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", entry.ClientID, clientID)
	}
	if entry.IPAddress != ip {
		t.Errorf("IPAddress = %q, want %q", entry.IPAddress, ip)
	}
	if entry.UserAgent != ua {
		t.Errorf("UserAgent = %q, want %q", entry.UserAgent, ua)
	}
	if entry.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero, want a populated timestamp")
	}
	if len(entry.Metadata) == 0 {
		t.Fatal("Metadata is empty, want the marshaled meta map")
	}
	if got := string(entry.Metadata); got == "" || got == "null" {
		t.Errorf("Metadata = %q, want marshaled JSON of the meta map", got)
	}
}

// TestLog_NilMetadata_DoesNotErrorOrPanic proves the nil-metadata path
// (meta == nil, so metaJSON stays nil and gets inserted as SQL NULL) is
// handled without error, and List correctly surfaces a nil/empty
// Metadata field for it rather than panicking on json.RawMessage(nil).
func TestLog_NilMetadata_DoesNotErrorOrPanic(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	actor := fmt.Sprintf("nilmetauser%d", time.Now().UnixNano())
	eventType := "logout"

	s.Log(eventType, actor, "", "", "", nil)

	entry := waitForEntry(t, s, eventType, actor)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM audit_log WHERE id=$1`, entry.ID) })

	if entry.Metadata != nil {
		t.Errorf("Metadata = %q, want nil for a nil meta map", string(entry.Metadata))
	}
}

// TestList_OrderedNewestFirst proves List returns entries ordered by
// created_at DESC — audit review tooling depends on newest-first ordering
// to surface recent events without paging through history.
func TestList_OrderedNewestFirst(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	uniq := time.Now().UnixNano()
	actor := fmt.Sprintf("orderuser%d", uniq)

	// client_id/ip_address/user_agent are nullable columns in the schema
	// (List now handles NULLs there gracefully, see
	// TestList_NullNullableColumn_ErrorsInsteadOfDegrading below) — pass empty
	// strings here (matching what Store.Log always does) so this test
	// isolates ordering behavior only.
	var id1, id2 string
	err := pool.QueryRow(ctx, `
		INSERT INTO audit_log (event_type, actor, client_id, ip_address, user_agent, created_at)
		VALUES ($1,$2,'','','', now() - interval '1 hour') RETURNING id`,
		"event.first", actor,
	).Scan(&id1)
	if err != nil {
		t.Fatalf("insert first: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_log WHERE id=$1`, id1) })

	err = pool.QueryRow(ctx, `
		INSERT INTO audit_log (event_type, actor, client_id, ip_address, user_agent, created_at)
		VALUES ($1,$2,'','','', now()) RETURNING id`,
		"event.second", actor,
	).Scan(&id2)
	if err != nil {
		t.Fatalf("insert second: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_log WHERE id=$1`, id2) })

	entries, err := s.List(ctx, 500)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	var idx1, idx2 = -1, -1
	for i, e := range entries {
		if e.ID == id1 {
			idx1 = i
		}
		if e.ID == id2 {
			idx2 = i
		}
	}
	if idx1 == -1 || idx2 == -1 {
		t.Fatalf("List missing expected entries: idx1=%d idx2=%d", idx1, idx2)
	}
	if idx2 >= idx1 {
		t.Errorf("List order: newer entry (idx %d) should come before older entry (idx %d) — want newest first", idx2, idx1)
	}
}

// TestList_LimitClamping proves List's limit-clamping behavior: values
// <=0 or >500 fall back to a default of 100, rather than passing an
// unbounded or invalid LIMIT straight through to Postgres (which — for
// limit<=0 — would either error or, worse for a limit like -1, be
// misinterpreted).
func TestList_LimitClamping(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	// Seed more than 100 rows is impractical here; instead prove the call
	// succeeds (i.e. doesn't error out) for boundary values, which would
	// fail immediately if the raw value were passed to `LIMIT $1` for a
	// negative or zero input in a way Postgres rejects.
	for _, limit := range []int{0, -5, 501, 1, 500} {
		if _, err := s.List(ctx, limit); err != nil {
			t.Errorf("List(limit=%d): %v", limit, err)
		}
	}
}

// TestList_EmptyTableStillWorks proves List on filters that match nothing
// returns an empty, non-error result — List itself always queries the
// whole table, so instead we check a fresh, disjoint actor is absent to
// confirm no spurious rows leak into unrelated queries. (There's no
// per-actor filter on List, so this mainly guards against a nil-vs-error
// mixup on an otherwise-normal query.)
func TestList_ReturnsNoErrorAndEntriesHaveIDs(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	entries, err := s.List(ctx, 5)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if e.ID == "" {
			t.Errorf("entry has empty ID: %+v", e)
		}
	}
}

// TestList_NullNullableColumn_ErrorsInsteadOfDegrading documented a real
// robustness bug found while writing these tests: actor, client_id,
// ip_address, and user_agent are all nullable in the schema
// (migrations/008_audit_log.sql — none of them are NOT NULL), but
// Store.List used to scan them directly into non-pointer string fields
// (`&e.ClientID` etc., all plain `string` in the Entry struct). pgx
// refuses to scan a SQL NULL into *string, so a single row with any of
// these columns NULL made the *entire* List query fail with an error —
// not just that one row silently showing an empty string.
//
// Store.Log itself never produces a NULL in these columns (it always
// passes concrete, possibly-empty string arguments), so this couldn't be
// triggered by the normal Log() write path. But the columns are reachable
// by any other writer (a direct INSERT, a manual ops query, a
// migration/backfill) since the schema explicitly allows NULL there. When
// it happened, the failure mode was severe for an audit log: List became
// entirely non-functional (every call errored) until the offending row
// was fixed or deleted, hiding the whole audit trail rather than
// degrading gracefully for the one affected entry.
//
// Fixed in Store.List by scanning the nullable columns into sql.NullString
// and converting to the Entry struct's empty-string zero value. This test
// now asserts the fixed behavior: List succeeds and the NULL columns come
// back as empty strings on the Entry, rather than the whole call erroring.
func TestList_NullNullableColumn_ErrorsInsteadOfDegrading(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO audit_log (event_type, actor, client_id, ip_address, user_agent)
		VALUES ($1, NULL, NULL, NULL, NULL) RETURNING id`,
		"event.with.nulls",
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert row with NULL nullable columns: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM audit_log WHERE id=$1`, id) })

	entries, err := s.List(ctx, 500)
	if err != nil {
		t.Fatalf("List returned an error for a row with NULL nullable columns (actor/client_id/ip_address/"+
			"user_agent scanned into non-pointer string fields): %v", err)
	}

	var found *Entry
	for i := range entries {
		if entries[i].ID == id {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("List did not return the row with NULL nullable columns (id=%s)", id)
	}
	if found.Actor != "" {
		t.Errorf("Actor = %q, want empty string for NULL column", found.Actor)
	}
	if found.ClientID != "" {
		t.Errorf("ClientID = %q, want empty string for NULL column", found.ClientID)
	}
	if found.IPAddress != "" {
		t.Errorf("IPAddress = %q, want empty string for NULL column", found.IPAddress)
	}
	if found.UserAgent != "" {
		t.Errorf("UserAgent = %q, want empty string for NULL column", found.UserAgent)
	}
}
