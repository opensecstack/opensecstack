//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/db"
)

// TestWORM_Integration_ChainVerification exercises the real WORM emit/verify
// HTTP handlers against a live Postgres database (DATABASE_URL). It appends a
// short sequence of genuine WORM entries through POST /api/v1/worm/emit —
// the same production code path used by the running service — confirms
// GET /api/v1/worm/verify reports the resulting chain intact, then tampers
// with a persisted entry directly in the database (simulating real
// corruption, bypassing the application layer entirely) and confirms verify
// now correctly reports a break. This is the integration-level counterpart
// to the pure-function unit tests in internal/db/worm_test.go, which cover
// TripleHash/chainHash in isolation but never touch a real database.
func TestWORM_Integration_ChainVerification(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping WORM integration test")
	}

	ctx := context.Background()
	database, err := db.New(ctx, dsn)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	defer database.Close()

	h := NewWORM(zerolog.Nop(), database)

	from := time.Now().UTC().Add(-time.Minute)

	// 1. Emit a few real WORM entries through the production HTTP handler.
	type emitResp struct {
		WORMEntryID string `json:"worm_entry_id"`
	}
	var ids []uuid.UUID
	for i := 0; i < 3; i++ {
		body, _ := json.Marshal(map[string]any{
			"source":     "integration-test",
			"event_type": "scan.created",
			"project_id": "worm-integration-test",
			"payload":    map[string]any{"seq": i},
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/worm/emit", bytes.NewBuffer(body))
		rw := httptest.NewRecorder()
		h.Emit(rw, req)
		if rw.Code != http.StatusOK {
			t.Fatalf("emit %d: expected 200, got %d: %s", i, rw.Code, rw.Body.String())
		}
		var resp emitResp
		if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
			t.Fatalf("emit %d: decode response: %v", i, err)
		}
		id, err := uuid.Parse(resp.WORMEntryID)
		if err != nil {
			t.Fatalf("emit %d: invalid worm_entry_id %q: %v", i, resp.WORMEntryID, err)
		}
		ids = append(ids, id)
	}

	to := time.Now().UTC().Add(time.Minute)

	// 2. Verify the chain is reported intact via the real verify endpoint.
	result := verifyChain(t, h, from, to)
	if !result.Valid {
		t.Fatalf("expected chain to be valid before tampering, got break at %q", result.BreakAt)
	}
	if result.EntriesVerified < 3 {
		t.Fatalf("expected at least 3 entries verified, got %d", result.EntriesVerified)
	}

	// 3. Tamper with a persisted entry directly in the database. worm_entries
	// carries append-only RULEs blocking UPDATE/DELETE (migrations/001_initial.sql),
	// so the rule must be disabled for this session to simulate real corruption —
	// e.g. a compromised superuser bypassing the application layer entirely,
	// which is exactly the scenario chain verification exists to catch.
	if _, err := database.Pool.Exec(ctx, `ALTER TABLE worm_entries DISABLE RULE worm_no_update`); err != nil {
		t.Fatalf("disable worm_no_update rule: %v", err)
	}
	defer func() {
		_, _ = database.Pool.Exec(ctx, `ALTER TABLE worm_entries ENABLE RULE worm_no_update`)
	}()

	tag, err := database.Pool.Exec(ctx,
		`UPDATE worm_entries SET payload = $1 WHERE id = $2`,
		[]byte(`{"tampered":true}`), ids[1],
	)
	if err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("expected to tamper exactly 1 row, affected %d", tag.RowsAffected())
	}

	if _, err := database.Pool.Exec(ctx, `ALTER TABLE worm_entries ENABLE RULE worm_no_update`); err != nil {
		t.Fatalf("re-enable worm_no_update rule: %v", err)
	}

	// 4. Verify now correctly reports the break.
	result2 := verifyChain(t, h, from, to)
	if result2.Valid {
		t.Fatal("expected chain verification to detect tampering, but it reported valid")
	}
	if result2.BreakAt == "" {
		t.Fatal("expected BreakAt to be populated after tampering")
	}
}

// TestImmutability_UpdateAndDeleteAreNoOps confirms the append-only guarantee
// documented in migrations/000001_initial.up.sql: worm_no_update and
// worm_no_delete are PostgreSQL RULEs of the form "DO INSTEAD NOTHING", so a
// direct UPDATE/DELETE against worm_entries — bypassing the application layer
// entirely, e.g. a compromised superuser — must silently affect zero rows and
// leave the persisted entry byte-for-byte unchanged, rather than erroring or
// (worse) succeeding.
func TestImmutability_UpdateAndDeleteAreNoOps(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping WORM immutability test")
	}

	ctx := context.Background()
	database, err := db.New(ctx, dsn)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	defer database.Close()

	h := NewWORM(zerolog.Nop(), database)

	body, _ := json.Marshal(map[string]any{
		"source":     "immutability-test",
		"event_type": "scan.created",
		"project_id": "worm-immutability-test",
		"payload":    map[string]any{"seq": 0},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/worm/emit", bytes.NewBuffer(body))
	rw := httptest.NewRecorder()
	h.Emit(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("emit: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	var emitResp struct {
		WORMEntryID string `json:"worm_entry_id"`
		ChainHash   string `json:"chain_hash"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &emitResp); err != nil {
		t.Fatalf("emit: decode response: %v", err)
	}
	id, err := uuid.Parse(emitResp.WORMEntryID)
	if err != nil {
		t.Fatalf("emit: invalid worm_entry_id %q: %v", emitResp.WORMEntryID, err)
	}

	// Attempt a direct UPDATE without disabling worm_no_update — this must be
	// rejected (turned into a no-op) by the RULE, not by application code.
	updateTag, err := database.Pool.Exec(ctx,
		`UPDATE worm_entries SET payload = $1 WHERE id = $2`,
		[]byte(`{"tampered":true}`), id,
	)
	if err != nil {
		t.Fatalf("UPDATE against worm_entries returned an error instead of a silent no-op: %v", err)
	}
	if updateTag.RowsAffected() != 0 {
		t.Fatalf("expected worm_no_update RULE to block the UPDATE (0 rows affected), got %d", updateTag.RowsAffected())
	}

	var chainHash string
	if err := database.Pool.QueryRow(ctx, `SELECT chain_hash FROM worm_entries WHERE id = $1`, id).Scan(&chainHash); err != nil {
		t.Fatalf("re-read entry after UPDATE attempt: %v", err)
	}
	if chainHash != emitResp.ChainHash {
		t.Fatalf("entry was mutated despite worm_no_update RULE: chain_hash changed from %q to %q", emitResp.ChainHash, chainHash)
	}

	// Attempt a direct DELETE without disabling worm_no_delete — same
	// expectation: silently blocked, row still present afterward.
	deleteTag, err := database.Pool.Exec(ctx, `DELETE FROM worm_entries WHERE id = $1`, id)
	if err != nil {
		t.Fatalf("DELETE against worm_entries returned an error instead of a silent no-op: %v", err)
	}
	if deleteTag.RowsAffected() != 0 {
		t.Fatalf("expected worm_no_delete RULE to block the DELETE (0 rows affected), got %d", deleteTag.RowsAffected())
	}

	var stillExists bool
	if err := database.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM worm_entries WHERE id = $1)`, id).Scan(&stillExists); err != nil {
		t.Fatalf("re-check entry existence after DELETE attempt: %v", err)
	}
	if !stillExists {
		t.Fatal("entry was deleted despite worm_no_delete RULE")
	}
}

func verifyChain(t *testing.T, h *WORM, from, to time.Time) db.VerifyResult {
	t.Helper()
	url := fmt.Sprintf("/api/v1/worm/verify?from=%s&to=%s", from.Format(time.RFC3339), to.Format(time.RFC3339))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	rw := httptest.NewRecorder()
	h.Verify(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	var result db.VerifyResult
	if err := json.Unmarshal(rw.Body.Bytes(), &result); err != nil {
		t.Fatalf("verify: decode response: %v", err)
	}
	return result
}
