package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/opencsirt/internal/db"
)

// unreachablePool returns a pgx pool configured against a syntactically
// valid but unreachable address (port 1 on loopback). pgxpool.NewWithConfig
// never dials eagerly, so construction always succeeds; the first real
// query then fails fast with a connection-refused error. This lets us
// exercise Snapshot.Get's error-handling branches for real, without a live
// database and without mocking the store types (which wrap *pgxpool.Pool
// concretely and have no interface seam).
func unreachablePool(t *testing.T) *db.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 1)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestSnapshotGet_DBUnreachable_DegradesGracefully proves the snapshot
// endpoint never fails the request just because a downstream store query
// errors: every store call is individually guarded with `if ..., err ==
// nil`, so an unreachable database must still yield 200 with the
// corresponding fields left at their zero value.
func TestSnapshotGet_DBUnreachable_DegradesGracefully(t *testing.T) {
	pool := unreachablePool(t)
	h := &Snapshot{
		Incidents:  db.NewIncidentStore(pool),
		Advisories: db.NewAdvisoryStore(pool),
		Outbox:     db.NewOutboxStore(pool),
		IOCIngest:  db.NewIOCIngestStore(pool),
		NodeName:   "test-node",
		Version:    "1.2.3",
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/snapshot", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 even when the DB is unreachable; body=%s", w.Code, w.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["node"] != "test-node" {
		t.Errorf("node = %v, want test-node", body["node"])
	}
	if body["version"] != "1.2.3" {
		t.Errorf("version = %v, want 1.2.3", body["version"])
	}
	// incidents_by_status / advisories_by_state have no `omitempty` tag, so
	// the nil map (assignment skipped because CountByStatus/State errored)
	// serializes as JSON null rather than {}. Confirm it stays null instead
	// of silently becoming a wrong-but-present value.
	if v, ok := body["incidents_by_status"]; !ok || v != nil {
		t.Errorf("incidents_by_status = %v, want null when the query errors", v)
	}
	if v, ok := body["advisories_by_state"]; !ok || v != nil {
		t.Errorf("advisories_by_state = %v, want null when the query errors", v)
	}
	if body["outbox_pending"] != float64(0) {
		t.Errorf("outbox_pending = %v, want 0 (zero value on error)", body["outbox_pending"])
	}
	if body["outbox_failed"] != float64(0) {
		t.Errorf("outbox_failed = %v, want 0 (zero value on error)", body["outbox_failed"])
	}
	if body["citadel_queue_depth"] != float64(0) {
		t.Errorf("citadel_queue_depth = %v, want 0 when QueueDepth is nil", body["citadel_queue_depth"])
	}
	if _, ok := body["iocs_last_ingested_at"]; ok {
		t.Errorf("iocs_last_ingested_at should be omitted when the query errors, got %v", body["iocs_last_ingested_at"])
	}
	if body["advisory_service_up"] != false {
		t.Errorf("advisory_service_up = %v, want false when HealthCheck is nil", body["advisory_service_up"])
	}
}

// TestSnapshotGet_UsesQueueDepthAndHealthCheckCallbacks proves the two
// injected callbacks (QueueDepth, HealthCheck) are actually invoked and
// their results wired into the response — these have no DB dependency and
// were previously entirely uncovered.
func TestSnapshotGet_UsesQueueDepthAndHealthCheckCallbacks(t *testing.T) {
	pool := unreachablePool(t)
	var healthCheckCalled bool
	h := &Snapshot{
		Incidents:  db.NewIncidentStore(pool),
		Advisories: db.NewAdvisoryStore(pool),
		Outbox:     db.NewOutboxStore(pool),
		IOCIngest:  db.NewIOCIngestStore(pool),
		QueueDepth: func() int { return 42 },
		HealthCheck: func(ctx context.Context) bool {
			healthCheckCalled = true
			// The handler must give the callback a bounded context, not the
			// unbounded request context — verify a deadline is actually set.
			if _, ok := ctx.Deadline(); !ok {
				t.Errorf("HealthCheck context has no deadline")
			}
			return true
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/snapshot", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !healthCheckCalled {
		t.Fatal("HealthCheck callback was never invoked")
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["citadel_queue_depth"] != float64(42) {
		t.Errorf("citadel_queue_depth = %v, want 42", body["citadel_queue_depth"])
	}
	if body["advisory_service_up"] != true {
		t.Errorf("advisory_service_up = %v, want true", body["advisory_service_up"])
	}
}

// TestSnapshotGet_SnapshotAtIsCurrent guards against a regression where
// SnapshotAt is computed once at struct-literal time rather than per
// request.
func TestSnapshotGet_SnapshotAtIsCurrent(t *testing.T) {
	pool := unreachablePool(t)
	h := &Snapshot{
		Incidents:  db.NewIncidentStore(pool),
		Advisories: db.NewAdvisoryStore(pool),
		Outbox:     db.NewOutboxStore(pool),
		IOCIngest:  db.NewIOCIngestStore(pool),
	}
	before := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/snapshot", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)
	after := time.Now().UTC()

	var body struct {
		SnapshotAt time.Time `json:"snapshot_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.SnapshotAt.Before(before) || body.SnapshotAt.After(after) {
		t.Errorf("snapshot_at = %v, want between %v and %v", body.SnapshotAt, before, after)
	}
}
