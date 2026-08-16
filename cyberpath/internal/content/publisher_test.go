package content

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── pure-function unit tests (no DB required) ──────────────────────────

func TestParseVersionMajor(t *testing.T) {
	cases := map[string]int{
		"":       1,
		"1.4.0":  1,
		"2":      2,
		"10.0.0": 10,
		"0.9.0":  1,
		"abc":    1,
		"3.x.y":  3,
		"-1.0.0": 1,
	}
	for in, want := range cases {
		if got := parseVersionMajor(in); got != want {
			t.Errorf("parseVersionMajor(%q) = %d want %d", in, got, want)
		}
	}
}

func TestNonEmpty(t *testing.T) {
	if got := nonEmpty("", "", "c"); got != "c" {
		t.Errorf("nonEmpty = %q want c", got)
	}
	if got := nonEmpty("a", "b"); got != "a" {
		t.Errorf("nonEmpty = %q want a", got)
	}
	if got := nonEmpty("", ""); got != "" {
		t.Errorf("nonEmpty = %q want empty", got)
	}
	if got := nonEmpty(); got != "" {
		t.Errorf("nonEmpty() = %q want empty", got)
	}
}

func TestMaxInt(t *testing.T) {
	if maxInt(1, 2) != 2 {
		t.Error("maxInt(1,2) != 2")
	}
	if maxInt(5, 2) != 5 {
		t.Error("maxInt(5,2) != 5")
	}
	if maxInt(3, 3) != 3 {
		t.Error("maxInt(3,3) != 3")
	}
}

func TestNullableUUID(t *testing.T) {
	if nullableUUID(uuid.Nil) != nil {
		t.Error("nullableUUID(Nil) should be nil")
	}
	id := uuid.New()
	got := nullableUUID(id)
	if got != id {
		t.Errorf("nullableUUID(id) = %v want %v", got, id)
	}
}

func TestSummariseErrors(t *testing.T) {
	if got := summariseErrors(nil); got != "no errors" {
		t.Errorf("summariseErrors(nil) = %q want %q", got, "no errors")
	}
	warningsOnly := []ValidationError{{Code: "x", Severity: "warning", Message: "m", Path: "p"}}
	if got := summariseErrors(warningsOnly); got != "no errors" {
		t.Errorf("summariseErrors(warnings only) = %q want no errors", got)
	}
	diags := []ValidationError{
		{Code: "a", Severity: "error", Path: "p1", Message: "bad a"},
		{Code: "b", Severity: "warning", Path: "p2", Message: "meh"},
		{Code: "c", Severity: "error", Path: "p3", Message: "bad c"},
	}
	got := summariseErrors(diags)
	if !strings.Contains(got, "bad a") || !strings.Contains(got, "bad c") {
		t.Errorf("summariseErrors missing entries: %q", got)
	}
	if strings.Contains(got, "meh") {
		t.Errorf("summariseErrors should not include warnings: %q", got)
	}
}

func TestNormaliseLabRuntime(t *testing.T) {
	cases := map[string]string{
		"docker":       "docker",
		"wasmtime":     "wasmtime",
		"wasm-shell":   "wasmtime",
		"wasm-python":  "wasmtime",
		"wasm-kubectl": "wasmtime",
		"vm":           "vm", // unknown passthrough
		"":             "",
	}
	for in, want := range cases {
		if got := normaliseLabRuntime(in); got != want {
			t.Errorf("normaliseLabRuntime(%q) = %q want %q", in, got, want)
		}
	}
}

// ── Publish guard-clause tests (no DB touched) ─────────────────────────

func TestPublish_NilTrack(t *testing.T) {
	p := &Publisher{Pool: &pgxpool.Pool{}}
	err := p.Publish(context.Background(), nil, uuid.New())
	if err == nil || !strings.Contains(err.Error(), "track is nil") {
		t.Errorf("expected 'track is nil' error, got %v", err)
	}
}

func TestPublish_NilPool(t *testing.T) {
	p := &Publisher{}
	tr := minimalValidTrack()
	err := p.Publish(context.Background(), tr, uuid.New())
	if err == nil || !strings.Contains(err.Error(), "pool is nil") {
		t.Errorf("expected 'pool is nil' error, got %v", err)
	}
}

// TestPublish_ValidationFailure exercises the Strict validation-refusal
// path. Validation happens before any DB connection is opened, so an
// unconnected (lazily-dialed) pgxpool.Pool is safe to use here — pgxpool.New
// only parses the DSN, it does not dial.
func TestPublish_ValidationFailure(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://nouser@127.0.0.1:1/nodb")
	if err != nil {
		t.Fatalf("pgxpool.New (lazy, no dial expected): %v", err)
	}
	defer pool.Close()

	p := &Publisher{Pool: pool, Strict: true}
	tr := minimalValidTrack()
	tr.TitleSQ = "" // triggers track.missing_title_sq (error severity)
	err = p.Publish(context.Background(), tr, uuid.New())
	if err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("expected validation failure error, got %v", err)
	}
}

func TestPublish_NonStrictSkipsValidationButStillNeedsDB(t *testing.T) {
	// Non-strict mode skips the validation gate, so Publish proceeds to
	// BeginTx. Against an address nothing listens on, BeginTx/dial fails —
	// this exercises the "begin tx" error-wrapping branch without a live DB.
	pool, err := pgxpool.New(context.Background(), "postgres://nouser@127.0.0.1:1/nodb")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	p := &Publisher{Pool: pool, Strict: false}
	tr := minimalValidTrack()
	tr.TitleSQ = "" // would fail validation, but Strict=false ignores it
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = p.Publish(ctx, tr, uuid.New())
	if err == nil {
		t.Fatal("expected error dialing unreachable DB")
	}
}

func TestPublishAll_LoadError(t *testing.T) {
	p := &Publisher{Pool: &pgxpool.Pool{}}
	_, err := p.PublishAll(context.Background(), filepath.Join("testdata", "does-not-exist-dir"), uuid.New())
	if err == nil {
		t.Fatal("expected error for missing dir")
	}
}

// ── DB-backed integration tests ─────────────────────────────────────────
//
// These run against the shared cyberpath_test Postgres instance. They are
// intentionally NOT gated behind a build tag so `go test ./...` exercises
// the real upsert/version-insert SQL paths; if the DB is unreachable the
// tests skip cleanly so the suite still passes in environments without it.

const defaultTestDBURL = "postgres://apiguard@localhost:5434/cyberpath_test?sslmode=disable"

func testDBURL() string {
	if v := os.Getenv("CYBERPATH_TEST_DB_URL"); v != "" {
		return v
	}
	return defaultTestDBURL
}

func connectTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, testDBURL())
	if err != nil {
		t.Skipf("content: cannot construct test DB pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("content: test DB not reachable: %v", err)
	}
	return pool
}

// loadUniqueSampleTrack loads testdata/sample-track and rewrites its
// track id and lab id to unique, disposable values so this test never
// collides with itself, other packages, or a concurrent run against the
// shared database.
func loadUniqueSampleTrack(t *testing.T) *TrackYAML {
	t.Helper()
	root, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	tr, err := LoadTrack(root, "sample-track")
	if err != nil {
		t.Fatalf("LoadTrack: %v", err)
	}
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	tr.ID = "content-test-" + suffix
	for i := range tr.Modules {
		if tr.Modules[i].Lab != nil && tr.Modules[i].Lab.Lab != nil {
			tr.Modules[i].Lab.Lab.ID = "content-test-lab-" + suffix
			tr.Modules[i].Lab.ID = tr.Modules[i].Lab.Lab.ID
		}
	}
	return tr
}

// cleanupPublishedTrack removes every row this test may have written,
// respecting FK order (lab_definitions is ON DELETE RESTRICT against
// tracks, everything else cascades).
func cleanupPublishedTrack(pool *pgxpool.Pool, tr *TrackYAML) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := range tr.Modules {
		if tr.Modules[i].Lab != nil && tr.Modules[i].Lab.Lab != nil {
			_, _ = pool.Exec(ctx, `DELETE FROM lab_definitions WHERE id = $1`, tr.Modules[i].Lab.Lab.ID)
			_, _ = pool.Exec(ctx, `DELETE FROM content_versions WHERE entity_type = 'lab' AND entity_id = $1`, tr.Modules[i].Lab.Lab.ID)
		}
		if tr.Modules[i].Quiz != nil {
			_, _ = pool.Exec(ctx, `DELETE FROM content_versions WHERE entity_type = 'quiz' AND entity_id = $1`, tr.Modules[i].Quiz.ID)
		}
		for _, l := range tr.Modules[i].Lessons {
			_, _ = pool.Exec(ctx, `DELETE FROM content_versions WHERE entity_type = 'lesson' AND entity_id = $1`, l.ID)
		}
		_, _ = pool.Exec(ctx, `DELETE FROM content_versions WHERE entity_type = 'module' AND entity_id = $1`, tr.Modules[i].ID)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM content_versions WHERE entity_type = 'track' AND entity_id = $1`, tr.ID)
	_, _ = pool.Exec(ctx, `DELETE FROM tracks WHERE slug = $1`, tr.ID)
}

type fakeAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (f *fakeAudit) Log(_ context.Context, e AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

type fakeOutbox struct {
	mu     sync.Mutex
	events []OutboxEvent
}

func (f *fakeOutbox) Enqueue(_ context.Context, e OutboxEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func TestPublish_Success(t *testing.T) {
	pool := connectTestDB(t)
	defer pool.Close()

	tr := loadUniqueSampleTrack(t)
	defer cleanupPublishedTrack(pool, tr)

	audit := &fakeAudit{}
	outbox := &fakeOutbox{}
	p := NewPublisher(pool, audit, outbox)

	byUser := uuid.Nil // system publish; publisher must tolerate a NULL actor
	if err := p.Publish(context.Background(), tr, byUser); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if tr.ContentHash == "" {
		t.Error("ContentHash not populated after publish")
	}

	var slug string
	if err := pool.QueryRow(context.Background(), `SELECT slug FROM tracks WHERE slug = $1`, tr.ID).Scan(&slug); err != nil {
		t.Fatalf("track row not found: %v", err)
	}

	var moduleCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM modules m JOIN tracks t ON t.id = m.track_id WHERE t.slug = $1`, tr.ID).Scan(&moduleCount); err != nil {
		t.Fatalf("count modules: %v", err)
	}
	if moduleCount != len(tr.Modules) {
		t.Errorf("modules persisted = %d want %d", moduleCount, len(tr.Modules))
	}

	var lessonCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM lessons l
		JOIN modules m ON m.id = l.module_id
		JOIN tracks t ON t.id = m.track_id
		WHERE t.slug = $1`, tr.ID).Scan(&lessonCount); err != nil {
		t.Fatalf("count lessons: %v", err)
	}
	if lessonCount == 0 {
		t.Error("expected lessons to be persisted")
	}

	var quizCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM quizzes q JOIN tracks t ON t.id = q.track_id WHERE t.slug = $1`, tr.ID).Scan(&quizCount); err != nil {
		t.Fatalf("count quizzes: %v", err)
	}
	if quizCount != 1 {
		t.Errorf("quizzes persisted = %d want 1", quizCount)
	}

	var labCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM lab_definitions WHERE id = $1`, tr.Modules[0].Lab.Lab.ID).Scan(&labCount); err != nil {
		t.Fatalf("count lab_definitions: %v", err)
	}
	if labCount != 1 {
		t.Errorf("lab_definitions persisted = %d want 1", labCount)
	}

	// Re-publish an unchanged track: content_versions rows must not
	// duplicate (ON CONFLICT DO NOTHING on entity_type/entity_id/version).
	if err := p.Publish(context.Background(), tr, byUser); err != nil {
		t.Fatalf("re-publish: %v", err)
	}
	var versionRows int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM content_versions WHERE entity_type = 'track' AND entity_id = $1`, tr.ID).Scan(&versionRows); err != nil {
		t.Fatalf("count content_versions: %v", err)
	}
	if versionRows != 1 {
		t.Errorf("content_versions rows for track = %d want 1 (idempotent re-publish)", versionRows)
	}

	audit.mu.Lock()
	gotAuditEvents := len(audit.events)
	audit.mu.Unlock()
	if gotAuditEvents == 0 {
		t.Error("expected at least one audit event")
	}

	outbox.mu.Lock()
	gotOutboxEvents := len(outbox.events)
	outbox.mu.Unlock()
	if gotOutboxEvents == 0 {
		t.Error("expected at least one outbox event")
	}
}

func TestPublish_VersionBumpCreatesNewContentVersionRow(t *testing.T) {
	pool := connectTestDB(t)
	defer pool.Close()

	tr := loadUniqueSampleTrack(t)
	defer cleanupPublishedTrack(pool, tr)

	p := NewPublisher(pool, nil, nil)
	if err := p.Publish(context.Background(), tr, uuid.Nil); err != nil {
		t.Fatalf("Publish v1: %v", err)
	}

	tr.Version = "2.0.0"
	tr.TitleEN = "Modified for v2"
	if err := p.Publish(context.Background(), tr, uuid.Nil); err != nil {
		t.Fatalf("Publish v2: %v", err)
	}

	var rows int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM content_versions WHERE entity_type = 'track' AND entity_id = $1`, tr.ID).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 2 {
		t.Errorf("content_versions rows after version bump = %d want 2", rows)
	}
}

func TestPublishAll_Success(t *testing.T) {
	pool := connectTestDB(t)
	defer pool.Close()

	root, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	// PublishAll loads directly from disk, so it publishes the fixed
	// "sample-track" id; clean it up by that known slug afterwards.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = pool.Exec(ctx, `DELETE FROM lab_definitions WHERE id = 'sample-lab'`)
		_, _ = pool.Exec(ctx, `DELETE FROM content_versions WHERE entity_id = 'sample-track' OR entity_id = 'sample-lab' OR entity_type IN ('module','lesson','quiz')`)
		_, _ = pool.Exec(ctx, `DELETE FROM tracks WHERE slug = 'sample-track'`)
	}()

	p := NewPublisher(pool, nil, nil)
	count, err := p.PublishAll(context.Background(), root, uuid.Nil)
	if err != nil {
		t.Fatalf("PublishAll: %v", err)
	}
	if count != 1 {
		t.Errorf("PublishAll count = %d want 1", count)
	}
}
