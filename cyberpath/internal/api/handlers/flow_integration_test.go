//go:build integration

// Integration test — full enrollment-to-certificate flow.
//
// Covers: enroll (seed) → lesson complete → track completion detected →
// auto-issue cert (Ed25519-signed) → CITADEL outbox events persisted.
//
// Requires a fully-migrated Postgres instance pointed at by
// CYBERPATH_TEST_DB_URL; skipped otherwise.
//
// Run with:
//
//	go test -tags integration -p 1 -count=1 ./internal/api/handlers/
package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/cyberpath/internal/api/handlers"
	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/cert"
	"github.com/opensecstack/cyberpath/internal/db"
	"github.com/opensecstack/cyberpath/internal/wireup"
)

// TestFlow_EnrollCompleteIssueCITADEL exercises the entire happy path:
//
//  1. Seed: tenant → user → track → module → lesson (single lesson track)
//  2. POST /lessons/{id}/complete  (user claim injected via auth.WithClaims)
//  3. Assert lesson completion row created
//  4. Assert track completion row created (last lesson triggers it)
//  5. Assert certification issued and Ed25519 signature present
//  6. Assert ≥2 CITADEL outbox entries (lesson + track-level events)
//  7. Assert track-level event carries certification_level = "track-cert"
func TestFlow_EnrollCompleteIssueCITADEL(t *testing.T) {
	pool := openTestPool(t)

	// ── Seed fixtures ──────────────────────────────────────────────────
	tenantID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO tenants (id, slug, name) VALUES ($1,$2,$3)`,
		tenantID, "t-"+tenantID.String()[:8], "flow-test-tenant")

	userID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO users (id, tenant_id, email, role_id) VALUES ($1,$2,$3,'learner')`,
		userID, tenantID, userID.String()[:8]+"@flow.test")

	trackID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO tracks (id, slug, title, published) VALUES ($1,$2,$3,true)`,
		trackID, "flow-track-"+trackID.String()[:8], "Flow Test Track")

	moduleID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO modules (id, track_id, slug, title) VALUES ($1,$2,$3,$4)`,
		moduleID, trackID, "flow-mod-"+moduleID.String()[:8], "Flow Module")

	lessonID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO lessons (id, module_id, slug, title) VALUES ($1,$2,$3,$4)`,
		lessonID, moduleID, "flow-lesson-"+lessonID.String()[:8], "Flow Lesson")

	t.Cleanup(func() {
		ctx := context.Background()
		// outbox has no cascading FK — clean by subject
		_, _ = pool.Exec(ctx,
			`DELETE FROM outbox WHERE payload::jsonb->>'subject' = $1
			   OR payload::jsonb->'cyberpath'->>'user_id' = $2`,
			"user:"+userID.String(), userID.String())
		// cascade: tracks → modules → lessons, certifications
		_, _ = pool.Exec(ctx, `DELETE FROM tracks WHERE id = $1`, trackID)
		// cascade: tenants → users → completions, progress
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	// ── Wire stores and handlers ───────────────────────────────────────
	lessonStore := db.NewLessonStore(pool)
	progressStore := db.NewProgressStore(pool)
	completionStore := db.NewCompletionStore(pool)
	outboxStore := db.NewOutboxStore(pool)
	trackStore := db.NewTrackStore(pool)
	certStore := db.NewCertificationStore(pool)

	signer, err := cert.NewSigner("")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// CertificationsHandler must be wired before LessonsHandler (CertIssuer dep).
	certHandler := handlers.NewCertificationsHandler(handlers.CertHandlerDeps{
		Certs:       certStore,
		Tracks:      trackStore,
		Completions: completionStore,
		Signer:      signer,
		Outbox:      wireup.CertOutbox(outboxStore),
	})

	lessonsHandler := handlers.NewLessonsHandler(handlers.LessonsDeps{
		Lessons:         lessonStore,
		Progress:        progressStore,
		Completions:     completionStore,
		Outbox:          outboxStore,
		Tracks:          trackStore,
		TrackCompletion: completionStore,
		CertIssuer:      certHandler,
		CitadelProject:  "test-project",
	})

	// ── Exercise POST /lessons/{id}/complete ───────────────────────────
	body, _ := json.Marshal(map[string]int{"time_spent_seconds": 60})
	req := httptest.NewRequest(http.MethodPost,
		"/lessons/"+lessonID.String()+"/complete",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Inject chi route param + JWT claims without running full middleware.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", lessonID.String())
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = auth.WithClaims(ctx, &auth.Claims{Sub: userID.String(), Role: "learner"})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	lessonsHandler.Complete(rec, req)

	// ── Assertions ─────────────────────────────────────────────────────
	if rec.Code != http.StatusOK {
		t.Fatalf("Complete: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Lesson completion record
	assertCount(t, pool, queryCtx, 1,
		`SELECT COUNT(*) FROM completions WHERE user_id=$1 AND kind='lesson' AND target_id=$2`,
		userID, lessonID)

	// 2. Track completion record (all lessons in track finished)
	assertCount(t, pool, queryCtx, 1,
		`SELECT COUNT(*) FROM completions WHERE user_id=$1 AND kind='track' AND target_id=$2`,
		userID, trackID)

	// 3. Certification issued
	assertCount(t, pool, queryCtx, 1,
		`SELECT COUNT(*) FROM certifications WHERE user_id=$1 AND track_id=$2 AND revoked=false`,
		userID, trackID)

	// 4. Certificate signature is non-empty and correct length (Ed25519 hex = 128 chars)
	var sig string
	err = pool.QueryRow(queryCtx,
		`SELECT COALESCE(signature,'') FROM certifications WHERE user_id=$1 AND track_id=$2 AND revoked=false`,
		userID, trackID).Scan(&sig)
	if err != nil {
		t.Fatalf("cert signature query: %v", err)
	}
	if len(sig) != 128 {
		t.Fatalf("cert signature: expected 128 hex chars (Ed25519), got %d: %q", len(sig), sig)
	}

	// 5. At least 2 CITADEL outbox entries (lesson + track events)
	var outboxTotal int
	err = pool.QueryRow(queryCtx,
		`SELECT COUNT(*) FROM outbox WHERE event_type='cyberpath.completion' AND destination='citadel'`).Scan(&outboxTotal)
	if err != nil {
		t.Fatalf("outbox count query: %v", err)
	}
	if outboxTotal < 2 {
		t.Fatalf("outbox: expected ≥2 cyberpath.completion entries, got %d", outboxTotal)
	}

	// 6. Track-level event has certification_level = "track-cert"
	assertCount(t, pool, queryCtx, 1,
		`SELECT COUNT(*) FROM outbox
		 WHERE event_type='cyberpath.completion'
		   AND destination='citadel'
		   AND payload::jsonb->'cyberpath'->>'certification_level' = 'track-cert'`)

	// 7. Certification-issued CITADEL event enqueued
	assertCount(t, pool, queryCtx, 1,
		`SELECT COUNT(*) FROM outbox
		 WHERE event_type='cyberpath.certification.issued'
		   AND destination='citadel'
		   AND payload::jsonb->'cyberpath'->>'user_id' = $1`,
		userID.String())
}

// TestFlow_AutoIssue_Idempotency verifies that completing the same lesson
// twice (e.g. page reload) does not produce a second certification.
func TestFlow_AutoIssue_Idempotency(t *testing.T) {
	pool := openTestPool(t)

	tenantID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO tenants (id, slug, name) VALUES ($1,$2,$3)`,
		tenantID, "idem-"+tenantID.String()[:8], "idempotency-tenant")

	userID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO users (id, tenant_id, email, role_id) VALUES ($1,$2,$3,'learner')`,
		userID, tenantID, userID.String()[:8]+"@idem.test")

	trackID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO tracks (id, slug, title, published) VALUES ($1,$2,$3,true)`,
		trackID, "idem-track-"+trackID.String()[:8], "Idempotency Track")

	moduleID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO modules (id, track_id, slug, title) VALUES ($1,$2,$3,$4)`,
		moduleID, trackID, "idem-mod", "Idem Module")

	lessonID := uuid.New()
	execOrFatal(t, pool, `INSERT INTO lessons (id, module_id, slug, title) VALUES ($1,$2,$3,$4)`,
		lessonID, moduleID, "idem-lesson", "Idem Lesson")

	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx,
			`DELETE FROM outbox WHERE payload::jsonb->>'subject' = $1
			   OR payload::jsonb->'cyberpath'->>'user_id' = $2`,
			"user:"+userID.String(), userID.String())
		_, _ = pool.Exec(ctx, `DELETE FROM tracks WHERE id = $1`, trackID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	signer, _ := cert.NewSigner("")
	outboxStore := db.NewOutboxStore(pool)
	completionStore := db.NewCompletionStore(pool)
	trackStore := db.NewTrackStore(pool)

	certHandler := handlers.NewCertificationsHandler(handlers.CertHandlerDeps{
		Certs:       db.NewCertificationStore(pool),
		Tracks:      trackStore,
		Completions: completionStore,
		Signer:      signer,
		Outbox:      wireup.CertOutbox(outboxStore),
	})
	lessonsHandler := handlers.NewLessonsHandler(handlers.LessonsDeps{
		Lessons:         db.NewLessonStore(pool),
		Progress:        db.NewProgressStore(pool),
		Completions:     completionStore,
		Outbox:          outboxStore,
		Tracks:          trackStore,
		TrackCompletion: completionStore,
		CertIssuer:      certHandler,
	})

	callComplete := func() int {
		body, _ := json.Marshal(map[string]int{"time_spent_seconds": 30})
		req := httptest.NewRequest(http.MethodPost,
			"/lessons/"+lessonID.String()+"/complete",
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", lessonID.String())
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = auth.WithClaims(ctx, &auth.Claims{Sub: userID.String(), Role: "learner"})
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		lessonsHandler.Complete(rec, req)
		return rec.Code
	}

	if code := callComplete(); code != http.StatusOK {
		t.Fatalf("first complete: expected 200, got %d", code)
	}
	if code := callComplete(); code != http.StatusOK {
		t.Fatalf("second complete: expected 200, got %d", code)
	}

	qctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Must have exactly one certification despite two complete calls.
	assertCount(t, pool, qctx, 1,
		`SELECT COUNT(*) FROM certifications WHERE user_id=$1 AND track_id=$2 AND revoked=false`,
		userID, trackID)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func openTestPool(t *testing.T) *pgxpool.Pool {
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

func execOrFatal(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("seed exec %q: %v", sql, err)
	}
}

func assertCount(t *testing.T, pool *pgxpool.Pool, ctx context.Context, want int, sql string, args ...any) {
	t.Helper()
	var got int
	if err := pool.QueryRow(ctx, sql, args...).Scan(&got); err != nil {
		t.Fatalf("count query %q: %v", sql, err)
	}
	if got != want {
		t.Fatalf("count query: expected %d, got %d\nSQL: %s", want, got, sql)
	}
}
