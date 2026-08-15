//go:build integration

// Integration tests for CertificationStore against the `certifications`
// table. Requires CYBERPATH_TEST_DB_URL; skipped otherwise.
package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// certFixture seeds a tenant, user and track.
func certFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (userID, trackID uuid.UUID) {
	t.Helper()

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "crt-"+tenantID.String()[:8], "cert-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	userID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		userID, tenantID, userID.String()+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	trackID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tracks (id, slug, title) VALUES ($1, $2, $3)`,
		trackID, "crt-track-"+trackID.String()[:8], "Cert Test Track"); err != nil {
		t.Fatalf("seed track: %v", err)
	}

	return userID, trackID
}

func TestCertificationStore_IssueListGetRevoke(t *testing.T) {
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
	defer pool.Close()

	userID, trackID := certFixture(t, ctx, pool)
	store := NewCertificationStore(pool)

	serial := "CERT-" + uuid.New().String()[:8]
	issued, err := store.Issue(ctx, userID, trackID, serial, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.Serial != serial {
		t.Fatalf("Issue: serial = %q, want %q", issued.Serial, serial)
	}
	if issued.Revoked {
		t.Fatal("Issue: new certification should not be revoked")
	}
	if issued.ExpiresAt != nil {
		t.Fatalf("Issue: ExpiresAt = %v, want nil", issued.ExpiresAt)
	}

	// ListByUser (includeExpired=false) should show the fresh, non-revoked cert.
	list, err := store.ListByUser(ctx, userID, false)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != issued.ID {
		t.Fatalf("ListByUser: expected our cert, got %d rows", len(list))
	}

	// GetByUserTrack returns the same row.
	got, err := store.GetByUserTrack(ctx, userID, trackID)
	if err != nil {
		t.Fatalf("GetByUserTrack: %v", err)
	}
	if got.ID != issued.ID {
		t.Fatalf("GetByUserTrack: id = %v, want %v", got.ID, issued.ID)
	}

	// SetSignature.
	if err := store.SetSignature(ctx, issued.ID, "sig-abc", "/pdf/path.pdf"); err != nil {
		t.Fatalf("SetSignature: %v", err)
	}
	afterSig, err := store.GetByUserTrack(ctx, userID, trackID)
	if err != nil {
		t.Fatalf("GetByUserTrack after SetSignature: %v", err)
	}
	if afterSig.Signature != "sig-abc" || afterSig.PDFPath != "/pdf/path.pdf" {
		t.Fatalf("SetSignature: unexpected row after update: %+v", afterSig)
	}

	// Revoke.
	if err := store.Revoke(ctx, issued.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Now GetByUserTrack (which filters revoked=false) should return no rows.
	_, err = store.GetByUserTrack(ctx, userID, trackID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetByUserTrack after revoke: err = %v, want pgx.ErrNoRows", err)
	}

	// ListByUser with includeExpired=false must now exclude the revoked cert.
	listAfterRevoke, err := store.ListByUser(ctx, userID, false)
	if err != nil {
		t.Fatalf("ListByUser after revoke: %v", err)
	}
	if len(listAfterRevoke) != 0 {
		t.Fatalf("ListByUser after revoke: got %d rows, want 0", len(listAfterRevoke))
	}

	// ListByUser with includeExpired=true still shows it.
	listIncludeExpired, err := store.ListByUser(ctx, userID, true)
	if err != nil {
		t.Fatalf("ListByUser(includeExpired): %v", err)
	}
	if len(listIncludeExpired) != 1 {
		t.Fatalf("ListByUser(includeExpired): got %d rows, want 1", len(listIncludeExpired))
	}
}

func TestCertificationStore_Issue_DuplicateSerial(t *testing.T) {
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
	defer pool.Close()

	userID, trackID := certFixture(t, ctx, pool)
	store := NewCertificationStore(pool)

	serial := "DUP-" + uuid.New().String()[:8]
	if _, err := store.Issue(ctx, userID, trackID, serial, nil); err != nil {
		t.Fatalf("Issue (first): %v", err)
	}

	if _, err := store.Issue(ctx, userID, trackID, serial, nil); err == nil {
		t.Fatal("Issue (duplicate serial): expected unique constraint violation, got nil")
	}
}

func TestCertificationStore_ExpiresAt(t *testing.T) {
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
	defer pool.Close()

	userID, trackID := certFixture(t, ctx, pool)
	store := NewCertificationStore(pool)

	past := time.Now().Add(-24 * time.Hour)
	serial := "EXP-" + uuid.New().String()[:8]
	issued, err := store.Issue(ctx, userID, trackID, serial, &past)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.ExpiresAt == nil {
		t.Fatal("Issue: ExpiresAt not populated")
	}

	// includeExpired=false must filter out the already-expired cert.
	list, err := store.ListByUser(ctx, userID, false)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListByUser: expected expired cert to be filtered, got %d rows", len(list))
	}
}

func TestCertificationStore_Revoke_NotFound(t *testing.T) {
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
	defer pool.Close()

	store := NewCertificationStore(pool)

	err = store.Revoke(ctx, uuid.New())
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Revoke (unknown id): err = %v, want pgx.ErrNoRows", err)
	}
}

func TestCertificationStore_SetSignature_NotFound(t *testing.T) {
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
	defer pool.Close()

	store := NewCertificationStore(pool)

	err = store.SetSignature(ctx, uuid.New(), "sig", "path")
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("SetSignature (unknown id): err = %v, want pgx.ErrNoRows", err)
	}
}

func TestCertificationStore_GetByUserTrack_NotFound(t *testing.T) {
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
	defer pool.Close()

	store := NewCertificationStore(pool)

	_, err = store.GetByUserTrack(ctx, uuid.New(), uuid.New())
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetByUserTrack (unknown): err = %v, want pgx.ErrNoRows", err)
	}
}
