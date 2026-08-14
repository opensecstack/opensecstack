package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/opensecstack/threatflow/internal/config"
)

// testDSN returns the disposable-postgres DSN for db package tests, skipping
// cleanly when THREATFLOW_TEST_DB_URL is unset so `go test ./...` stays fast
// and hermetic (mirrors internal/db/store's testDB helper).
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("THREATFLOW_TEST_DB_URL")
	if dsn == "" {
		t.Skip("THREATFLOW_TEST_DB_URL not set; skipping db integration tests")
	}
	return dsn
}

func TestOpen_InvalidURL_ReturnsParseError(t *testing.T) {
	_, err := Open(context.Background(), config.DatabaseConfig{URL: "not-a-valid-dsn ::"})
	if err == nil {
		t.Fatal("expected error for invalid DSN, got nil")
	}
}

func TestOpen_UnreachableHost_ReturnsPingError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Open(ctx, config.DatabaseConfig{URL: "postgres://user:pass@127.0.0.1:1/nonexistent?sslmode=disable&connect_timeout=1"})
	if err == nil {
		t.Fatal("expected error for unreachable host, got nil")
	}
}

func TestOpen_Success_PingsAndCloses(t *testing.T) {
	dsn := testDSN(t)

	database, err := Open(context.Background(), config.DatabaseConfig{
		URL:          dsn,
		MaxOpenConns: 5,
		MaxIdleConns: 1,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if database.Pool == nil {
		t.Fatal("expected non-nil Pool")
	}
	database.Close()

	// Close must be safe to call twice and on a nil-Pool DB.
	database.Close()
	(&DB{}).Close()
}

func TestOpen_Success_WithoutPoolSizeOverrides(t *testing.T) {
	dsn := testDSN(t)

	database, err := Open(context.Background(), config.DatabaseConfig{URL: dsn})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer database.Close()
}
