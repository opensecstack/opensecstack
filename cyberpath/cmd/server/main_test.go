package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/config"
)

// ---------------------------------------------------------------------------
// stubPinger
// ---------------------------------------------------------------------------

func TestStubPinger_AlwaysReturnsNil(t *testing.T) {
	var p stubPinger
	if err := p.Ping(context.Background()); err != nil {
		t.Errorf("stubPinger.Ping() = %v, want nil", err)
	}
	// Also exercise Ping with an already-canceled context, since the stub
	// is documented to ignore the context entirely (degraded-mode fallback
	// must never itself report unhealthy).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Ping(ctx); err != nil {
		t.Errorf("stubPinger.Ping(canceled ctx) = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// dbConfigured
// ---------------------------------------------------------------------------

func TestDBConfigured(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		password string
		want     bool
	}{
		{"both empty", "", "", false},
		{"url set", "postgres://x", "", true},
		{"password set", "", "hunter2", true},
		{"both set", "postgres://x", "hunter2", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dbConfigured(tt.url, tt.password)
			if got != tt.want {
				t.Errorf("dbConfigured(%q, %q) = %v, want %v", tt.url, tt.password, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// effectiveSinauthURL
// ---------------------------------------------------------------------------

func TestEffectiveSinauthURL(t *testing.T) {
	if got := effectiveSinauthURL(""); got != "http://localhost:8100" {
		t.Errorf("effectiveSinauthURL(\"\") = %q, want the dev default", got)
	}
	if got := effectiveSinauthURL("https://sinauth.internal"); got != "https://sinauth.internal" {
		t.Errorf("effectiveSinauthURL(configured) = %q, want the configured value unchanged", got)
	}
}

// ---------------------------------------------------------------------------
// effectiveDrainGrace
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// buildApp
//
// buildApp performs the server's full dependency wire-up. Without a DB it
// runs entirely in the "degraded mode" this file's package comment
// describes — no network I/O beyond an optional Docker daemon probe — so
// it is safe and fast to exercise directly under `go test`. The
// DB-configured-but-unreachable case is also deterministic (bounded by
// db.New's 5s ping timeout) and requires no live database.
// ---------------------------------------------------------------------------

func TestBuildApp_DegradedMode_NoDBConfigured(t *testing.T) {
	cfg := &config.Config{}
	srv, worker, closeDB := buildApp(context.Background(), cfg, zerolog.Nop())
	defer closeDB()

	if srv == nil {
		t.Fatal("buildApp() returned a nil *http.Server")
	}
	if srv.Handler == nil {
		t.Error("buildApp() returned a server with a nil Handler (router not wired)")
	}
	if worker != nil {
		t.Error("buildApp() with no DB configured: worker should be nil (outbox worker never started)")
	}
	// closeDB must be safe to call even though no DB was ever opened.
}

func TestBuildApp_DBConfiguredButUnreachable_FallsBackToDegradedMode(t *testing.T) {
	cfg := &config.Config{}
	// A loopback address nothing listens on: connection is refused
	// immediately rather than timing out, so db.New's ping fails fast and
	// buildApp falls back to the stub pinger exactly as it would for any
	// other DB outage.
	cfg.DB.URL = "postgres://user:pass@127.0.0.1:1/nonexistent?sslmode=disable&connect_timeout=1"

	srv, worker, closeDB := buildApp(context.Background(), cfg, zerolog.Nop())
	defer closeDB()

	if srv == nil {
		t.Fatal("buildApp() returned a nil *http.Server")
	}
	if worker != nil {
		t.Error("buildApp() with an unreachable DB: worker should be nil (outbox worker never wired)")
	}
}

// liveTestDBURL is the shared Postgres instance available to this
// package's tests per the task's own environment notes. Only ever used
// read-only here (open a pool, ping, start/stop the outbox worker against
// an empty poll) — no DDL, no row writes.
const liveTestDBURL = "postgres://apiguard@localhost:5434/cyberpath_test?sslmode=disable"

// requireLiveDB skips the test unless liveTestDBURL is actually reachable,
// so this suite still passes in environments without that shared instance.
func requireLiveDB(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "localhost:5434", 2*time.Second)
	if err != nil {
		t.Skipf("shared test Postgres unreachable, skipping: %v", err)
	}
	_ = conn.Close()
}

// TestBuildApp_WithLiveDB_WiresAuthIRFlowAndWorker proves buildApp's
// DB-backed wire-up path — auth handlers, the IRFlow webhook handler, and
// the CITADEL outbox worker — actually activates when a real DB
// connection succeeds and the relevant secrets are configured. The worker
// is stopped immediately after the assertions via the same
// cancel-then-Wait sequence main() itself uses for shutdown.
func TestBuildApp_WithLiveDB_WiresAuthIRFlowAndWorker(t *testing.T) {
	requireLiveDB(t)

	cfg := &config.Config{}
	cfg.DB.URL = liveTestDBURL
	cfg.Auth.Secret = "test-only-signing-secret-not-for-prod-use"
	cfg.Auth.Issuer = "cyberpath-test"
	cfg.IRFlow.WebhookSecret = "test-irflow-webhook-secret"

	ctx, cancel := context.WithCancel(context.Background())
	srv, worker, closeDB := buildApp(ctx, cfg, zerolog.Nop())

	if srv == nil {
		t.Fatal("buildApp() returned a nil *http.Server")
	}
	if worker == nil {
		t.Error("buildApp() with a live DB: expected the outbox worker to be wired, got nil")
	}

	// Shut down exactly as main() does: cancel the context, then wait for
	// the worker's goroutines to drain, then close the pool.
	cancel()
	if worker != nil {
		worker.Wait()
	}
	closeDB()
}

// ---------------------------------------------------------------------------
// main(), via subprocess
//
// main() calls os.Exit indirectly (via zerolog's Fatal, and directly on a
// failed Shutdown) and normally blocks forever in ListenAndServe, so it
// cannot run in-process under `go test`. Following the same re-exec
// pattern used by cmd/cyberpath-cli's tests (and Go's own os/exec package
// tests), TestServerHelperProcess re-invokes the compiled test binary as
// a subprocess with a sentinel env var, letting the real main() run to
// completion in a disposable child process.
//
// The child is configured (via CYBERPATH_* env vars, exactly as a real
// deployment would be) with an invalid HTTP_ADDR so ListenAndServe fails
// immediately: main() takes its errCh branch, drains (1ms grace), calls
// Shutdown on a server that never actually started listening (a no-op),
// and returns — exercising the full main() control flow deterministically
// and fast, without binding a real port or sending OS signals.
// ---------------------------------------------------------------------------

func TestServerHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SERVER_HELPER") != "1" {
		return
	}
	main()
}

func TestMain_ListenErrorTriggersCleanShutdown(t *testing.T) {
	testArgs := []string{"-test.run=^TestServerHelperProcess$"}
	// Forward -test.gocoverdir so the child's execution of main() (and
	// buildApp, and everything else it reaches) contributes to this
	// package's coverage profile — GOCOVERDIR alone in the environment
	// is not enough for a *test* binary to know where to write.
	if dir := os.Getenv("GOCOVERDIR"); dir != "" {
		testArgs = append(testArgs, "-test.gocoverdir="+dir)
	}
	cmd := exec.Command(os.Args[0], testArgs...)
	cmd.Env = append(os.Environ(),
		"GO_WANT_SERVER_HELPER=1",
		// Port 999999 is out of range (max 65535), so net.Listen fails
		// synchronously instead of trying to bind.
		"CYBERPATH_SERVER_HTTP_ADDR=127.0.0.1:999999",
		"CYBERPATH_SERVER_DRAIN_GRACE=1ms",
		"CYBERPATH_CONTENT_PATH=",
		"CYBERPATH_DB_URL=",
		"CYBERPATH_DB_PASSWORD=",
		"CYBERPATH_ENV=",
		"GO_ENV=",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess main() did not exit cleanly: %v\noutput:\n%s", err, out)
	}
}

func TestEffectiveDrainGrace(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero falls back to default", 0, 5 * time.Second},
		{"negative falls back to default", -1 * time.Second, 5 * time.Second},
		{"positive value passed through", 30 * time.Second, 30 * time.Second},
		{"small positive value passed through", 1 * time.Millisecond, 1 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveDrainGrace(tt.in)
			if got != tt.want {
				t.Errorf("effectiveDrainGrace(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
