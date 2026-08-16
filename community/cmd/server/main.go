package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opensecstack/community/internal/api"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
	"github.com/opensecstack/community/internal/scheduler"
)

var version = "dev"

// newHTTPServer builds the *http.Server that wraps the given handler with
// this service's fixed timeouts. Extracted from main() so the wiring
// (addr/timeouts) is testable without binding a real listener.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// shutdownServer gracefully shuts the server down, bounding the wait with
// the given timeout. Extracted from main() so the context/timeout plumbing
// is testable against an httptest-style *http.Server without needing a real
// OS signal.
func shutdownServer(srv *http.Server, timeout time.Duration) error {
	shutCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	pool, err := db.Connect(cfg.DBURL, cfg.DBMaxConns)
	if err != nil {
		slog.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(pool); err != nil {
		slog.Error("migration", "err", err)
		os.Exit(1)
	}

	srv := api.NewServer(cfg, pool, version)

	httpSrv := newHTTPServer(cfg.HTTPAddr, srv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go scheduler.Start(ctx, pool, cfg)

	go func() {
		slog.Info("community starting", "addr", cfg.HTTPAddr, "version", version)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	_ = shutdownServer(httpSrv, 10*time.Second)
}
