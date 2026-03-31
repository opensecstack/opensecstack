package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/opensecstack/threatflow/internal/api"
	"github.com/opensecstack/threatflow/internal/config"
)

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().Int("port", 8091, "HTTP listen port")
	viper.BindPFlag("port", serveCmd.Flags().Lookup("port"))
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the ThreatFlow HTTP API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()
		srv := api.NewServer(cfg)

		addr := fmt.Sprintf(":%d", cfg.Port)
		httpServer := &http.Server{
			Addr:         addr,
			Handler:      srv.Router(),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		// Graceful shutdown on SIGINT/SIGTERM.
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			log.Info().Str("addr", addr).Msg("ThreatFlow API server starting")
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("server failed")
			}
		}()

		<-quit
		log.Info().Msg("shutting down…")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return httpServer.Shutdown(ctx)
	},
}
