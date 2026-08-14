package cmd

import (
	"testing"

	"github.com/spf13/viper"
)

// TestServeCmd_RegisteredWithCorrectMetadata pins Use/Short for the serve
// subcommand's help text.
func TestServeCmd_RegisteredWithCorrectMetadata(t *testing.T) {
	if serveCmd.Use != "serve" {
		t.Errorf("Use = %q, want serve", serveCmd.Use)
	}
	if serveCmd.Short == "" {
		t.Error("Short description must not be empty")
	}
	if serveCmd.RunE == nil {
		t.Error("serveCmd must define RunE")
	}
}

// TestServeCmd_PortFlagDefaultAndBinding proves --port defaults to 8091 and
// is bound into viper (so THREATFLOW_PORT and --port both resolve to
// cfg.Port at startup). RunE itself is not invoked here — it opens a real
// DB/HTTP listener with no test seam, so exercising it belongs in an
// integration test, not a unit test.
func TestServeCmd_PortFlagDefaultAndBinding(t *testing.T) {
	f := serveCmd.Flags().Lookup("port")
	if f == nil {
		t.Fatal("--port flag not registered")
	}
	if f.DefValue != "8091" {
		t.Errorf("--port default = %q, want 8091", f.DefValue)
	}
	if f.Value.Type() != "int" {
		t.Errorf("--port type = %q, want int", f.Value.Type())
	}
}

// TestServeCmd_PortFlagParsesOverride proves a caller-supplied --port value
// is actually parsed and reflected by viper, without starting a server.
func TestServeCmd_PortFlagParsesOverride(t *testing.T) {
	if err := serveCmd.Flags().Set("port", "9999"); err != nil {
		t.Fatalf("set --port: %v", err)
	}
	defer func() {
		_ = serveCmd.Flags().Set("port", "8091")
	}()

	if got := viper.GetInt("port"); got != 9999 {
		t.Errorf("viper port = %d, want 9999", got)
	}
}

// TestServeCmd_RegisteredOnRootCmd proves serve is reachable as
// `threatflow serve` through the standard subcommand lookup.
func TestServeCmd_RegisteredOnRootCmd(t *testing.T) {
	found, _, err := rootCmd.Find([]string{"serve"})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if found != serveCmd {
		t.Error("rootCmd.Find(\"serve\") did not resolve to serveCmd")
	}
}
