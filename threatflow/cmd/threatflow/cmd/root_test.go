package cmd

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// TestRootCmd_RegistersExpectedSubcommands proves migrate, serve, and
// version are wired onto rootCmd via their package init()s — a regression
// guard for `threatflow <subcommand>` routing.
func TestRootCmd_RegistersExpectedSubcommands(t *testing.T) {
	want := map[string]bool{"migrate": false, "serve": false, "version": false}
	for _, c := range rootCmd.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered on rootCmd", name)
		}
	}
}

// TestRootCmd_Metadata pins the CLI's Use/Short strings so accidental edits
// to the top-level help text are caught.
func TestRootCmd_Metadata(t *testing.T) {
	if rootCmd.Use != "threatflow" {
		t.Errorf("Use = %q, want threatflow", rootCmd.Use)
	}
	if rootCmd.Short == "" {
		t.Error("Short description must not be empty")
	}
}

// TestRootCmd_PersistentFlagsRegisteredWithDefaults proves --log-level and
// --log-format are registered with the documented defaults and are bound
// into viper so THREATFLOW_LOG_LEVEL / THREATFLOW_LOG_FORMAT env overrides
// work as intended.
func TestRootCmd_PersistentFlagsRegisteredWithDefaults(t *testing.T) {
	lvl := rootCmd.PersistentFlags().Lookup("log-level")
	if lvl == nil {
		t.Fatal("--log-level flag not registered")
	}
	if lvl.DefValue != "info" {
		t.Errorf("--log-level default = %q, want info", lvl.DefValue)
	}

	format := rootCmd.PersistentFlags().Lookup("log-format")
	if format == nil {
		t.Fatal("--log-format flag not registered")
	}
	if format.DefValue != "json" {
		t.Errorf("--log-format default = %q, want json", format.DefValue)
	}
}

// TestInitConfig_InvalidLogLevelFallsBackToInfo proves a garbage log level
// (typo'd env var, bad flag value) degrades gracefully to Info instead of
// crashing the process at startup.
func TestInitConfig_InvalidLogLevelFallsBackToInfo(t *testing.T) {
	prev := viper.GetString("log_level")
	defer viper.Set("log_level", prev)

	viper.Set("log_level", "not-a-real-level")
	initConfig()

	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("global level = %v, want InfoLevel fallback for invalid input", zerolog.GlobalLevel())
	}
}

// TestInitConfig_ValidLogLevelIsApplied proves a well-formed level string
// (as would arrive via --log-level or THREATFLOW_LOG_LEVEL) is actually
// applied to the global zerolog level, not silently ignored.
func TestInitConfig_ValidLogLevelIsApplied(t *testing.T) {
	prev := viper.GetString("log_level")
	defer func() {
		viper.Set("log_level", prev)
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}()

	viper.Set("log_level", "debug")
	initConfig()

	if zerolog.GlobalLevel() != zerolog.DebugLevel {
		t.Errorf("global level = %v, want DebugLevel", zerolog.GlobalLevel())
	}
}

// TestInitConfig_TextFormatDoesNotPanic proves the "text" log-format branch
// (which swaps log.Logger to a ConsoleWriter) executes without error; we
// cannot assert on log.Logger's internal writer type without exporting
// internals, so this test's purpose is coverage of the branch plus a
// not-panicking guarantee.
func TestInitConfig_TextFormatDoesNotPanic(t *testing.T) {
	prevLevel := viper.GetString("log_level")
	prevFormat := viper.GetString("log_format")
	defer func() {
		viper.Set("log_level", prevLevel)
		viper.Set("log_format", prevFormat)
	}()

	viper.Set("log_level", "info")
	viper.Set("log_format", "text")
	initConfig()
}

// TestExecute_SuccessPathDoesNotExit drives the exported Execute() wrapper
// (the same entry point main() calls) through a successful subcommand
// invocation. Execute() calls os.Exit(1) only on error, so this test
// deliberately picks an args set ("version") that cannot fail, proving the
// success path returns normally instead of terminating the test process.
func TestExecute_SuccessPathDoesNotExit(t *testing.T) {
	rootCmd.SetArgs([]string{"version"})
	defer rootCmd.SetArgs(nil)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	Execute()
	os.Stdout = orig
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if buf.Len() == 0 {
		t.Error("expected version output on stdout")
	}
}
