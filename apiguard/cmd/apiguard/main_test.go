package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func TestSeverityMeetsThreshold(t *testing.T) {
	cases := []struct {
		sev, threshold string
		want           bool
	}{
		{"critical", "high", true},
		{"high", "high", true},
		{"medium", "high", false},
		{"low", "info", true},
		{"info", "critical", false},
		{"critical", "critical", true},
		{"bogus", "high", false},
		{"high", "bogus", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := severityMeetsThreshold(c.sev, c.threshold); got != c.want {
			t.Errorf("severityMeetsThreshold(%q, %q) = %v, want %v", c.sev, c.threshold, got, c.want)
		}
	}
}

func TestInitLoggerLevel(t *testing.T) {
	t.Run("valid level", func(t *testing.T) {
		initLoggerLevel("debug")
		if zerolog.GlobalLevel() != zerolog.DebugLevel {
			t.Errorf("expected debug level, got %v", zerolog.GlobalLevel())
		}
	})
	t.Run("invalid level falls back to info", func(t *testing.T) {
		initLoggerLevel("not-a-real-level")
		if zerolog.GlobalLevel() != zerolog.InfoLevel {
			t.Errorf("expected info level fallback, got %v", zerolog.GlobalLevel())
		}
	})
}

func TestInitConfig_NoFileFound(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(orig) }()

	// No apiguard.yaml anywhere on the search path — must not panic/fatal.
	initConfig("")
}

func TestInitConfig_ExplicitFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(cfgFile, []byte("port: 9090\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	initConfig(cfgFile)
}

func TestVersionCmd_Run(t *testing.T) {
	cmd := versionCmd()
	if cmd.Use != "version" {
		t.Errorf("expected Use=version, got %q", cmd.Use)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	cmd.Run(cmd, nil)
	_ = w.Close()
	os.Stdout = old

	out, _ := io.ReadAll(r)
	if !bytes.Contains(out, []byte("apiguard")) {
		t.Errorf("expected output to mention apiguard, got %q", out)
	}
}

func TestReportCmd_RunE_MissingScanID(t *testing.T) {
	cmd := reportCmd()
	cmd.SetArgs([]string{})
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Error("expected error when --scan-id is missing")
	}
}

func TestReportCmd_Flags(t *testing.T) {
	cmd := reportCmd()
	for _, name := range []string{"scan-id", "format", "output", "config"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q to be registered", name)
		}
	}
}

func TestRuleCmd_HasSubcommands(t *testing.T) {
	cmd := ruleCmd()
	if !cmd.HasSubCommands() {
		t.Fatal("expected rule command to have subcommands")
	}
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	if !names["validate"] || !names["test"] {
		t.Errorf("expected validate and test subcommands, got %v", names)
	}
}

func TestRuleValidateCmd_RunE_NonexistentPath(t *testing.T) {
	cmd := ruleValidateCmd()
	if err := cmd.RunE(cmd, []string{filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestRuleValidateCmd_RunE_DirectoryPath(t *testing.T) {
	cmd := ruleValidateCmd()
	if err := cmd.RunE(cmd, []string{t.TempDir()}); err == nil {
		t.Error("expected error when path is a directory")
	}
}

func TestRuleValidateCmd_RunE_InvalidRuleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad_rule.yaml")
	if err := os.WriteFile(path, []byte("not: [valid, rule, schema"), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	cmd := ruleValidateCmd()
	if err := cmd.RunE(cmd, []string{path}); err == nil {
		t.Error("expected error for malformed rule YAML")
	}
}

func TestRuleTestCmd_RunE_MissingTarget(t *testing.T) {
	cmd := ruleTestCmd()
	if err := cmd.RunE(cmd, []string{"rule.yaml"}); err == nil {
		t.Error("expected error when --target is missing")
	}
}

func TestRuleTestCmd_RunE_MissingSpec(t *testing.T) {
	cmd := ruleTestCmd()
	_ = cmd.Flags().Set("target", "http://example.com")
	if err := cmd.RunE(cmd, []string{"rule.yaml"}); err == nil {
		t.Error("expected error when --spec is missing")
	}
}

func TestRuleTestCmd_Flags(t *testing.T) {
	cmd := ruleTestCmd()
	for _, name := range []string{"target", "spec"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q to be registered", name)
		}
	}
}

func TestServerCmd_FlagsAndBinding(t *testing.T) {
	cmd := serverCmd()
	for _, name := range []string{"config", "port", "db-url", "redis-url", "jwt-secret"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q to be registered", name)
		}
	}
}

func TestScanCmd_Flags(t *testing.T) {
	cmd := scanCmd()
	if cmd.Use == "" {
		t.Error("expected scanCmd to have a Use string")
	}
	if cmd.Flags().Lookup("target") == nil {
		t.Error("expected --target flag on scan command")
	}
}
