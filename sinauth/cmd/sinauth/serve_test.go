package main

import (
	"errors"
	"strings"
	"testing"
)

func TestDevMode_DefaultsFalse(t *testing.T) {
	t.Setenv("SINAUTH_DEV_MODE", "")
	if devMode() {
		t.Error("devMode() = true, want false when SINAUTH_DEV_MODE is unset")
	}
}

func TestDevMode_TrueWhenSetToTrue(t *testing.T) {
	t.Setenv("SINAUTH_DEV_MODE", "true")
	if !devMode() {
		t.Error("devMode() = false, want true when SINAUTH_DEV_MODE=true")
	}
}

func TestDevMode_FalseForOtherValues(t *testing.T) {
	// devMode is a strict equality check against "true", unlike
	// config.envBool's lenient "1"/"yes" handling — pin that down so a
	// future "helpful" refactor to reuse envBool doesn't silently change
	// what values enable dev mode for this specific CLI flag.
	for _, v := range []string{"1", "yes", "TRUE", "True", "false"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("SINAUTH_DEV_MODE", v)
			if devMode() {
				t.Errorf("devMode() = true for SINAUTH_DEV_MODE=%q, want false", v)
			}
		})
	}
}

func TestResolveKeyPath_EmptyFallsBackToDevDefault(t *testing.T) {
	got := resolveKeyPath("")
	want := "dev-keys/sinauth.pem"
	if got != want {
		t.Errorf("resolveKeyPath(\"\") = %q, want %q", got, want)
	}
}

func TestResolveKeyPath_ConfiguredValuePassedThrough(t *testing.T) {
	got := resolveKeyPath("/etc/sinauth/signing.pem")
	if got != "/etc/sinauth/signing.pem" {
		t.Errorf("resolveKeyPath: got %q, want configured value unchanged", got)
	}
}

func TestBootstrapAdminMessage_StoreError(t *testing.T) {
	msg := bootstrapAdminMessage("admin@example.com", false, errors.New("connection reset"))
	if !strings.Contains(msg, "WARNING") || !strings.Contains(msg, "admin@example.com") || !strings.Contains(msg, "connection reset") {
		t.Errorf("bootstrapAdminMessage (error case) = %q, want it to mention WARNING, the email, and the error", msg)
	}
}

func TestBootstrapAdminMessage_Promoted(t *testing.T) {
	msg := bootstrapAdminMessage("admin@example.com", true, nil)
	if !strings.Contains(msg, "bootstrapped platform admin") || !strings.Contains(msg, "admin@example.com") {
		t.Errorf("bootstrapAdminMessage (promoted case) = %q, want it to confirm bootstrap for the email", msg)
	}
}

func TestBootstrapAdminMessage_NoMatchingUser(t *testing.T) {
	msg := bootstrapAdminMessage("nobody@example.com", false, nil)
	if !strings.Contains(msg, "no matching user exists yet") || !strings.Contains(msg, "nobody@example.com") {
		t.Errorf("bootstrapAdminMessage (no-user case) = %q, want it to explain no matching user for the email", msg)
	}
	if strings.Contains(msg, "WARNING") {
		t.Errorf("bootstrapAdminMessage (no-user case) should not read as an error/WARNING: %q", msg)
	}
}

// TestServeCmd_FlagDefault proves the --addr flag defaults to empty (so
// SINAUTH_HTTP_ADDR / config default is used unless explicitly overridden).
func TestServeCmd_FlagDefault(t *testing.T) {
	f := serveCmd.Flags().Lookup("addr")
	if f == nil {
		t.Fatal("serveCmd is missing the --addr flag")
	}
	if f.DefValue != "" {
		t.Errorf("--addr default = %q, want empty (config value should win unless overridden)", f.DefValue)
	}
}
