package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/opensecstack/opensecstack/irflow/internal/auth"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// whatever was written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading pipe: %v", err)
	}
	return buf.String()
}

func resetAuthIssueFlags() {
	authIssueUser = ""
	authIssueRole = auth.RoleOperator
	authIssueEmail = ""
}

func TestRunAuthIssue_MissingSecret_ReturnsError(t *testing.T) {
	resetAuthIssueFlags()
	t.Setenv("IRFLOW_AUTH_SECRET", "")
	authIssueUser = "alice"

	err := runAuthIssue(authIssueCmd, nil)
	if err == nil {
		t.Fatal("expected an error when auth.secret is not configured, got nil")
	}
	if !strings.Contains(err.Error(), "auth.secret is not configured") {
		t.Errorf("error = %v, want message about missing auth.secret", err)
	}
}

func TestRunAuthIssue_UnknownRole_ReturnsError(t *testing.T) {
	resetAuthIssueFlags()
	t.Setenv("IRFLOW_AUTH_SECRET", "test-secret-for-cli")
	authIssueUser = "alice"
	authIssueRole = "wizard"

	err := runAuthIssue(authIssueCmd, nil)
	if err == nil {
		t.Fatal("expected an error for an unknown role, got nil")
	}
	if !strings.Contains(err.Error(), "unknown role") {
		t.Errorf("error = %v, want message about unknown role", err)
	}
}

func TestRunAuthIssue_Success_PrintsValidToken(t *testing.T) {
	resetAuthIssueFlags()
	const secret = "test-secret-for-cli-success"
	t.Setenv("IRFLOW_AUTH_SECRET", secret)
	authIssueUser = "alice"
	authIssueRole = auth.RoleAdmin
	authIssueEmail = "alice@example.com"

	var runErr error
	out := captureStdout(t, func() {
		runErr = runAuthIssue(authIssueCmd, nil)
	})
	if runErr != nil {
		t.Fatalf("runAuthIssue returned error: %v", runErr)
	}

	token := strings.TrimSpace(out)
	if token == "" {
		t.Fatal("expected a token to be printed to stdout, got empty output")
	}

	claims, err := auth.Verify(secret, token)
	if err != nil {
		t.Fatalf("printed token does not verify against the configured secret: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "alice")
	}
	if claims.Role != auth.RoleAdmin {
		t.Errorf("Role = %q, want %q", claims.Role, auth.RoleAdmin)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "alice@example.com")
	}
}
