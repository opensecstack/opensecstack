package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/opensecstack/threatflow/internal/version"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// whatever was written. versionCmd.Run uses fmt.Printf (not
// cmd.OutOrStdout()), so cmd.SetOut is not sufficient here — the real
// process stdout must be captured.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return buf.String()
}

// TestVersionCmd_PrintsVersionCommitAndBuildDate proves `threatflow version`
// prints all three build-time-injected fields in the documented format.
func TestVersionCmd_PrintsVersionCommitAndBuildDate(t *testing.T) {
	out := captureStdout(t, func() {
		versionCmd.Run(versionCmd, nil)
	})

	if !strings.Contains(out, "threatflow") {
		t.Errorf("output %q missing binary name", out)
	}
	if !strings.Contains(out, version.Version) {
		t.Errorf("output %q missing Version %q", out, version.Version)
	}
	if !strings.Contains(out, version.GitCommit) {
		t.Errorf("output %q missing GitCommit %q", out, version.GitCommit)
	}
	if !strings.Contains(out, version.BuildDate) {
		t.Errorf("output %q missing BuildDate %q", out, version.BuildDate)
	}
}

// TestVersionCmd_RegisteredWithCorrectMetadata pins Use/Short so the
// subcommand's help text doesn't drift silently.
func TestVersionCmd_RegisteredWithCorrectMetadata(t *testing.T) {
	if versionCmd.Use != "version" {
		t.Errorf("Use = %q, want version", versionCmd.Use)
	}
	if versionCmd.Short == "" {
		t.Error("Short description must not be empty")
	}
}

// TestRootCmd_ExecuteVersionSubcommand drives the command through
// rootCmd.Execute() (the same path the real binary takes) to prove the
// "version" arg actually routes to versionCmd end-to-end.
func TestRootCmd_ExecuteVersionSubcommand(t *testing.T) {
	rootCmd.SetArgs([]string{"version"})
	defer rootCmd.SetArgs(nil)

	out := captureStdout(t, func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("Execute: %v", err)
		}
	})
	if !strings.Contains(out, "threatflow") {
		t.Errorf("output %q missing binary name", out)
	}
}
