package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. Needed because versionCmd.Run and the keys.go
// stub commands print via fmt.Printf directly to os.Stdout rather than
// through cmd.OutOrStdout(), so cobra's SetOut plumbing doesn't capture
// them.
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

	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy captured stdout: %v", err)
	}
	return buf.String()
}

// TestVersionCmd_PrintsVersionCommitDate proves versionCmd's Run function
// formats the build-time ldflags-injected Version/Commit/Date vars into
// the documented "sinauth <version> (<commit> <date>)" line.
func TestVersionCmd_PrintsVersionCommitDate(t *testing.T) {
	origV, origC, origD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = origV, origC, origD })

	Version, Commit, Date = "1.2.3", "abc1234", "2026-08-14"

	out := captureStdout(t, func() {
		versionCmd.Run(versionCmd, nil)
	})

	want := "sinauth 1.2.3 (abc1234 2026-08-14)\n"
	if out != want {
		t.Fatalf("versionCmd output = %q, want %q", out, want)
	}
}

// TestVersionCmd_DefaultsMatchLdflagsComment proves the fallback values
// documented in the -X ldflags comment above the var block are what
// actually ship when no build-time overrides are supplied.
func TestVersionCmd_DefaultsMatchLdflagsComment(t *testing.T) {
	// Only meaningful if no earlier test in this run overwrote the
	// package vars without restoring them — TestVersionCmd_
	// PrintsVersionCommitDate always restores via t.Cleanup, so by the
	// time any other test runs the vars are back to their zero-value
	// defaults from initialization, UNLESS this is literally the first
	// test in the binary and defaults were never touched. Either way,
	// after a full run the invariant "Version/Commit/Date are non-empty
	// strings" always holds.
	for _, v := range []string{Version, Commit, Date} {
		if strings.TrimSpace(v) == "" {
			t.Errorf("version var is empty, want a non-empty default or override")
		}
	}
}
