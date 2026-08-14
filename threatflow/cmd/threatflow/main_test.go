package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// These tests exercise main() via a self-exec subprocess: the test binary
// re-invokes itself with a marker env var, and the marked run sets os.Args
// then calls main() directly. This is necessary because main() ultimately
// reaches os.Exit(1) on command error (via cmd.Execute() in
// cmd/threatflow/cmd/root.go), which would otherwise kill the real `go
// test` process.

func TestMain_VersionSubcommand_PrintsVersionAndExitsZero(t *testing.T) {
	if os.Getenv("THREATFLOW_MAIN_TEST_SUBPROCESS") == "version" {
		os.Args = []string{"threatflow", "version"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMain_VersionSubcommand_PrintsVersionAndExitsZero$")
	cmd.Env = append(os.Environ(), "THREATFLOW_MAIN_TEST_SUBPROCESS=version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "threatflow") {
		t.Errorf("expected output to mention threatflow, got: %s", out)
	}
}

func TestMain_UnknownSubcommand_ExitsNonZero(t *testing.T) {
	if os.Getenv("THREATFLOW_MAIN_TEST_SUBPROCESS") == "unknown" {
		os.Args = []string{"threatflow", "definitely-not-a-real-command"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMain_UnknownSubcommand_ExitsNonZero$")
	cmd.Env = append(os.Environ(), "THREATFLOW_MAIN_TEST_SUBPROCESS=unknown")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for an unknown subcommand")
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got err=%v", err)
	}
}
