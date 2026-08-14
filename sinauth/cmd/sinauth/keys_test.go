package main

import (
	"strings"
	"testing"
)

// TestRunKeysGenerate_NotYetImplemented and TestRunKeysRotate_NotYetImplemented
// pin down the current (explicitly stubbed) behaviour of `sinauth keys
// generate`/`sinauth keys rotate`: both print a "not yet implemented"
// notice and return nil rather than a misleading success message or a
// panic. If these are ever implemented for real, these tests should be
// replaced with tests of the real behaviour — until then they guard
// against the stub silently starting to claim success.
func TestRunKeysGenerate_NotYetImplemented(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runKeysGenerate(keysGenerateCmd, nil); err != nil {
			t.Fatalf("runKeysGenerate: %v", err)
		}
	})
	if !strings.Contains(out, "not yet implemented") {
		t.Errorf("output = %q, want it to contain %q", out, "not yet implemented")
	}
}

func TestRunKeysRotate_NotYetImplemented(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runKeysRotate(keysRotateCmd, nil); err != nil {
			t.Fatalf("runKeysRotate: %v", err)
		}
	})
	if !strings.Contains(out, "not yet implemented") {
		t.Errorf("output = %q, want it to contain %q", out, "not yet implemented")
	}
}

// TestKeysCmd_Wiring proves keysCmd exposes exactly the generate/rotate
// subcommands wired in init(), matching how root.go composes the CLI.
func TestKeysCmd_Wiring(t *testing.T) {
	names := map[string]bool{}
	for _, c := range keysCmd.Commands() {
		names[c.Name()] = true
	}
	if !names["generate"] {
		t.Error("keysCmd is missing the 'generate' subcommand")
	}
	if !names["rotate"] {
		t.Error("keysCmd is missing the 'rotate' subcommand")
	}
}
