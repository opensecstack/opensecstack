package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestRoot_AllSubcommandsRegistered proves root.go's init() wires every
// intended subcommand onto the root command — a missing AddCommand call
// would silently drop a whole CLI surface (e.g. `sinauth migrate` simply
// not existing) without any compile-time signal.
func TestRoot_AllSubcommandsRegistered(t *testing.T) {
	want := []string{"serve", "migrate", "keys", "version", "health", "promote-admin", "permify-sync"}

	got := map[string]bool{}
	for _, c := range root.Commands() {
		got[c.Name()] = true
	}

	for _, name := range want {
		if !got[name] {
			t.Errorf("root command %q is not registered", name)
		}
	}
	if len(root.Commands()) != len(want) {
		t.Errorf("root has %d subcommands %v, want exactly %v", len(root.Commands()), commandNames(root.Commands()), want)
	}
}

func commandNames(cmds []*cobra.Command) []string {
	names := make([]string, len(cmds))
	for i, c := range cmds {
		names[i] = c.Name()
	}
	return names
}
