package version

import "testing"

func TestGet_ReflectsPackageVariables(t *testing.T) {
	origVersion, origCommit, origDate := Version, GitCommit, BuildDate
	t.Cleanup(func() {
		Version, GitCommit, BuildDate = origVersion, origCommit, origDate
	})

	Version = "9.9.9"
	GitCommit = "abc1234"
	BuildDate = "2026-01-01T00:00:00Z"

	got := Get()
	want := Info{Version: "9.9.9", GitCommit: "abc1234", BuildDate: "2026-01-01T00:00:00Z"}
	if got != want {
		t.Fatalf("Get() = %+v, want %+v", got, want)
	}
}

func TestGet_DefaultsAreNonEmpty(t *testing.T) {
	// Sanity check on the package defaults declared at var-init time —
	// these ship in the binary until overridden by ldflags at build time.
	info := Get()
	if info.Version == "" || info.GitCommit == "" || info.BuildDate == "" {
		t.Fatalf("Get(): default Info has empty field(s): %+v", info)
	}
}
