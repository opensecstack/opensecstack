package version

import "testing"

func TestDefaultValues_AreNonEmpty(t *testing.T) {
	if Version == "" {
		t.Error("Version must not be empty")
	}
	if GitCommit == "" {
		t.Error("GitCommit must not be empty")
	}
	if BuildDate == "" {
		t.Error("BuildDate must not be empty")
	}
}

func TestVersion_DefaultIsDev(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want %q", Version, "dev")
	}
}

func TestGitCommit_DefaultIsUnknown(t *testing.T) {
	if GitCommit != "unknown" {
		t.Errorf("GitCommit = %q, want %q", GitCommit, "unknown")
	}
}

func TestBuildDate_DefaultIsUnknown(t *testing.T) {
	if BuildDate != "unknown" {
		t.Errorf("BuildDate = %q, want %q", BuildDate, "unknown")
	}
}

func TestVariables_CanBeOverridden(t *testing.T) {
	// Save originals and restore after test.
	origVersion := Version
	origGitCommit := GitCommit
	origBuildDate := BuildDate
	t.Cleanup(func() {
		Version = origVersion
		GitCommit = origGitCommit
		BuildDate = origBuildDate
	})

	Version = "1.2.3"
	GitCommit = "abc1234"
	BuildDate = "2026-03-30T00:00:00Z"

	if Version != "1.2.3" {
		t.Errorf("Version = %q after override, want %q", Version, "1.2.3")
	}
	if GitCommit != "abc1234" {
		t.Errorf("GitCommit = %q after override, want %q", GitCommit, "abc1234")
	}
	if BuildDate != "2026-03-30T00:00:00Z" {
		t.Errorf("BuildDate = %q after override, want %q", BuildDate, "2026-03-30T00:00:00Z")
	}
}
