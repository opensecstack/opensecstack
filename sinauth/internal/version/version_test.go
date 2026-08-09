package version

import "testing"

func TestString_FormatsAllThreeFields(t *testing.T) {
	origVersion, origCommit, origDate := Version, Commit, Date
	defer func() { Version, Commit, Date = origVersion, origCommit, origDate }()

	Version = "1.2.3"
	Commit = "abc123"
	Date = "2026-01-01"

	got := String()
	want := "1.2.3 (abc123 2026-01-01)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestString_Defaults(t *testing.T) {
	origVersion, origCommit, origDate := Version, Commit, Date
	defer func() { Version, Commit, Date = origVersion, origCommit, origDate }()

	Version, Commit, Date = "dev", "none", "unknown"

	got := String()
	want := "dev (none unknown)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
