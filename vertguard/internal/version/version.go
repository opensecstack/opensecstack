// Package version exposes build-time metadata injected via ldflags.
//
// See Makefile `LDFLAGS` for the injection points. Values are
// populated at `go build` time; defaults reflect a dev build.
package version

var (
	// Version is the semver version string (e.g. "0.1.0").
	Version = "1.0.0"

	// GitCommit is the short SHA of the build commit.
	GitCommit = "unknown"

	// BuildDate is the RFC3339 UTC timestamp of the build.
	BuildDate = "unknown"
)

// Info bundles the version metadata into a single struct for JSON
// responses (e.g. the /health endpoint).
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"commit"`
	BuildDate string `json:"built"`
}

// Get returns the current build Info.
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
	}
}
