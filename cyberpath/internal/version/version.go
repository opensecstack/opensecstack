// Package version exposes build-time metadata injected via ldflags.
//
// Values are populated at `go build` time (see Makefile LDFLAGS);
// defaults reflect a dev build.
package version

var (
	// Version is the semver version string (e.g. "0.0.1").
	Version = "1.0.0"

	// GitCommit is the short SHA of the build commit.
	GitCommit = "unknown"

	// BuildDate is the RFC3339 UTC timestamp of the build.
	BuildDate = "unknown"
)

// Info bundles the version metadata for JSON responses.
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
