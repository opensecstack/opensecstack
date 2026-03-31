// Package version holds build-time version information shared across the
// application. Values are injected via ldflags at build time.
package version

// Version, GitCommit, and BuildDate are set by the linker at build time.
// They default to development-friendly values when not overridden.
var (
	Version   = "1.0.0"
	GitCommit = "unknown"
	BuildDate = "unknown"
)
