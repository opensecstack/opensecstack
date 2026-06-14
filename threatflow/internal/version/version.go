package version

// Set via -ldflags at build time.
var (
	Version   = "1.0.0"
	GitCommit = "unknown"
	BuildDate = "unknown"
)
