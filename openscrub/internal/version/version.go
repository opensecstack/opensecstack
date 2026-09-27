// Package version exposes the build-time version string.
package version

// Version is the semver-style version of the OpenScrub control plane.
// Overridden via -ldflags at build time (see cmd/openscrub/Dockerfile);
// var rather than const so -X can inject it.
var Version = "1.0.0"
