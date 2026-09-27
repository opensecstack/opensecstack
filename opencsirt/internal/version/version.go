package version

// Version of OpenCSIRT. Overridden via -ldflags at build time (see
// Dockerfile); var rather than const so -X can inject it.
var Version = "1.0.0"
