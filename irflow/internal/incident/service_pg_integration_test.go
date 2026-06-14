//go:build integration

// Service-level integration coverage lives in the cmd/irflow E2E test
// because it can import db and incident without the circular-dependency
// gymnastics a test in this package would need.
package incident
