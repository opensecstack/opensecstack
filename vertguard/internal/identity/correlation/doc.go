// Package correlation provides cross-session fingerprint tracking for
// Module 5 (Synthetic Identity Detection). It detects the same synthetic
// actor submitting multiple fraudulent identity claims across sessions,
// supplementing the per-session rule engine in internal/identity/scanner.go.
//
// Phase 4.3 — v1 uses an in-memory store. Future versions will support
// Redis for multi-replica deployments via the same Correlator interface.
package correlation
