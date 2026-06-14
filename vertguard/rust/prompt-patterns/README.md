# vertguard-prompt-patterns

**STATUS: OPTIONAL PERFORMANCE PATH (v1.1) — NOT THE PRODUCTION ENGINE.**

The production prompt-injection engine for VertGuard Module 3 is the
Go package at `internal/prompt`. As of VG-003 (v1.0) the Go engine
ships a curated rule pack (`internal/prompt/rules/v1.json`),
token-level heuristics (`heuristics.go`), and a subprocess-based
`MLBackend` contract (`mlexec.go`). All deployments use that engine.

This Rust crate is reserved for a v1.1 hot-path optimisation
(experimental). Its `Engine::scan` is currently a stub that returns
an empty `ScanResult` regardless of input — downstream Rust consumers
MUST NOT treat it as a working scanner.

See:
- `internal/prompt/` — production Go engine (regex + heuristics + ML hook)
- `internal/prompt/rules/v1.json` — shipped rule pack
- `docs/module-3-prompt-injection.md` — engine design notes
- `docs/owasp-llm-top10-coverage.md` — coverage matrix
