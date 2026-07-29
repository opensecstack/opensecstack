# Good First Issues

This guide helps new contributors find their footing. Every item listed here is approachable without deep knowledge of the full codebase.

---

## Before you start

1. Read [CONTRIBUTING.md](../CONTRIBUTING.md) — especially the commit format and PR checklist
2. Set up the dev environment: `docker compose up` in the root
3. Pick one item from the lists below
4. Comment on the GitHub Issue to claim it — prevents duplicate work
5. Open a draft PR early; maintainers will help if you get stuck

---

## APIGuard — Go + Rust

These require Go or Rust. APIGuard is the most active platform and the best entry point.

| Area | Task | Skills | Difficulty |
|------|------|--------|-----------|
| Tests | Add table-driven tests for the CVSS 3.1 scoring edge cases | Go, testing | Easy |
| Tests | Add fuzz targets for the OpenAPI parser | Rust | Medium |
| Docs | Add a `--help` example to the CLI usage section in the README | Markdown | Easy |
| Config | Validate that `scanner.concurrency` cannot be set to 0 in config loading | Go | Easy |
| Scanner | Add A8 (Security Misconfiguration) detection for missing CORS headers | Go | Medium |
| Reporter | Add a Markdown reporter alongside HTML/JSON/SARIF | Go | Medium |
| CI | Add a step that checks the SARIF output validates against the SARIF 2.1.0 JSON schema | YAML, CI | Easy |

---

## NIS2 Compass — Python

Python-first. Good entry for contributors from compliance or data backgrounds.

| Area | Task | Skills | Difficulty |
|------|------|--------|-----------|
| Tests | Write tests for all 10 NIS2 Article 21(2) measure evaluators (a–j) | Python, pytest | Easy |
| Tests | Add tests for the audit log chain hash version migration (v1 → v2) | Python | Medium |
| Docs | Write a worked example: assess a fictional SaaS company against NIS2 | Markdown | Easy |
| Reports | Add a CSV export option alongside PDF and JSON | Python | Easy |
| UI | Add a filter by measure category (a–j) to the findings view | Python, Jinja2 | Medium |

---

## CITADEL — Go

The governance engine. Requires reading the MARSHAL and WORM specs in `citadel/docs/` (`marshal-engine.md` and `worm-log.md`).

| Area | Task | Skills | Difficulty |
|------|------|--------|-----------|
| Tests | Add unit tests for `vigil/deep.go` — chain break detection | Go, testing | Medium |
| Tests | Add tests for the `augur` advisory rules AUG-006 through AUG-009 | Go | Medium |
| Docs | Write a connector integration guide (how to send HMAC-SHA256 signed events) | Markdown | Easy |
| Config | Add env-var documentation to the sample `config.yaml` | YAML | Easy |
| API | Add pagination to `GET /api/v1/worm/entries` | Go | Medium |

---

## vantage-hash — Rust

The TripleHash crate. Isolated and self-contained — ideal for Rust newcomers.

| Area | Task | Skills | Difficulty |
|------|------|--------|-----------|
| Tests | Property-based fuzz: verify that `from_hex(hash.hex()) == hash` for all inputs | Rust, proptest | Easy |
| Feature | Add `TripleHash::compute_stream` for hashing large files without loading them fully | Rust, async | Medium |
| Docs | Add a doc-test showing how to extract the SHA-256 component for use with a legacy system | Rust | Easy |
| Bench | Compare TripleHash throughput against standalone SHA-256 and publish the ratio | Rust, criterion | Easy |

---

## SDK — Go / Python / Rust

Three languages, mostly adding coverage and polish.

| Area | Task | Skills | Difficulty |
|------|------|--------|-----------|
| Go SDK | Add retry with exponential backoff to the APIGuard client | Go | Medium |
| Go SDK | Add a mock server helper for tests that don't need a real APIGuard instance | Go | Medium |
| Python SDK | Add async variants of all client methods using `asyncio` | Python | Medium |
| Python SDK | Publish the package to PyPI (draft the release workflow) | Python, CI | Easy |
| Rust SDK | Add integration tests against the mockoon mock server | Rust, testing | Medium |

---

## Documentation — Any background

No coding required.

| Task | Skills | Difficulty |
|------|--------|-----------|
| Translate the APIGuard README into Albanian | Albanian, Markdown | Easy |
| Translate the NIS2 Compass quickstart into German | German, Markdown | Easy |
| Write a "how CITADEL MARSHAL works" explainer blog post (to go in `docs/blog/`) | Technical writing | Medium |
| Review the architecture diagrams in `ARCHITECTURE.md` for accuracy | Security knowledge | Easy |
| Add missing alt-text to all images in the docs | Markdown | Easy |

---

## How issues are labelled on GitHub

| Label | Meaning |
|-------|---------|
| `good first issue` | Suitable for new contributors |
| `help wanted` | Maintainers actively want someone to pick this up |
| `mentor available` | A maintainer has offered to pair on this |
| `platform: apiguard` | Scoped to APIGuard |
| `platform: citadel` | Scoped to CITADEL |
| `platform: nis2compass` | Scoped to NIS2 Compass |
| `lang: go` / `lang: rust` / `lang: python` | Primary language |

Filter GitHub Issues by `good first issue + help wanted` to find the highest-priority entry points.
