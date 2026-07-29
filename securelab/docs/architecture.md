# SecureLab Architecture

This document describes the SecureLab v1.0.0 architecture as
implemented: a Go 1.22 API backend, a Rust payload-generation crate,
and a React/TypeScript dashboard.

## High-level topology

```
                    ┌──────────────────────────────────┐
                    │    Operator (browser)             │
                    │    React/TypeScript dashboard     │
                    │    :3000 (nginx in production)    │
                    └────────────┬─────────────────────┘
                                 │ HTTPS
                                 ▼
                    ┌──────────────────────────────────┐
                    │    SecureLab API (Go 1.22)        │
                    │    chi router · pgx · zap         │
                    │    :8080                          │
                    │                                  │
                    │    /cmd/securelab/                │
                    │    /internal/scenarios/           │
                    │    /internal/attacks/             │
                    │    /internal/detection/           │
                    │    /internal/citadel/             │
                    └──────┬───────────────────────────┘
                           │
              ┌────────────┼────────────────────┐
              ▼            ▼                    ▼
   ┌────────────────┐ ┌──────────┐  ┌──────────────────────┐
   │ Attack modules │ │PostgreSQL│  │  Detection monitor   │
   │ (Go, native)   │ │:5432     │  │  (polls platforms)   │
   │                │ │          │  │                      │
   │ api / network  │ │runs ·    │  │  → OpenScrub         │
   │ recon / exfil  │ │envs ·    │  │  → APIGuard          │
   │                │ │audit_log │  │  → ThreatFlow        │
   └────────────────┘ └──────────┘  └──────────────────────┘
                                       ┌────────────────────┐
                                       │  CITADEL           │
                                       │  securelab.        │
                                       │  run_completed     │
                                       │  (HMAC-SHA256)     │
                                       └────────────────────┘

  Test environments (--internal Docker network, never reaches prod):

  ┌───────────────────────────────────────────────────────────┐
  │  securelab-test-net  (internal: true — no external route) │
  │                                                           │
  │  ┌─────────────┐         ┌─────────────┐                 │
  │  │ target-api  │         │  target-db  │                 │
  │  │ :9090       │         │  :5432      │                 │
  │  │ (intentional│         │             │                 │
  │  │  OWASP vulns│         │             │                 │
  │  │  for testing│         │             │                 │
  │  └─────────────┘         └─────────────┘                 │
  └───────────────────────────────────────────────────────────┘
```

### Key Go packages

- **chi** (`github.com/go-chi/chi`) — lightweight, idiomatic HTTP router
- **pgx** (`github.com/jackc/pgx/v5`) — PostgreSQL driver with native protocol support
- **zap** (`go.uber.org/zap`) — structured, leveled logging
- **encoding/json** — JSON serialization (standard library)
- **crypto/hmac + crypto/sha256** — CITADEL event signing

### Rust payload-gen crate

`rust/payload-gen` is a standalone Rust library (`payload_gen`, crate-type
`lib`) with its own unit test suite. It is not currently linked into the
live Go API request path — attack modules under `internal/attacks/`
generate their own payloads natively in Go today. The crate exists as
a maintained, independently-tested source of payload-generation
primitives for future reuse:

- `generate_bola_payloads(count)` — sequential IDs and UUIDs
- `generate_jwt_none_token(claims)` — unsigned `alg:none` JWTs
- `generate_mass_assignment_payload(base, extra_fields)` — merged JSON
- `mutate(input, iterations)` — byte-level fuzzing mutations (bit-flip,
  byte substitution, length extension)
- `encoder` module — encoding helpers

## Related

- [README.md](../README.md)
- [ROADMAP.md](../ROADMAP.md)
- [SECURITY.md](../SECURITY.md)
- [docs/deployment.md](deployment.md)
- [docs/scenario-spec.md](scenario-spec.md)
- [docs/citadel-integration.md](citadel-integration.md)
- [docs/mitre-attack-mapping.md](mitre-attack-mapping.md)
- [docs/safety-controls.md](safety-controls.md)
