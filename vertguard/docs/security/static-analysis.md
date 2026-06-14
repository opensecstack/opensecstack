## VertGuard Static Analysis Report

Tool inventory and findings for `gosec`, `govulncheck`, and
`staticcheck` against the v0.1.0-alpha.0 tree. The companion
`golangci-lint` run is gated by `.github/workflows/ci.yml` job
`go-lint` and is not duplicated here.

### Environment

| Item | Value |
|---|---|
| Repo root | `c:/Users/User/Workspace/opensecstack/opensecstack/vertguard` |
| Go toolchain | `go1.24` (per `Dockerfile:53`, `go.mod`) |
| OS used for run | Windows 11 / Git-Bash |
| Date | 2026-04-26 |

### 1. Tooling installation

The audit-prep environment is sandboxed and does not permit
outbound `go install`. Document the exact retry the auditor (or any
operator with network access) should run:

```bash
# Install (network required)
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install honnef.co/go/tools/cmd/staticcheck@latest

export PATH="$(go env GOPATH)/bin:$PATH"

# Sanity
gosec --version
govulncheck -version
staticcheck -version
```

PowerShell variant:

```powershell
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
$env:PATH = "$(go env GOPATH)\bin;$env:PATH"
```

### 2. Run commands

```bash
cd c:/Users/User/Workspace/opensecstack/opensecstack/vertguard

# gosec — JSON for ingestion, exits non-zero on findings
gosec -fmt json -out reports/gosec.json -severity medium ./... || true
gosec -fmt text ./...        # human-readable to terminal

# govulncheck — DB lookup against go.mod + transitive
govulncheck ./...            > reports/govulncheck.txt 2>&1 || true
govulncheck -mode=binary ./bin/vertguard-server   # release-time

# staticcheck — bug-class linter
staticcheck ./...            > reports/staticcheck.txt 2>&1 || true
```

PowerShell equivalent:

```powershell
New-Item -ItemType Directory -Force reports | Out-Null
gosec -fmt json -out reports/gosec.json -severity medium ./... ; if (-not $?) { }
govulncheck ./... | Tee-Object reports/govulncheck.txt
staticcheck ./... | Tee-Object reports/staticcheck.txt
```

### 3. Outcome in this run

Tool installation was blocked by the sandbox (`go install` requires
network egress; permission denied). No findings produced in this
session. The retry commands above are the day-one ask for the
auditor. CI integration is tracked as gap **7.4 / 7.5** in
`security-checklist.md` and should be added before kick-off.

### 4. Pre-known low-noise patterns (by inspection)

These are areas a human reviewer should mark as expected
false-positives or deliberate trade-offs, so the auditor does not
re-litigate them. None of these block the engagement.

| Pattern | Location(s) | Decision | Justification |
|---|---|:-:|---|
| `crypto/sha256` used for hashing user input | `internal/prompt/scanner.go:151`, `internal/citadel/client.go:213,232` | accept-with-justification | SHA-256 is required by the wire contract (CITADEL HMAC) and is the documented privacy mechanism for prompt input |
| `math/rand` (no `crypto/rand`) | search confirms only `google/uuid` (which uses `crypto/rand` internally) | n/a | — |
| `errcheck`-style unchecked writes on response writer (`_, _ = w.Write(...)`) | `internal/auth/middleware.go:140,153,187` | accept | Response stream may already be closed; explicit discard documents intent |
| Async fire-and-forget audit | `internal/audit/event.go:126-138` | accept | Documented design: a downed sink must not 5xx the request path |
| `httpServer` without TLS | `internal/api/server.go:195-200` | accept | TLS terminated upstream by ingress; documented in `threat-model.md § TB-1` |
| Hand-built JSON error body (`writeUnauthorized`) | `auth/middleware.go:137-188` | accept | Strings are constants; no untrusted interpolation. `jsonEscape` covers the one variable string |
| `strings.LastIndex` IP parsing in rate limiter key | `ratelimit/limiter.go:291-294` | review | Behind `chi/middleware.RealIP`; IPv6 with bracketed port ok. Edge case: bare IPv6 without port retains a `:` — rated low impact (key still uniquely maps) |

### 5. Recommended CI gates (post-fix)

Add to `.github/workflows/ci.yml`:

```yaml
  govulncheck:
    name: govulncheck
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: vertguard
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
          cache-dependency-path: vertguard/go.sum
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - run: govulncheck ./...

  gosec:
    name: gosec
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: vertguard
    steps:
      - uses: actions/checkout@v4
      - uses: securego/gosec@master
        with:
          args: '-severity medium ./...'

  cargo-audit:
    name: cargo-audit
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: vertguard/rust
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-audit --locked
      - run: cargo audit
```

Failure threshold: `gosec --severity medium` (low-severity findings
remain visible but non-blocking). `govulncheck` is exit-on-finding.

### 6. Reporting format for the auditor

When findings appear, format each as:

| Tool | Severity | File:line | Finding | Decision | Owner |
|---|---|---|---|---|---|
| (e.g.) gosec G104 | low | `internal/.../foo.go:42` | Errors unhandled | accept-with-justification | maintainer |

Decisions are one of: **fix-now**, **accept-with-justification**,
**false-positive**. Every accept/false-positive must carry a
one-line justification visible in CI logs.

### 7. Related

- `security-checklist.md` § 7 dependency hygiene
- `pre-audit-plan.md` — T-6 milestone covers CI uplift
