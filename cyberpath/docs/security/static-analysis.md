## CyberPath Static Analysis

Tool inventory and CI integration for CyberPath's three language
surfaces (Go API, Rust sandbox host, React frontend) plus the
content-quality linter for lesson markdown and lab YAML.

### Environment

| Item | Value |
|---|---|
| Repo root | `c:/Users/User/Workspace/opensecstack/opensecstack/cyberpath` |
| Go toolchain | `go1.24` (per `Dockerfile`, `go.mod`) |
| Rust toolchain | `stable` (lands with v1.0.0; `rust-toolchain.toml`) |
| Node toolchain | `node 20` (per `web/package.json` engines) |
| OS used for run | Windows 11 / Git-Bash |
| Date | 2026-04-26 |

### 1. Go — `gosec`, `govulncheck`, `staticcheck`

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
export PATH="$(go env GOPATH)/bin:$PATH"
```

Run:

```bash
cd c:/Users/User/Workspace/opensecstack/opensecstack/cyberpath
mkdir -p reports

# gosec — JSON for ingestion, severity ≥ medium blocks
gosec -fmt json -out reports/gosec.json -severity medium ./... || true
gosec -fmt text ./...

# govulncheck — vuln DB lookup against go.mod transitive
govulncheck ./...        > reports/govulncheck.txt 2>&1 || true
govulncheck -mode=binary ./bin/cyberpath-server   # release-time

# staticcheck — bug-class linter
staticcheck ./...        > reports/staticcheck.txt 2>&1 || true
```

### 2. Rust (sandbox-host) — `cargo audit`, `cargo geiger`

The sandbox host is the most security-critical Rust crate in the
ecosystem. `cargo geiger` quantifies `unsafe` use; the sandbox host
intentionally uses `unsafe` for wasmtime FFI, so the goal is "no
new `unsafe` outside reviewed paths".

```bash
cargo install cargo-audit --locked
cargo install cargo-geiger --locked

cd c:/Users/User/Workspace/opensecstack/opensecstack/cyberpath/rust

cargo audit                                          | tee ../reports/cargo-audit.txt
cargo audit --json > ../reports/cargo-audit.json     || true
cargo geiger --output-format Json --json --all-targets > ../reports/cargo-geiger.json
cargo geiger                                         | tee ../reports/cargo-geiger.txt
```

PowerShell equivalent:

```powershell
cargo install cargo-audit --locked
cargo install cargo-geiger --locked
Set-Location c:/Users/User/Workspace/opensecstack/opensecstack/cyberpath/rust
cargo audit | Tee-Object ../reports/cargo-audit.txt
cargo geiger --output-format Json --json --all-targets | Out-File -Encoding utf8 ../reports/cargo-geiger.json
```

### 3. React (web/) — `npm audit`, `eslint-plugin-security`

```bash
cd c:/Users/User/Workspace/opensecstack/opensecstack/cyberpath/web

npm ci
npm audit --audit-level=moderate --json > ../reports/npm-audit.json || true
npm audit --audit-level=moderate

# eslint with security plugin
npx eslint --ext .ts,.tsx --config .eslintrc.json src/ \
    --format json --output-file ../reports/eslint.json || true
npx eslint --ext .ts,.tsx --config .eslintrc.json src/
```

Required `.eslintrc.json` excerpt:

```json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended-legacy"],
  "rules": {
    "react/no-danger": "error",
    "no-eval": "error",
    "no-implied-eval": "error"
  }
}
```

### 4. Semgrep — custom CyberPath ruleset

Semgrep is the cross-language linter that enforces house rules.
Custom rules live in `tools/semgrep/`:

| Rule id | Language | What it catches |
|---|---|---|
| `cyberpath.no-raw-sql` | Go | `fmt.Sprintf` / string-concat into a SQL exec call |
| `cyberpath.no-inner-html` | TypeScript / TSX | `dangerouslySetInnerHTML` without an explicit `eslint-disable` and a security-team approver in CODEOWNERS |
| `cyberpath.no-unbounded-egress` | YAML (lab definitions) | `egress_cidrs:` containing `0.0.0.0/0` or `::/0` |
| `cyberpath.no-host-fs` | Rust (sandbox-host) | `wasmtime::component::Linker::func_wrap` registering a function whose body touches `std::fs` |

Run:

```bash
cd c:/Users/User/Workspace/opensecstack/opensecstack/cyberpath
pip install semgrep   # or use the docker image
semgrep --config tools/semgrep/ --error --json --output reports/semgrep.json
semgrep --config tools/semgrep/ --error
```

Failure threshold: `--error` makes any finding non-zero exit. To
introduce an exception, the developer adds an inline
`# nosem: cyberpath.no-raw-sql` comment **with** a security-team
GitHub identity in the same line, and the suppression policy in §7
applies.

### 5. Content-quality linter

Lesson markdown and lab YAML pass through a custom linter (Go
binary, lives in `cmd/content-lint/`). Beyond the semgrep rules
above, it adds:

| Check | Catches |
|---|---|
| `markdown.no-raw-html` | Raw `<script>`, `<iframe>`, inline `on*=` event handlers, raw `<a href="javascript:...">` in any lesson `*.md` |
| `markdown.no-data-uri-script` | `<img src="data:text/html,...">` and similar XSS-shaped data URIs |
| `lab.egress.allowlist-required` | Lab YAML with `egress: allow` but no `egress_cidrs` array |
| `lab.egress.cidr-shape` | `egress_cidrs` entries that are unparseable, or are `0.0.0.0/0` / `::/0` |
| `lab.image.signed` | Lab image reference is digest-pinned (`@sha256:...`) and Cosign-verifiable |
| `lab.fuel-cap` | Lab YAML declares `fuel_limit` and `memory_limit_mb`; defaults applied otherwise |

Run:

```bash
go run ./cmd/content-lint/ -path content/tracks/ -format json > reports/content-lint.json
go run ./cmd/content-lint/ -path content/tracks/
```

The linter is also invoked by `make lint-content` and is wired into
the content-PR template.

### 6. CI integration

All of the above run on every PR and on push to `main`. Workflow
file: `.github/workflows/ci.yml` (the placeholder this document
references; lands with v1.0.0). Skeleton:

```yaml
name: ci
on: [push, pull_request]

jobs:
  go-static:
    name: go static analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.24', cache-dependency-path: cyberpath/go.sum }
      - working-directory: cyberpath
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...
      - uses: securego/gosec@master
        with: { args: '-severity medium ./cyberpath/...' }

  rust-static:
    name: rust static analysis (sandbox-host)
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: cyberpath/rust } }
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-audit cargo-geiger --locked
      - run: cargo audit
      - run: cargo geiger --all-targets

  web-static:
    name: web static analysis
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: cyberpath/web } }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm, cache-dependency-path: cyberpath/web/package-lock.json }
      - run: npm ci
      - run: npm audit --audit-level=moderate
      - run: npx eslint --ext .ts,.tsx src/

  semgrep:
    name: semgrep
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with: { config: cyberpath/tools/semgrep/ }

  content-lint:
    name: content lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.24' }
      - working-directory: cyberpath
        run: go run ./cmd/content-lint/ -path content/tracks/

  fuzz-content-yaml:
    name: fuzz content-yaml parser
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.24' }
      - working-directory: cyberpath
        run: go test -run=^$ -fuzz=FuzzContentYAML -fuzztime=120s ./internal/content/...
```

Failure thresholds:

- `gosec --severity medium`: low-severity findings remain visible
  but non-blocking.
- `govulncheck`: any finding fails the job.
- `cargo audit`: any finding fails the job.
- `cargo geiger`: informational; reviewed in PR but does not block.
- `npm audit --audit-level=moderate`: moderate or higher fails.
- `eslint`: any error fails.
- `semgrep`: any finding fails (`--error`).
- `content-lint`: any finding fails.
- Fuzz: 120 seconds per CI run; longer campaigns are tracked under
  `pre-audit-plan.md` G2.

### 7. Suppression policy

Suppressions are an explicit deviation from the security baseline
and require security-team approval, recorded in code:

| Form | Approval recorded by |
|---|---|
| `// nolint:gosec // <reason>; approved-by:@github-handle` | The handle MUST appear in `CODEOWNERS` for the security team |
| `// nosem: cyberpath.<rule> <reason>; approved-by:@github-handle` | Same |
| ESLint inline `// eslint-disable-next-line security/<rule> -- <reason>; approved-by:@github-handle` | Same |
| `cargo audit --ignore RUSTSEC-XXXX-XXXX` recorded in `audit.toml` | Same; PR description must link to upstream tracking issue |

A PR that adds a suppression without a `approved-by:` handle in the
security-team CODEOWNERS group fails the `semgrep` job (a meta-rule
in `tools/semgrep/cyberpath.suppression-discipline.yaml` enforces
the form).

### 8. Pre-known low-noise patterns

Areas where a human reviewer should mark expected false-positives
ahead of an audit, so reviewers do not re-litigate them:

| Pattern | Location(s) | Decision | Justification |
|---|---|:-:|---|
| `crypto/sha256` used for content + lab-image hashing | `internal/content/loader.go`, `internal/lab/image.go` | accept-with-justification | SHA-256 is the documented integrity primitive |
| `unsafe` blocks in sandbox-host | `rust/sandbox-host/src/host_func/*.rs` | accept-with-justification | wasmtime FFI requires it; bounded set, 2-reviewer rule |
| Async fire-and-forget CITADEL emit | `internal/citadel/client.go` | accept | Documented design — a downed sink must not 5xx the completion |
| `httpServer` without TLS | `internal/api/server.go` | accept | TLS terminated upstream by ingress; documented in `threat-model.md § TB-1` |
| WebSocket upgrade with Bearer token in query | `internal/lab/ws.go` | accept-with-justification | xterm.js cannot set headers on upgrade; token short-lived (5 min) and per-session |

### 9. Reporting format

When findings appear, format each as:

| Tool | Severity | File:line | Finding | Decision | Owner |
|---|---|---|---|---|---|
| (e.g.) gosec G104 | low | `internal/.../foo.go:42` | Errors unhandled | accept-with-justification | maintainer |

Decisions are one of: **fix-now**, **accept-with-justification**,
**false-positive**. Every accept/false-positive carries a one-line
justification visible in CI logs.

### 10. Related

- `security-checklist.md` § 7 dependency hygiene, § 8 frontend
- `pre-audit-plan.md` — fuzz campaign and sandbox-escape suite
- `image-signing.md` — Cosign verification of lab images
- `.github/workflows/ci.yml` (placeholder; lands with v1.0.0)
