# CyberPath Lab Content Guide

> Authoring guide for hands-on labs. Read this alongside
> [./track-content-guide.md](./track-content-guide.md) — labs live
> inside tracks, but the lab YAML schema and the sandbox semantics
> warrant their own document.
>
> Status: design intent. v1.0.0 ships Docker-backed labs; v1.0.0
> introduces the wasmtime sandbox. The schema below targets v1.0.0;
> Docker labs use the same shape with `runtime: docker` and a
> different validation harness.

A CyberPath lab is a sandboxed, time-bounded, validated exercise
that proves a learner can *do* something rather than just recognise
it. The host materialises assets, runs the entry command, the
learner interacts via xterm.js, and on submit the validation engine
deterministically grades the outcome. Labs are content; they ship in
the same repo as track content.

## File layout

```
content/phishing-recognition/labs/
  recognise-spear-phishing/
    lab.yaml
    assets/
      sample-1.eml
      sample-2.eml
      sample-3.eml
      README.sq.md           # learner-facing brief
      README.en.md
    fixtures/                # initial sandbox FS state, packed by host
      .bashrc
```

## Lab YAML schema

```yaml
# content/phishing-recognition/labs/recognise-spear-phishing/lab.yaml
id:      recognise-spear-phishing
version: 1.0.0

# Wasm runtimes available in v1.0.0:
#   wasm-shell    — busybox-like shell (cat, grep, less, head, tail)
#   wasm-python   — CPython 3.12 compiled to wasi-preview1
#   wasm-kubectl  — read-only kubectl against a pre-populated fixture
runtime: wasm-shell

# Image is a pre-built wasm bundle published to the lab-image
# registry; SHA-256 pinned and verified at session start.
image:   "ghcr.io/opensecstack/cyberpath-labs/wasm-shell:1.4.0"

entry_command: "/bin/sh"

assets:
  # Inline file: content packed straight from the lab directory.
  - path:    "/work/sample-1.eml"
    content: "@./assets/sample-1.eml"     # @./ = relative to lab.yaml

  - path:    "/work/sample-2.eml"
    content: "@./assets/sample-2.eml"

  # URL fetch: host downloads at session start, SHA-256 pinned.
  - path:    "/work/large-corpus.tar.gz"
    url:     "https://cdn.example/cyberpath/phishing-corpus-2027.tar.gz"
    sha256:  "8d4f...e21a"

# Validation runs after the learner clicks "Submit". Each rule is
# evaluated in order; a rule's `weight` contributes to the lab score.
validation:
  - id:       found-phishing-1
    type:     file_exists
    target:   "/work/answers/sample-1-classification.txt"
    weight:   1
    diagnostic:
      sq: "Mungon klasifikimi i sample-1."
      en: "Missing classification for sample-1."

  - id:       correct-classification-1
    type:     regex_match
    target:   "/work/answers/sample-1-classification.txt"
    expected: "^phishing$"
    weight:   2
    diagnostic:
      sq: "Sample-1 është phishing — pritej 'phishing'."
      en: "Sample-1 is phishing — expected 'phishing'."

  - id:       grep-suspicious-domain
    type:     cmd_exit
    target:   "grep -q 'paypa1\\.com' /work/answers/notes.txt"
    expected: 0                        # exit code 0 = pass
    weight:   1
    diagnostic:
      sq: "Nuk ke shënuar domain-in e dyshimtë në notes.txt."
      en: "You didn't note the suspicious domain in notes.txt."

success_criteria:
  min_score:        4                  # of 4 weighted points
  required_rules:   [correct-classification-1]   # must pass

time_limit_seconds: 1800               # 30 min hard cap

network:
  egress_whitelist: []                 # default deny-all; explicitly empty
  # For tracks that genuinely need the network (e.g. API security
  # lab), list FQDNs here; the host enforces via the wasmtime
  # network capability layer.

hints:
  - trigger:        idle_seconds:300   # learner idle for 5 minutes
    text:
      sq:  "Provo të kontrollosh fushën 'From:' kundrejt domain-it të pretenduar."
      en:  "Try checking the 'From:' field against the claimed domain."
  - trigger:        failed_validations:2
    text:
      sq:  "Klasifikimi pranohet vetëm si 'phishing' ose 'legitimate'."
      en:  "Classification is accepted only as 'phishing' or 'legitimate'."
```

## Wasm runtime constraints

The wasmtime host enforces the following at lab start; a lab YAML
that violates them is rejected by the linter:

- **No syscalls outside WASI.** All file I/O goes through the host-
  provisioned FS. There is no `/proc`, no raw socket, no fork.
- **Memory cap**: 512 MB default per session. Override via
  `runtime_limits.memory_mb` (max 2048 in v1.0.0).
- **CPU fuel**: wasmtime fuel-metering caps execution at ~30 seconds
  of compute per validation step. A lab that needs more must split
  into checkpoints.
- **Network**: deny-all by default. Egress is by FQDN whitelist
  enforced at the host (DNS resolution + connect intercepted in the
  WASI sockets layer). No raw IP connections.
- **Filesystem**: `/work` is the writable scratch dir; everything
  else is read-only. Asset paths must start with `/work` or `/etc`
  (the latter for fixtures only).
- **Determinism**: `/dev/urandom` is seeded per-session from the
  lab session id. Time is virtualised to the session start. This
  makes labs reproducible for grading.

## Validation engine semantics

When the learner clicks "Submit":

1. The host snapshots the sandbox FS.
2. Each rule under `validation` is evaluated in order against the
   snapshot — `file_exists`, `cmd_exit`, `regex_match` are the
   v1.0.0 primitives.
3. Each rule produces `pass | fail` plus the rule's diagnostic in
   the learner's UI language if it failed.
4. The score is `Σ weight where rule passed`.
5. Pass/fail = `score ≥ success_criteria.min_score AND every rule
   in success_criteria.required_rules passed`.
6. The result, including per-rule diagnostics and the snapshot
   `evidence_hash`, is recorded in the `lab_sessions` table.
7. A passing lab triggers the lesson completion path; a failing lab
   leaves the learner on the lab with diagnostics shown.

Validation is deterministic — same FS snapshot, same result. This
matters for audit replay: an auditor can re-run validation against
the persisted snapshot and reproduce the grade.

### Validation rule types (v1.0.0)

| Type | Purpose | Fields |
|---|---|---|
| `file_exists` | Confirm a path exists in the snapshot | `target` |
| `cmd_exit`    | Run a shell command, check exit code | `target`, `expected` |
| `regex_match` | Run a regex against a file's contents | `target`, `expected` |

`expected` is a literal value for `file_exists` (presence is
implicit) and `cmd_exit` (exit code), and a regex (RE2 syntax) for
`regex_match`. Regexes are anchored unless explicitly opted out — `^...$`
is automatic.

## Hints engine

Hints are nudges, not solutions. They surface when a learner is
likely stuck:

- `idle_seconds:N` — N seconds since last keystroke or terminal output
- `failed_validations:M` — M failed submit attempts in this session
- `elapsed_seconds:N` — N seconds since lab start regardless of
  activity (use sparingly; can interrupt a learner mid-thought)

Each hint fires at most once per session. The order in `hints[]` is
the order they will surface. A hint that gives away the answer is
flagged by review; the convention is to point at the *category* of
thing to check, not the answer.

## Local lab dev

Authors iterate on labs without spinning up the full server:

```bash
# Run the lab locally against a wasmtime host
cyberpath-cli lab run \
  --content ./content/phishing-recognition/labs/recognise-spear-phishing/

# Run validation against a checked-in expected snapshot (regression test)
cyberpath-cli lab validate \
  --content ./content/phishing-recognition/labs/recognise-spear-phishing/ \
  --snapshot ./test-fixtures/passing-attempt/

# Lint the lab YAML
cyberpath-cli lab lint ./content/phishing-recognition/labs/recognise-spear-phishing/
```

The CLI uses the same wasmtime host code as the production runner,
so a lab that works locally works in production (or doesn't, for
the same reason).

## Performance budget

The wasmtime sandbox exists because Docker spinup is slow. Hold the
line:

| Metric | Budget | Measured at |
|---|---|---|
| Cold start (first lab on a fresh pod) | < 5 s | T-shirt-medium pod, p95 |
| Heat-up (subsequent lab on same pod) | < 1 s | T-shirt-medium pod, p95 |
| Validation evaluation                | < 2 s | per-rule p95            |

A lab that exceeds these budgets triggers a CI failure; either the
asset payload shrinks, the entry command becomes lazier, or the lab
is split. The platform-side budget is documented in
[./architecture.md](./architecture.md) and the success metrics in
[../ROADMAP.md](../ROADMAP.md).

## Asset packaging

The host materialises files into the sandbox FS at session start:

- **Inline assets** (`content: "@./..."`) are packed into the lab
  image at build time. Cheap; no network at session start.
- **URL assets** (`url: "..."`) are fetched at session start, SHA-256
  verified, then materialised. Use only when the asset is large
  enough that bundling it inflates every session start.
- **Fixtures** (`fixtures/` directory beside `lab.yaml`) are packed
  as a tarball into `/work` before the entry command runs.

Total assets per lab: soft cap 64 MB, hard cap 256 MB. A lab that
needs more is almost always doing something the wasm sandbox isn't
the right tool for — see Track 8 (Network forensics) discussions
about Firecracker fallback in
[../ROADMAP.md](../ROADMAP.md).

## Real example: 80-line "spot the phishing email" lab

```yaml
# content/phishing-recognition/labs/recognise-spear-phishing/lab.yaml
id:       recognise-spear-phishing
version:  1.0.0
runtime:  wasm-shell
image:    "ghcr.io/opensecstack/cyberpath-labs/wasm-shell:1.4.0"
entry_command: "/bin/sh"

# Three .eml files: one legitimate, two phishing. Learner classifies
# each by writing one line per file into /work/answers/.
assets:
  - path:    "/work/sample-1.eml"
    content: "@./assets/sample-1.eml"
  - path:    "/work/sample-2.eml"
    content: "@./assets/sample-2.eml"
  - path:    "/work/sample-3.eml"
    content: "@./assets/sample-3.eml"
  - path:    "/work/README.md"
    content: "@./assets/README.en.md"

validation:
  - id:        sample-1-classified
    type:      regex_match
    target:    "/work/answers/sample-1.txt"
    expected:  "^(phishing|legitimate)$"
    weight:    1
    diagnostic:
      sq: "Përgjigja e sample-1 duhet të jetë 'phishing' ose 'legitimate'."
      en: "sample-1 answer must be 'phishing' or 'legitimate'."

  - id:        sample-1-correct
    type:      regex_match
    target:    "/work/answers/sample-1.txt"
    expected:  "^phishing$"
    weight:    2
    diagnostic:
      sq: "Sample-1 është phishing."
      en: "Sample-1 is phishing."

  - id:        sample-2-correct
    type:      regex_match
    target:    "/work/answers/sample-2.txt"
    expected:  "^legitimate$"
    weight:    2
    diagnostic:
      sq: "Sample-2 është legjitim."
      en: "Sample-2 is legitimate."

  - id:        sample-3-correct
    type:      regex_match
    target:    "/work/answers/sample-3.txt"
    expected:  "^phishing$"
    weight:    2
    diagnostic:
      sq: "Sample-3 është phishing."
      en: "Sample-3 is phishing."

success_criteria:
  min_score:       6
  required_rules:  [sample-1-correct, sample-2-correct, sample-3-correct]

time_limit_seconds: 1200             # 20 minutes

network:
  egress_whitelist: []

hints:
  - trigger: idle_seconds:240
    text:
      sq: "Krahaso fushën 'From:' me domain-in e organizatës së pretenduar."
      en: "Compare the 'From:' field with the claimed organisation's domain."
  - trigger: failed_validations:2
    text:
      sq: "Shkruaj saktësisht 'phishing' ose 'legitimate' (pa shkronja të mëdha)."
      en: "Write exactly 'phishing' or 'legitimate' (lowercase, no quotes)."
```

## See also

- [./track-content-guide.md](./track-content-guide.md) — track YAML
- [./architecture.md](./architecture.md) — wasm sandbox section
- [./instructor-handbook.md](./instructor-handbook.md) — grading flow
- [./operator-handbook.md](./operator-handbook.md) — sandbox operations
- [../ROADMAP.md](../ROADMAP.md) — sandbox-related success metrics
- [../SECURITY.md](../SECURITY.md) — sandbox-escape disclosure SLA
