# Scenario Authoring Guide

> **Security review required.** All scenarios contributed to the
> SecureLab scenario library must pass the security review checklist
> in [CONTRIBUTING.md](../CONTRIBUTING.md) before merge. Do not
> submit a scenario PR without completing that checklist.

A SecureLab scenario is a YAML file that defines a multi-step attack
sequence, its MITRE ATT&CK mapping, target scope constraints, and the
detection assertions that must pass for the scenario to be considered
validated.

## File location and naming

Scenarios live under `scenarios/<tactic>/<slug>.yaml`.

Examples:
```
scenarios/execution/T1059.001-powershell-encoded.yaml
scenarios/persistence/T1547.001-registry-run-key.yaml
scenarios/initial-access/T1566.001-spearphishing-attachment.yaml
```

Naming convention: `{technique-id}-{short-description}.yaml` using
ATT&CK technique notation (uppercase T, dot notation for sub-
techniques, hyphen-separated description in lowercase).

## Schema overview

```yaml
# scenarios/execution/T1059.001-powershell-encoded.yaml

id: T1059.001-powershell-encoded
version: "1.0.0"
title: "PowerShell Encoded Command Execution"
description: |
  Executes a Base64-encoded PowerShell command via cmd.exe as an
  unprivileged user. Tests detection of encoded PowerShell invocation,
  a common defence-evasion pattern combined with T1059.001.

author: securelab-core
reviewed_by: alice@opensecstack.org
review_date: "2027-10-15"

mitre:
  technique: T1059.001
  sub_technique: "PowerShell"
  tactic: execution
  phase: execution

platform:
  - windows

target_scope:
  # Scenarios may only execute against hosts within this CIDR list.
  # This field is validated against SECURELAB_TARGET_CIDR_ALLOWLIST
  # at execution time; execution is rejected if any step targets a
  # host outside this scope.
  cidrs:
    - "192.168.100.0/24"
  description: "Lab Windows endpoints — isolated test network"

steps:
  - index: 1
    name: spawn-cmd
    primitive: cmd-spawn
    description: "Open cmd.exe as the test user"
    target: "192.168.100.10"
    parameters:
      user: testuser
    destructive: false
    rollback: null

  - index: 2
    name: execute-encoded-ps
    primitive: powershell-encoded-command
    description: "Execute Base64-encoded PowerShell command"
    target: "192.168.100.10"
    parameters:
      command: "Get-Process"
      encoding: base64_standard
    destructive: false
    rollback: null
    impact: |
      Runs Get-Process on the target. No file system changes.
      No persistence mechanism. Non-destructive.

  - index: 3
    name: verify-execution
    primitive: process-list-check
    description: "Verify powershell.exe appeared in process list"
    target: "192.168.100.10"
    parameters:
      process_name: "powershell.exe"
    destructive: false
    rollback: null

expected_detections:
  - step: 2
    source: openscrub
    rule_ref: "DETECT-PS-ENCODED-001"
    description: "OpenScrub should fire on encoded PowerShell invocation"
    detection_window_s: 30
    severity: medium

  - step: 2
    source: apiguard
    rule_ref: null
    description: "APIGuard is not expected to detect this step (no API traffic)"
    detection_window_s: 30
    expected_verdict: not_applicable

tags:
  - powershell
  - encoding
  - evasion
  - t1059

references:
  - "https://attack.mitre.org/techniques/T1059/001/"
  - "https://lolbas-project.github.io/lolbas/OtherMSbinaries/Powershell/"

changelog:
  - version: "1.0.0"
    date: "2027-10-15"
    author: alice@opensecstack.org
    notes: "Initial scenario, reviewed and approved."
```

## Field reference

### Top-level fields

| Field | Required | Type | Description |
|---|:-:|---|---|
| `id` | Yes | string | Unique scenario identifier. Must match filename slug. |
| `version` | Yes | semver string | Scenario version. Bump on any change to steps, primitives, or detection assertions. |
| `title` | Yes | string | Short human-readable title. |
| `description` | Yes | string | What the scenario does and why it is relevant. |
| `author` | Yes | string | Original author (username or email). |
| `reviewed_by` | Yes | string | Security reviewer who approved the scenario. |
| `review_date` | Yes | ISO date | Date of security review sign-off. |
| `mitre` | Yes | object | ATT&CK mapping (see below). |
| `platform` | Yes | list | Target platforms: `windows`, `linux`, `macos`. |
| `target_scope` | Yes | object | CIDRs this scenario is permitted to target. |
| `steps` | Yes | list | Ordered execution steps (see below). |
| `expected_detections` | Yes | list | Detection assertions per step. |
| `tags` | No | list | Free-form tags for search. |
| `references` | No | list | URLs to ATT&CK entry, tool documentation, etc. |
| `changelog` | Yes | list | Version history. |

### `mitre` object

| Field | Required | Description |
|---|:-:|---|
| `technique` | Yes | ATT&CK technique ID (e.g. `T1059`). |
| `sub_technique` | No | Sub-technique name (e.g. `PowerShell`). |
| `tactic` | Yes | ATT&CK tactic (e.g. `execution`). |
| `phase` | No | Kill-chain phase label. |

### `steps[*]` object

| Field | Required | Description |
|---|:-:|---|
| `index` | Yes | Execution order (1-based). Must be unique and sequential. |
| `name` | Yes | Step identifier (unique within scenario). |
| `primitive` | Yes | Attack primitive slug from the attack library. |
| `description` | Yes | What this step does. |
| `target` | Yes | Target IP or hostname (must be within `target_scope`). |
| `parameters` | No | Key-value parameters passed to the primitive. |
| `destructive` | Yes | `true` if this step modifies persistent state on the target. |
| `rollback` | Cond. | Required if `destructive: true`. Primitive slug + parameters to restore the target state. |
| `impact` | Yes | Free-text description of what this step does to the target. |

### `expected_detections[*]` object

| Field | Required | Description |
|---|:-:|---|
| `step` | Yes | Step index this detection assertion applies to. |
| `source` | Yes | `openscrub` \| `apiguard` \| `threatflow`. |
| `rule_ref` | No | Detection rule reference in the source platform. |
| `description` | Yes | Why this detection is expected (or not expected). |
| `detection_window_s` | No | Override the default detection window for this assertion. |
| `expected_verdict` | No | Default: `detected`. Set `not_applicable` for sources where no detection is expected. |
| `severity` | No | Expected severity level: `low` \| `medium` \| `high` \| `critical`. |

## Destructive steps and rollback

If a step sets `destructive: true`, a `rollback` primitive must be
provided. The scenario engine executes rollback steps in reverse order
on failure, and can optionally execute rollback after a successful
execution (configurable per run).

```yaml
- index: 3
  name: add-registry-run-key
  primitive: registry-write
  description: "Add persistence via HKCU Run key"
  target: "192.168.100.10"
  parameters:
    hive: HKCU
    path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    name: "SecurelabTest"
    value: "C:\\Temp\\test.exe"
  destructive: true
  rollback:
    primitive: registry-delete
    parameters:
      hive: HKCU
      path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      name: "SecurelabTest"
  impact: |
    Adds a registry Run key that would cause test.exe to execute at
    user login. The rollback deletes this key. The test binary
    (test.exe) is a benign no-op placed in C:\Temp by step 2.
```

## Detection assertions and the `not_applicable` verdict

Not every step produces traffic that every detection platform can
observe. Use `expected_verdict: not_applicable` for combinations where
no detection is expected by design — this makes the intent explicit and
prevents false `not_detected` verdicts from lowering the coverage score.

```yaml
expected_detections:
  - step: 1
    source: apiguard
    rule_ref: null
    description: "Step 1 does not generate API traffic; APIGuard cannot detect it."
    expected_verdict: not_applicable
```

## Validating a scenario locally

```bash
# Validate YAML schema
uv run python -m securelab.cli scenarios validate scenarios/execution/T1059.001-powershell-encoded.yaml

# Dry-run (no payloads dispatched, scope checked)
uv run python -m securelab.cli scenarios dry-run scenarios/execution/T1059.001-powershell-encoded.yaml \
  --target-scope 192.168.100.0/24
```

## Common mistakes

- **Missing `reviewed_by`:** scenarios without a completed review
  field are rejected by the PR pipeline.
- **Overly broad `target_scope`:** `0.0.0.0/0` is rejected at
  validation time. Scope to the minimum necessary CIDR.
- **Destructive step without rollback:** the scenario validator
  rejects scenarios with `destructive: true` and no `rollback`.
- **`expected_detections` is empty:** every scenario must have at
  least one detection assertion. A scenario with no detection
  assertions is not a validation scenario — it is a simulation without
  a pass/fail criterion.

## Related

- [CONTRIBUTING.md § Scenario and payload contributions](../CONTRIBUTING.md)
- [docs/mitre-attack-coverage.md](mitre-attack-coverage.md)
- [docs/api.md](api.md) — scenario CRUD endpoints
- Attack library primitives: `attack_library/*.yaml`
