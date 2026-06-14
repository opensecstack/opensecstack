# MITRE ATT&CK Coverage

SecureLab maps every scenario to one or more MITRE ATT&CK techniques
and sub-techniques, then tracks whether those techniques have been
**validated** — meaning a live execution produced a `detected` verdict
from at least one connected detection platform.

## Coverage model

Coverage is computed, not asserted. There are four coverage states:

| Status | Meaning |
|---|---|
| `no_scenario` | No scenario exists in the library for this technique. |
| `scenario_exists` | At least one scenario covers this technique, but no live execution has been run. |
| `executed` | A live execution completed, but the detection verdict was `not_detected` or `inconclusive`. |
| `validated` | A live execution completed with `detected` verdict from at least one configured detection platform. |

Only `validated` techniques count toward the coverage percentage
shown in the dashboard and emitted to CITADEL.

**Why this matters:** An organisation claiming "we cover T1059.001"
because a rule exists in their SIEM is different from one that can
show: "SecureLab ran T1059.001-powershell-encoded on 2027-11-01,
OpenScrub fired DETECT-PS-ENCODED-001 within 23 seconds, evidence
sealed in CITADEL at event ID citadel-evt-12345." The latter is
audit-grade. The former is not.

## ATT&CK matrix view

The ATT&CK coverage heatmap in the dashboard renders coverage state
as a colour-coded grid aligned to the ATT&CK matrix tactics:

| Colour | Coverage state |
|---|---|
| Grey | `no_scenario` |
| Blue | `scenario_exists` |
| Yellow | `executed` (not yet detected) |
| Green | `validated` (detected + evidence sealed) |

The heatmap is backed by the `/api/v1/coverage` endpoint, which
computes state from the `executions` and `detection_events` tables
in real time.

## ATT&CK Navigator layer export

SecureLab can export the current coverage state as an ATT&CK Navigator
layer JSON file:

```bash
curl http://localhost:8087/api/v1/coverage/navigator-layer \
     -H "Authorization: Bearer <token>" \
     -o securelab-coverage.json
```

Import this file into the ATT&CK Navigator
(`https://mitre-attack.github.io/attack-navigator/`) to render the
coverage heatmap in the official ATT&CK UI. Useful for sharing
coverage status with stakeholders outside the SecureLab dashboard.

## Initial technique coverage (v0.1.0)

The initial attack library targets 8 high-priority ATT&CK techniques.
Selection criteria: prevalence in threat intelligence from ThreatFlow
(as of 2027 Q3) and detection coverage in OpenScrub + APIGuard default
rule sets.

| Technique ID | Name | Tactic | Library status | Scenarios |
|---|---|---|:-:|:-:|
| **T1059.001** | Command and Scripting Interpreter: PowerShell | Execution | Planned | 2 |
| **T1059.003** | Command and Scripting Interpreter: Windows Command Shell | Execution | Planned | 1 |
| **T1078** | Valid Accounts | Defense Evasion, Persistence | Planned | 2 |
| **T1110.001** | Brute Force: Password Guessing | Credential Access | Planned | 1 |
| **T1190** | Exploit Public-Facing Application | Initial Access | Planned | 2 |
| **T1566.001** | Phishing: Spearphishing Attachment | Initial Access | Planned | 1 |
| **T1071.001** | Application Layer Protocol: Web Protocols | Command and Control | Planned | 1 |
| **T1036.005** | Masquerading: Match Legitimate Name or Location | Defense Evasion | Planned | 1 |

**v1.0.0 target:** ≥ 20 techniques with validated detection
assertions across the full kill chain.

## How technique mapping works

Each scenario declares its ATT&CK mapping in the `mitre` field of
the YAML. The MITRE mapper (`securelab/mitre_mapper/`) reads all
loaded scenarios at startup and builds an in-memory index:

```
technique_id → [scenario_slug, ...]
```

At query time (`GET /api/v1/coverage/{technique_id}`), the mapper
joins the scenario index against the `executions` and
`detection_events` tables to compute the current coverage state.

### Coverage computation rules

1. If no scenario maps to the technique: `no_scenario`.
2. If at least one scenario maps and no live execution exists:
   `scenario_exists`.
3. If at least one live execution exists and all detection verdicts
   are `not_detected` or `inconclusive`: `executed`.
4. If at least one live execution has a `detected` verdict from at
   least one source: `validated`.

Coverage percentage = (`validated` count) / (all techniques in
ATT&CK matrix) × 100. The denominator is the full ATT&CK matrix
for the configured version (default: v15), not just techniques with
scenarios — this gives an honest coverage picture.

## Sub-technique handling

ATT&CK sub-techniques (e.g. T1059.001 = PowerShell) are tracked
separately from their parent technique (T1059 = Command and Scripting
Interpreter). A scenario may map to a sub-technique, the parent, or
both.

Coverage reporting by default shows sub-technique granularity.
The Navigator layer export rolls sub-techniques up to the parent
for display purposes (following ATT&CK Navigator convention).

## Tactic coverage summary

The `/api/v1/coverage` endpoint returns per-tactic rollup:

```json
{
  "tactics": {
    "initial-access": {
      "total_techniques": 9,
      "scenarios_exist": 2,
      "validated": 1,
      "coverage_pct": 11.1
    },
    "execution": {
      "total_techniques": 12,
      "scenarios_exist": 3,
      "validated": 2,
      "coverage_pct": 16.7
    }
  }
}
```

## Coverage decay

Coverage status can **regress**. A technique that was `validated` at
the last execution may become `executed` if a subsequent execution
produces `not_detected`. This regression is surfaced in the dashboard
and in the CITADEL event as `detection_verdict: not_detected`.

Detection decay is a first-class concept in SecureLab. The operator
handbook ([docs/operator-handbook.md](operator-handbook.md))
describes how to schedule regular re-validation executions and how
to triage decay events.

## Mapping scenarios to the kill chain

When authoring a multi-technique campaign (a scenario with steps
that span multiple tactics), each step maps to its own technique.
The scenario itself maps to the primary technique; steps that touch
additional techniques are annotated in the step's `mitre_additional`
field:

```yaml
steps:
  - index: 1
    name: phishing-link-click
    primitive: http-link-fetch
    description: "Simulate user clicking a phishing link"
    mitre_additional:
      - technique: T1566.002
        tactic: initial-access

  - index: 2
    name: dropper-execution
    primitive: powershell-encoded-command
    description: "Execute dropper payload via PowerShell"
    # primary technique from scenario-level mitre field
```

## Related

- [docs/api.md](api.md) — `/api/v1/coverage` endpoint reference
- [docs/scenario-authoring.md](scenario-authoring.md) — `mitre` field in YAML
- [docs/operator-handbook.md](operator-handbook.md) — scheduling re-validation
- [docs/citadel-integration.md](citadel-integration.md) — coverage evidence in CITADEL
