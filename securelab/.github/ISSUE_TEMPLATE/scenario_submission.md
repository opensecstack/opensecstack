---
name: Community scenario submission
about: Submit a new attack scenario for inclusion in the SecureLab library
title: "[Scenario] <scenario-name>"
labels: scenario-submission, needs-security-review
assignees: ""
---

> **Important**: All scenario submissions require a mandatory security review before merge. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full checklist. Incomplete submissions will not be reviewed.

## Scenario YAML

<!-- Paste the complete scenario YAML below. It must pass `make scenario-validate` locally. -->

```yaml
# Paste scenario YAML here
```

## MITRE ATT&CK technique

**Technique ID**: <!-- e.g. T1078 -->
**Technique name**: <!-- e.g. Valid Accounts -->
**ATT&CK matrix version verified against**: <!-- e.g. v14.1 -->

## Scenario description

<!-- What does this scenario test? What vulnerability or technique does it exercise? -->

## Test evidence

<!-- Show that you have tested this scenario against the built-in test target or a comparable environment. Paste relevant output or screenshots. -->

**Test environment**: <!-- docker-compose.test.yml / custom -->
**Dry-run result**: <!-- paste output of --dry-run execution -->

## Expected detections

<!-- Which detection platforms should detect this scenario? What alert type? -->

| Platform | Expected alert | Detection window |
|---|---|---|
| OpenScrub | | |
| APIGuard | | |
| ThreatFlow | | |

## Safety review checklist

- [ ] Scenario does not reference any live C2 server, external download URL, or third-party infrastructure
- [ ] `mitre_technique_ids` field is present and accurate
- [ ] `timeout` is set and is reasonable
- [ ] No hardcoded credentials, internal hostnames, or organisation-specific references
- [ ] Scenario tested in dry-run mode with no errors
- [ ] If any step has destructive potential, it is documented and flagged appropriately

## Additional context

<!-- Any other relevant information: CVE references, public writeups, similar scenarios, etc. -->
