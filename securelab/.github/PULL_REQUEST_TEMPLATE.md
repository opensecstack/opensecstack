## Description

<!-- What does this PR do? Why is this change needed? -->

## Test plan

<!-- How was this tested? What commands were run? -->

- [ ] `make test` passes locally
- [ ] `make lint` passes locally
- [ ] Relevant integration tests run (or explain why not applicable)

## Scenario validation checklist

<!-- Complete if this PR adds or modifies scenario YAML files -->

- [ ] New/modified scenarios pass `make scenario-validate`
- [ ] `mitre_technique_ids` field is present and uses valid ATT&CK technique IDs
- [ ] Scenario `timeout` is set and is reasonable (max 30 minutes)
- [ ] All step `kind` values are valid built-in attack types
- [ ] Scenario does not contain hardcoded credentials or internal hostnames

## Safety controls checklist

<!-- Complete for any PR that touches scenario files, attack modules, or environment configuration -->

- [ ] No production URLs or domain names are referenced in changed files
- [ ] New environments (if any) use `internal: true` Docker networks
- [ ] Rate limits on new attack scenarios do not exceed platform caps
- [ ] CITADEL DRY_RUN is not disabled in any committed configuration

## Security review

<!-- Required for changes to scenarios/, attack modules, Rust payload-gen, or safety controls -->

- [ ] This PR does not require security review (explain why)
- [ ] Security review requested (add `security-review` label and assign a security team member)

## Changelog

<!-- Add a brief entry to CHANGELOG.md [Unreleased] section -->

- [ ] CHANGELOG.md updated
