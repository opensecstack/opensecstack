# ADR-001: YAML Scenario Format

**Status**: Accepted  
**Date**: 2026-05-10  
**Deciders**: SecureLab core team

## Context

SecureLab needs a format for defining attack scenarios. Scenarios must be:
- Authored by security engineers without requiring Go/Rust knowledge
- Version-controlled alongside the platform code
- Validated at CI time before any code runs them
- Readable by non-technical stakeholders (e.g. for compliance review)
- Contributed by the community without requiring platform expertise

## Decision

Use **YAML** as the scenario definition format, stored as `.yaml` files under the `scenarios/` directory tree.

## Alternatives considered

### JSON

- Pro: universally parseable, strict syntax
- Con: no comments (scenarios need inline documentation), verbose, poor readability for non-developers
- Con: editing large JSON files is error-prone (trailing commas, brace matching)

### Go structs (code-as-scenarios)

- Pro: type-safe at compile time, full IDE support
- Con: requires Go knowledge to author or review scenarios
- Con: scenario contribution requires a full Go toolchain setup
- Con: scenarios cannot be reviewed by non-developers (compliance, auditors)
- Con: running a scenario means executing arbitrary Go code — a significant security surface

### TOML

- Pro: readable, comments supported
- Con: less common in the security tooling ecosystem
- Con: array-of-tables syntax is awkward for step sequences
- Con: less tooling support for JSON Schema validation

## Rationale

YAML is the dominant format in security tooling (Sigma rules, Nuclei templates, Ansible playbooks, Kubernetes manifests). Security engineers already know it. It supports inline comments, is readable by non-developers, and has strong JSON Schema validation tooling.

The main drawback of YAML (footguns like implicit type coercion) is mitigated by running all scenario files through a strict JSON Schema validator at CI time and in the `scenario-validate` Makefile target.

## Consequences

- All scenarios live under `scenarios/` as `.yaml` files.
- A JSON Schema is maintained at `schemas/scenario.schema.json`.
- The `go test ./tests/scenarios/...` suite validates all scenario files at CI time.
- Scenario contributors do not need Go or Rust knowledge.
- Scenarios can be reviewed and approved by compliance and legal stakeholders without a development background.
