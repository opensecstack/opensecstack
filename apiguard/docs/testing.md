# Testing Guide

This document covers how APIGuard tests are organized, how to run them, and how to write new tests.

## Test Philosophy

APIGuard uses a layered testing strategy:

- **Unit tests** validate business logic in isolation. Go services, Rust parsers, and React components each have unit tests co-located with their source.
- **Integration tests** run against real PostgreSQL and Redis instances. Databases are never mocked. Each test creates and destroys its own schema to guarantee isolation.
- **End-to-end tests** exercise the full scan pipeline against intentionally vulnerable API targets (VAmPI, crAPI). These tests parse a spec, generate test cases, execute scans, analyse results, and assert on expected findings.
- **Rust parser tests** rely on fixture files covering valid schemas, malformed YAML, circular references, and oversized documents. Property-based tests supplement fixtures for edge cases.

## Running Tests

| Command | Description |
|---|---|
| `make test` | Run all tests (Go, Rust, E2E). |
| `make test-go` | Go unit and integration tests. |
| `make test-rust` | Rust tests via `cargo-nextest`. |
| `make test-e2e` | End-to-end tests against running test targets. |
| `make test-coverage` | Generate a combined coverage report. |

### Running a Single Test

Go:

```bash
go test -run TestName ./internal/...
```

Rust:

```bash
cargo test test_name
```

Or with nextest:

```bash
cargo nextest run test_name
```

## Go Test Structure

Tests live alongside the source file they cover:

```
internal/scanner/
  scanner.go
  scanner_test.go
internal/report/
  report.go
  report_test.go
```

### Conventions

- **Table-driven tests** are preferred. Define a slice of test cases with named fields and loop over them with `t.Run`.
- **Fixture data** goes in a `testdata/` directory within the package. Go tooling ignores `testdata/` during builds.
- **Integration tests** use the build tag `//go:build integration` on the first line of the file. They are included only when `make test-go` passes `-tags integration` to `go test`.
- **Test helpers** shared across packages live in `internal/testutil/`. This includes database setup, HTTP test servers, and assertion utilities.

Example table-driven test:

```go
func TestSeverityLabel(t *testing.T) {
    tests := []struct {
        name  string
        score float64
        want  string
    }{
        {"critical", 9.5, "CRITICAL"},
        {"high", 7.2, "HIGH"},
        {"zero", 0.0, "NONE"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := SeverityLabel(tt.score)
            if got != tt.want {
                t.Errorf("SeverityLabel(%v) = %q, want %q", tt.score, got, tt.want)
            }
        })
    }
}
```

## Rust Test Structure

### Unit Tests

Unit tests live inside the module they test, gated behind `cfg(test)`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_openapi_spec() {
        let input = include_str!("../../testdata/openapi/petstore-3.0.yaml");
        let result = parse(input);
        assert!(result.is_ok());
    }
}
```

### Integration Tests

Integration tests that span multiple modules live in `rust/tests/`. Each file is compiled as a separate binary.

### Fixtures

Fixture schemas are stored in `rust/testdata/`:

| Path | Contents |
|---|---|
| `rust/testdata/openapi/` | Valid OpenAPI 3.0 and 3.1 specifications. |
| `rust/testdata/swagger/` | Valid Swagger 2.0 specifications. |
| `rust/testdata/malformed/` | Broken YAML, missing required fields, invalid JSON. |
| `rust/testdata/circular/` | Specs with circular `$ref` chains. |
| `rust/testdata/oversized/` | Specs exceeding size limits. |

### Property-Based Tests

The `proptest` crate is used to generate arbitrary inputs for parser edge cases:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn no_panic_on_arbitrary_input(input in "\\PC*") {
        let _ = parse(&input);
    }
}
```

These tests catch panics, stack overflows, and unexpected errors that hand-written fixtures might miss.

## Integration Test Setup

Integration tests require PostgreSQL and Redis. Start them with the test-specific Compose file:

```bash
docker compose -f docker-compose.test.yml up -d
```

Set the database connection string:

```bash
export APIGUARD_TEST_DB_URL="postgres://apiguard:apiguard@localhost:5433/apiguard_test"
```

Then run integration tests:

```bash
make test-go
```

### Isolation Model

- Each test creates a uniquely-prefixed PostgreSQL schema (e.g., `test_a1b2c3_`) at setup and drops it at teardown.
- There is no shared mutable state between tests.
- Tests are safe to run in parallel. `go test -parallel` and `cargo nextest` both execute concurrently by default.

If a test fails and leaves a schema behind, subsequent runs will not be affected. A periodic cleanup job in CI drops orphaned test schemas older than one hour.

## End-to-End Tests

End-to-end tests validate the entire scan pipeline from spec parsing through to the final report.

### Prerequisites

Start the vulnerable test targets:

```bash
make targets-up
```

This launches VAmPI and crAPI in Docker containers. Wait for health checks to pass before running tests.

### Running

```bash
make test-e2e
```

### What Gets Tested

Each E2E test follows this sequence:

1. **Parse** an OpenAPI spec describing the target API.
2. **Generate** test cases from the parsed spec.
3. **Scan** the live target with generated test cases.
4. **Analyse** scan results to produce findings.
5. **Report** findings and assert on expected outcomes.

### Expected Findings

| Target | Expected Finding | Severity |
|---|---|---|
| VAmPI | BOLA (Broken Object Level Authorization) | HIGH |
| VAmPI | Mass assignment | MEDIUM |
| crAPI | Authentication bypass | CRITICAL |
| crAPI | Excessive data exposure | HIGH |

Tests assert on finding count, severity, CVSS score range, and the presence of evidence fields in each finding.

## Writing New OWASP Module Tests

When adding a new OWASP security test module, follow this procedure:

1. **Create a fixture spec.** Add an OpenAPI specification to `tests/integration/` that exercises the vulnerability class your module targets. The spec should describe endpoints present on VAmPI or crAPI. (Note: `testdata/` is for parser unit test fixtures only; integration and E2E test specs belong in `tests/integration/`.)

2. **Write the test.** The test should run your module against the live target and collect findings:

    ```go
    func TestBOLA_VAmPI(t *testing.T) {
        if testing.Short() {
            t.Skip("skipping E2E test in short mode")
        }

        spec := loadSpec(t, "tests/integration/vampi-openapi.yaml")
        findings, err := modules.RunBOLA(spec, "http://localhost:5001")
        require.NoError(t, err)

        assert.GreaterOrEqual(t, len(findings), 1)
        for _, f := range findings {
            assert.Equal(t, "BOLA", f.Category)
            assert.GreaterOrEqual(t, f.CVSS, 5.0)
            assert.LessOrEqual(t, f.CVSS, 9.0)
            assert.NotEmpty(t, f.Evidence)
        }
    }
    ```

3. **Assert on specific outcomes:**
   - **Finding count**: at least one finding for the targeted vulnerability.
   - **Severity**: matches the expected OWASP risk rating.
   - **CVSS range**: score falls within the expected band for the vulnerability class.
   - **Evidence**: each finding includes request/response evidence proving the issue.

4. **Tag the test.** If the test requires a live target, use the `//go:build e2e` build tag so it runs only under `make test-e2e`.

## CI Test Pipeline

GitHub Actions runs the full test suite on every pull request.

### Pipeline Steps

1. **Lint** -- `golangci-lint`, `clippy`, `eslint`.
2. **Unit tests** -- `make test-go` (without `-tags integration`), `make test-rust`.
3. **Integration tests** -- Start PostgreSQL and Redis via Docker services, then run `make test-go` with `-tags integration`.
4. **End-to-end tests** -- Start VAmPI and crAPI, then run `make test-e2e`.
5. **Coverage** -- `make test-coverage` uploads results.

### Coverage Thresholds

| Language | Minimum Coverage |
|---|---|
| Go | 70% |
| Rust | 80% |

The CI job fails if coverage drops below these thresholds. Coverage is measured on non-test code only.

## Test Data and Fixtures

All test fixtures live under `testdata/` directories, either at the repository root or within individual packages.

| Directory | Contents |
|---|---|
| `testdata/openapi/` | Valid OpenAPI 3.0 and 3.1 specifications (Petstore, VAmPI, crAPI). |
| `testdata/swagger/` | Swagger 2.0 specifications for backward-compatibility testing. |
| `testdata/graphql/` | GraphQL schema files for GraphQL endpoint testing. |
| `testdata/malformed/` | Intentionally broken specs: invalid YAML syntax, missing required fields, unsupported versions, truncated files. |

### Guidelines for Adding Fixtures

- Keep fixtures minimal. Include only the paths and components needed for the test.
- Name fixtures descriptively: `petstore-3.0.yaml`, `missing-info-field.yaml`, `circular-ref-chain.json`.
- Do not commit large auto-generated specs. If a test needs a large document, generate it programmatically in the test setup.
- Malformed fixtures should each target a single error condition so test failures are easy to diagnose.
