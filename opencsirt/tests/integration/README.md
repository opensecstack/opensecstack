# OpenCSIRT integration tests

Two harnesses:

- `run.sh` — bash harness. Brings up `deploy/docker-compose.yml`,
  drafts → publishes an advisory through the API, and asserts CITADEL
  emit (queue depth drains to 0).
- `api_contract_test.go` — Go contract tests against a running stack
  (build tag `//go:build integration`). Health shape, login response
  shape (incl. `sub`), constituency lifecycle, validation refusals.

## Run shell harness

```bash
bash tests/integration/run.sh
```

## Run Go contract tests

```bash
# stack must already be up at $OPENCSIRT_API_BASE
go test -tags=integration ./tests/integration/...
```

## Env

| Var | Default | Use |
|---|---|---|
| `OPENCSIRT_API_BASE` | `http://localhost:8088` | API base URL |
| `OPENCSIRT_TEST_USER` | `operator-csirt` | Login user |
| `OPENCSIRT_TEST_PASS` | `operatorpw` | Login password |
| `KEEP_STACK` | `0` | Set `1` to skip teardown after `run.sh` |
