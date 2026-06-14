# OpenScrub integration tests

Two harnesses:

- `run.sh` — shell harness. Brings up `deploy/docker-compose.yml`,
  creates a rule via the API, fires packets via `hping3`, and asserts
  the drop counter increases.
- `api_contract_test.go` — Go contract tests against a running stack
  (build tag `//go:build integration`). Lifecycle, dangerous-CIDR
  refusal, health.

## Run shell harness

```bash
bash tests/integration/run.sh
```

## Run Go contract tests

```bash
# stack must already be up
go test -tags=integration ./tests/integration/...
```

## Env

| Var | Default | Use |
|---|---|---|
| `OPENSCRUB_API_BASE` | `http://localhost:8087` | API base URL |
| `OPENSCRUB_TEST_USER` | `operator` | Login user |
| `OPENSCRUB_TEST_PASS` | `operator` | Login password |
| `KEEP_STACK` | `0` | Set `1` to skip docker compose teardown after `run.sh` |
