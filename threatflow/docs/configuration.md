# ThreatFlow Configuration

ThreatFlow is configured via environment variables, CLI flags, or a YAML config file. All environment variables use the `THREATFLOW_` prefix.

---

## Environment Variables

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_PORT` | `8091` | HTTP listen port |
| `THREATFLOW_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `THREATFLOW_LOG_FORMAT` | `json` | Log format: `json` or `text` |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_DB_URL` | `postgres://threatflow:threatflow@localhost:5432/threatflow?sslmode=disable` | PostgreSQL connection string |
| `THREATFLOW_DB_MAX_OPEN_CONNS` | `25` | Maximum open database connections |
| `THREATFLOW_DB_MAX_IDLE_CONNS` | `5` | Maximum idle connections in pool |

### CITADEL Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_CITADEL_API_URL` | *(empty — disabled)* | CITADEL base URL (e.g. `http://citadel:8099`) |
| `THREATFLOW_CITADEL_KEY_ID` | | HMAC connector key ID |
| `THREATFLOW_CITADEL_KEY_SECRET` | | HMAC-SHA256 signing secret (**never log**) |
| `THREATFLOW_CITADEL_PROJECT_ID` | `threatflow` | Project identifier for WORM events |

### Feed Configuration (planned)

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_FEED_CONFIG_PATH` | `feeds.yaml` | Path to feed configuration file |
| `THREATFLOW_FEED_DEFAULT_TTL` | `60d` | Default IOC time-to-live |
| `THREATFLOW_FEED_MAX_BATCH` | `1000` | Maximum IOCs per single ingestion batch |

### Redis (planned)

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_REDIS_URL` | `redis://localhost:6379/2` | Redis connection string |

### Authentication (planned)

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_AUTH_JWT_SECRET` | | JWT signing secret for API consumers |
| `THREATFLOW_AUTH_TOKEN_EXPIRY` | `1h` | JWT token expiry duration |

---

## CLI Flags

Flags override environment variables for the `serve` command:

```bash
threatflow serve --port 9091 --log-level debug --log-format text
```

| Flag | Env Equivalent |
|------|---------------|
| `--port` | `THREATFLOW_PORT` |
| `--log-level` | `THREATFLOW_LOG_LEVEL` |
| `--log-format` | `THREATFLOW_LOG_FORMAT` |

---

## Config File (planned)

ThreatFlow will support a YAML config file at `$HOME/.threatflow.yaml` or `./threatflow.yaml`:

```yaml
port: 8091
log_level: info
log_format: json

db:
  url: postgres://threatflow:secret@db:5432/threatflow?sslmode=require
  max_open_conns: 25

citadel:
  api_url: http://citadel:8099
  key_id: tf-connector-key
  key_secret: "${THREATFLOW_CITADEL_KEY_SECRET}"
  project_id: threatflow

feeds:
  - name: alienvault-otx
    type: taxii21
    url: https://otx.alienvault.com/taxii/
    poll_interval: 15m
    confidence_base: 70

  - name: abuse-ch-urlhaus
    type: csv
    url: https://urlhaus.abuse.ch/downloads/csv/
    poll_interval: 1h
    confidence_base: 80
```

---

## Precedence

Configuration values are resolved in this order (highest wins):

1. CLI flags (`--port 9091`)
2. Environment variables (`THREATFLOW_PORT=9091`)
3. Config file (`threatflow.yaml`)
4. Default values (compiled into the binary)

---

## See Also

- [Deployment](deployment.md) — deployment scenarios that require specific configuration
- [CITADEL Integration](citadel-integration.md) — CITADEL-specific config details
- [IOC Feeds](ioc-feeds.md) — feed configuration and polling intervals
- [Security Model](security-model.md) — security-sensitive configuration
- [Troubleshooting](troubleshooting.md) — common misconfiguration issues
