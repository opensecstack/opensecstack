# VertGuard Configuration Reference

Full reference for every `VERTGUARD_*` environment variable. For
production deployment topology, see
[../../docs/deployment-topology.md](../../docs/deployment-topology.md).

VertGuard reads configuration through Viper with `VERTGUARD_` prefix.
Nested keys use `_` separator. Precedence: env vars > YAML file >
hard-coded defaults.

## Server

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_PORT` | `8091` | HTTP port |
| `VERTGUARD_DASHBOARD_PORT` | `3009` | React dashboard port |
| `VERTGUARD_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `VERTGUARD_SERVER_READ_TIMEOUT` | `30s` | HTTP read timeout (generous for large media) |
| `VERTGUARD_SERVER_WRITE_TIMEOUT` | `30s` | HTTP write timeout |

## Database

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_DB_HOST` | `localhost` | PostgreSQL host |
| `VERTGUARD_DB_PORT` | `5438` | PostgreSQL port (VertGuard-specific, avoids conflicts) |
| `VERTGUARD_DB_NAME` | `vertguard` | Database name |
| `VERTGUARD_DB_USER` | `vertguard` | User |
| `VERTGUARD_DB_PASSWORD` | — | **Required** in production |
| `VERTGUARD_DB_SSL_MODE` | `require` | `require` / `verify-full` for prod; `disable` for dev |
| `VERTGUARD_DB_MAX_OPEN_CONNS` | `25` | Pool maximum |

## Auth (inherited ecosystem pattern)

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_AUTH_SECRET` | — | **Required** in prod. HS256 JWT signing key, ≥ 32 random bytes |
| `VERTGUARD_AUTH_TOKEN_TTL` | `8h` | Maximum token lifetime |
| `VERTGUARD_AUTH_ISSUER` | `vertguard` | Expected `iss` claim |
| `VERTGUARD_AUTH_DEV_MODE` | `false` | Forces dev mode even with secret set; **never** true in prod |

## CITADEL integration

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_CITADEL_API_URL` | — | Empty = standalone mode (no WORM, loud warn) |
| `VERTGUARD_CITADEL_KEY_ID` | — | Client key identifier |
| `VERTGUARD_CITADEL_KEY_SECRET` | — | HMAC shared secret |
| `VERTGUARD_CITADEL_PROJECT_ID` | — | Project scope for WORM entries |
| `VERTGUARD_CITADEL_DRY_RUN` | `false` | `true` short-circuits MARSHAL (staging only) |
| `VERTGUARD_CITADEL_QUEUE_MAX` | `10000` | Local queue size when CITADEL unreachable |

Full spec: [citadel-integration.md](citadel-integration.md).

## ThreatFlow integration

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_THREATFLOW_API_URL` | — | Empty = no push; local-only IOC storage |
| `VERTGUARD_THREATFLOW_KEY_ID` | — | |
| `VERTGUARD_THREATFLOW_KEY_SECRET` | — | HMAC shared secret |
| `VERTGUARD_WEBHOOK_THREATFLOW_SECRET` | — | Inbound webhook verification secret |
| `VERTGUARD_THREATFEED_PUSH_INTERVAL` | `15m` | Batched push cadence |
| `VERTGUARD_THREATFEED_RECONCILE_CRON` | `0 4 * * *` | Daily reconciliation |

Full spec: [threatflow-integration.md](threatflow-integration.md).

## Module 3 — Prompt Injection

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_PROMPT_CLEAN_THRESHOLD` | `0.3` | Below → CLEAN |
| `VERTGUARD_PROMPT_BLOCK_THRESHOLD` | `0.7` | At/above → BLOCKED |
| `VERTGUARD_PROMPT_MAX_INPUT_SIZE` | `1048576` | 1 MiB hard limit |
| `VERTGUARD_PROMPT_PATTERN_REGISTRY_PATH` | `/etc/vertguard/patterns/` | Directory with YAML pattern defs |
| `VERTGUARD_PROMPT_CUSTOM_PATTERNS_PATH` | — | Optional custom-patterns YAML |
| `VERTGUARD_PROMPT_NEMO_ENDPOINT` | — | Optional NeMo Guardrails URL |
| `VERTGUARD_PROMPT_LLAMAGUARD_ENDPOINT` | — | Optional Llama Guard URL |

Full spec: [module-3-prompt-injection.md](module-3-prompt-injection.md).

## Module 4 — AI Threat Feed

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_THREATFEED_SOURCES_PATH` | `/etc/vertguard/sources.yaml` | Source-manifest YAML |
| `VERTGUARD_THREATFEED_ATLAS_SYNC_CRON` | `0 0 * * 0` | Weekly Sunday 00:00 UTC |
| `VERTGUARD_THREATFEED_COMMUNITY_SYNC_CRON` | `0 6 * * *` | Daily 06:00 UTC |
| `VERTGUARD_THREATFEED_MIN_CONFIDENCE` | `0.5` | Drop IOCs below this |

## Module 1 — Media Authenticity (C2PA)

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_C2PA_TRUSTSTORE` | `/etc/vertguard/c2pa-truststore` | Directory with trusted root PEMs |
| `VERTGUARD_C2PA_OCSP_ENABLED` | `false` | OCSP certificate status checks |
| `VERTGUARD_MEDIA_MAX_SIZE` | `104857600` | 100 MiB hard limit |
| `VERTGUARD_MEDIA_CONTENT_RETENTION` | `false` | Keep content bytes in DB (privacy concern; default off) |

Full spec: [c2pa-integration.md](c2pa-integration.md).

## Module 2 — AI Phishing (Phase 4.2+)

Stubs in place; meaningful values land with Phase 4.2.

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_PHISHING_ENABLED` | `false` | Phase 4.2 activation flag |
| `VERTGUARD_PHISHING_MODELS_PATH` | `/var/lib/vertguard/models/phishing` | Model directory |
| `VERTGUARD_PHISHING_CLEAN_THRESHOLD` | `0.3` | |
| `VERTGUARD_PHISHING_BLOCK_THRESHOLD` | `0.7` | |

## Module 5 — Synthetic Identity (Phase 4.3+)

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_IDENTITY_ENABLED` | `false` | Phase 4.3 activation flag |
| `VERTGUARD_IDENTITY_REALTIME_ENABLED` | `false` | Per-frame video analysis (GPU required) |

## Python ML service (Phase 4.2+)

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_ML_GRPC_URL` | `localhost:50051` | gRPC side-car endpoint |
| `VERTGUARD_ML_MODELS_PATH` | `/var/lib/vertguard/models/` | Model cache directory |
| `VERTGUARD_ML_GPU_ENABLED` | `false` | Require GPU for inference |
| `VERTGUARD_ML_MAX_BATCH_SIZE` | `16` | Per-request batch size |

## Post-quantum flags (v1.1+)

| Variable | Default | Notes |
|---|---|---|
| `VERTGUARD_PQ_HYBRID_ENABLED` | `false` | Accept hybrid Ed25519+ML-DSA on inbound (v2.0+) |
| `VERTGUARD_PQ_REQUIRE_HYBRID` | `false` | Require hybrid on outbound (v3.0+) |

## Full example — production

```bash
# Server
VERTGUARD_PORT=8091
VERTGUARD_LOG_LEVEL=info

# Database
VERTGUARD_DB_HOST=vertguard-db.internal
VERTGUARD_DB_PASSWORD=***
VERTGUARD_DB_SSL_MODE=verify-full

# Auth
VERTGUARD_AUTH_SECRET=***  # openssl rand -base64 32

# CITADEL
VERTGUARD_CITADEL_API_URL=https://citadel.internal:8099
VERTGUARD_CITADEL_KEY_ID=vertguard-prod
VERTGUARD_CITADEL_KEY_SECRET=***
VERTGUARD_CITADEL_PROJECT_ID=prod

# ThreatFlow
VERTGUARD_THREATFLOW_API_URL=https://threatflow.internal:8084
VERTGUARD_THREATFLOW_KEY_SECRET=***
VERTGUARD_WEBHOOK_THREATFLOW_SECRET=***

# Module tuning
VERTGUARD_PROMPT_BLOCK_THRESHOLD=0.7
VERTGUARD_C2PA_TRUSTSTORE=/etc/vertguard/c2pa-truststore
```

## Full example — dev (docker-compose)

Matches shipped [docker-compose.yml](../docker-compose.yml):

```bash
VERTGUARD_PORT=8091
VERTGUARD_LOG_LEVEL=debug
VERTGUARD_DB_URL=postgres://vertguard:vertguard_dev@localhost:5438/vertguard?sslmode=disable
VERTGUARD_AUTH_SECRET=dev-secret-32-chars-minimum-replace-me
VERTGUARD_CITADEL_API_URL=  # empty = standalone (WARN on startup)
VERTGUARD_THREATFLOW_API_URL=  # empty = local-only
```

## Validation at startup

VertGuard validates on boot:

| Check | Failure action |
|---|---|
| Required fields present in production | Process exits with descriptive error |
| `AUTH_SECRET` ≥ 32 bytes | Refuse to start |
| `C2PA_TRUSTSTORE` readable + contains ≥ 1 PEM | Refuse to start |
| Pattern registry loadable | Refuse to start Module 3 (other modules continue) |
| Model registry checksums verify | Refuse to start Python ML service (Phase 4.2+) |

"Standalone mode" warnings (empty CITADEL_API_URL or
THREATFLOW_API_URL) are **not fatal** but log a loud WARN.

## Related

- [quick-start.md](quick-start.md)
- [api.md](api.md)
- [operator-handbook.md](operator-handbook.md)
- [../../docs/deployment-topology.md](../../docs/deployment-topology.md)
