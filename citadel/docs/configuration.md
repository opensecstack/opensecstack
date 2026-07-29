# CITADEL Configuration Reference

Full reference for every `CITADEL_*` environment variable. For
deployment-flavoured settings, see [deployment.md](./deployment.md).
For how these knobs interact with operations, see
[operator-runbook.md](./operator-runbook.md).

CITADEL reads configuration through Viper. The precedence order is:

1. Environment variables (`CITADEL_*`) — highest
2. Hard-coded defaults (below) — lowest

There is no YAML fallback today; configuration is env-only.

## Env var naming — the doubled prefix

Viper applies `SetEnvPrefix("CITADEL")` which prepends `CITADEL_`.
Nested config keys then expand with an additional segment. So the
`citadel.master_key` key at `CitadelConfig.MasterKey` becomes the env
var **`CITADEL_CITADEL_MASTER_KEY`** — the first `CITADEL_` is the
prefix, the second is the struct namespace.

This is easy to miss. The table below lists the **full env var name**,
not the internal key.

## Server

| Variable | Default | Notes |
|---|---|---|
| `CITADEL_PORT` | `8099` | HTTP port. Matches the port matrix in [../../docs/deployment-topology.md](../../docs/deployment-topology.md). |
| `CITADEL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. Use `debug` temporarily to diagnose; noisy in prod. |

## Database

| Variable | Default | Notes |
|---|---|---|
| `CITADEL_DB_URL` | — | **Required.** Full PostgreSQL connection string, e.g. `postgres://user:pass@host:5432/db?sslmode=require`. |
| `CITADEL_DB_MAX_OPEN_CONNS` | `25` | Pool maximum. Per-replica; tune against `replicas × max × Postgres.max_connections`. |
| `CITADEL_DB_MAX_IDLE_CONNS` | `5` | Idle connections kept warm. |
| `CITADEL_DB_CONN_MAX_LIFETIME` | `5m` | After this, a connection is closed and reopened — limits stale-connection surprises. |

Leaving `CITADEL_DB_URL` empty produces a startup WARN and guaranteed
runtime failure on the first query. There is no in-memory fallback —
CITADEL without a DB is meaningless because the WORM chain is the
product.

Production guidance: use `sslmode=require` at minimum; `verify-full`
when the DB certificate is signed by a known CA. Plain `disable` is
only acceptable on a fully-private network.

## CITADEL core

| Variable | Default | Notes |
|---|---|---|
| `CITADEL_CITADEL_MASTER_KEY` | — | **Required in production.** 64 hex characters = 32-byte Ed25519 private key for anchor signing. Empty → anchor signing disabled with a WARN log. |
| `CITADEL_CITADEL_ANCHOR_INTERVAL` | `100` | Anchor every N WORM entries. See [chain-anchor.md § Configuration](./chain-anchor.md#configuration) for the trade-offs. |
| `CITADEL_CITADEL_GENESIS_HASH` | `b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a15` | Pre-computed SHA-256("CITADEL-GENESIS-SIN-v1"). **Do not change** after the first entry. Changing the genesis invalidates every chain_hash downstream. |
| `CITADEL_CITADEL_SINAUTH_ISSUER_URL` | — | **Required.** sinauth OIDC issuer URL (e.g. `https://auth.sin.to`) that Gate 1/Gate 3 verify Actor/Verifier bearer tokens (`actor_token`/`verifier_token`) against. `NewServer` fetches the OIDC discovery document once at startup and **fails to start** if this is empty, unreachable, or misconfigured — see [ADR-005](../adrs/005-sinauth-identity-bridge.md). |
| `CITADEL_CITADEL_ENFORCE_IDENTITY` | `false` | When `true`, Gate 1 (AuthN) and Gate 3 (NDS) `REFUSE` a Kerkese whose `actor_token`/`verifier_token` is missing, invalid, or doesn't match the claimed `user_id`, instead of only warning. **Off by default** — apiguard's default config and threatflow submit a placeholder Verifier with no `verifier_token`; turning this on unconditionally today would refuse those platforms' default governed actions. See [ADR-006](../adrs/006-split-enforce-identity-and-signatures.md). |
| `CITADEL_CITADEL_ENFORCE_SIGNATURES` | `false` | When `true`, Gate 1 (AuthN) and Gate 3 (NDS) `REFUSE` a Kerkese whose `sig_operator`/`sig_verifier` Ed25519 signature is missing, unregistered, or invalid, instead of only warning. **Off by default** — no producer platform has per-user Ed25519 key custody / signing UX yet. See [ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md). |
| `CITADEL_CITADEL_PERMIFY_URL` | `""` | The Permify instance/schema Gate 2's optional snapshot check reads from — the same instance sinauth's `internal/authz` writes to, not a separate one (see sinauth's `adrs/006-permify-authorization-engine.md`). Empty → the Gate 2 Permify sub-check is a no-op PASS for every role/action, identical to rbacMap-only behavior. |
| `CITADEL_CITADEL_ENFORCE_PERMIFY_AUTHZ` | `false` | When `true`, Gate 2 (AuthZ) `REFUSE`s a Kerkese whose role/action pair the synced Permify snapshot explicitly denies (`known=true, allowed=false`), in addition to the always-enforced `rbacMap` check. **Off by default** (soft-launch) — a known-deny only `WARN`s until this is enabled; an unknown/unsynced role-action pair is always treated as PASS, never REFUSE. See [ADR-007](../adrs/007-permify-gate2-snapshot.md). |
| `CITADEL_CITADEL_PERMIFY_SYNC_INTERVAL` | `5m` | How often `internal/permifysync`'s ticker goroutine refreshes the local `permify_role_action_snapshot` table Gate 2 reads from. Gate 2 never calls Permify live, per-request. See [ADR-007](../adrs/007-permify-gate2-snapshot.md). |

Generate an anchor key:

```bash
openssl genpkey -algorithm ed25519 -outform DER | \
  openssl pkey -inform DER -outform PEM | \
  openssl pkey -in /dev/stdin -text -noout | \
  awk '/priv:/{getline; gsub(/[: ]/,""); print}'
```

Or, for a quick dev key:

```bash
openssl rand -hex 32
```

For production, the key MUST come from a secret manager. Rotation
cadence: quarterly (see [SECURITY.md](../SECURITY.md)).

## Operational flags (v1.1+)

Planned for v1.1, not yet wired. Documented here so authors know not
to set them:

| Variable | Default | Use |
|---|---|---|
| `CITADEL_WORM_READONLY` | `false` | When `true`, MARSHAL evaluates but Gate 5 refuses to append. Used during chain-integrity investigations. See [sop-012-incident.md](./sop-012-incident.md). |
| `CITADEL_DRY_RUN` | `false` | Forces every inbound Kerkese into dry-run mode regardless of the Kerkese's own flag. Staging-only. See [dry-run.md](./dry-run.md). |
| `CITADEL_DRY_RUN_ALLOWED` | `true` | When `false`, Kerkeses with `dry_run: true` are rejected with 400. Production-hardening flag. |

## Full example — production env

```bash
# Server
CITADEL_PORT=8099
CITADEL_LOG_LEVEL=info

# Database
CITADEL_DB_URL=postgres://citadel:***@citadel-db.internal:5432/citadel?sslmode=require
CITADEL_DB_MAX_OPEN_CONNS=25
CITADEL_DB_CONN_MAX_LIFETIME=5m

# Anchor key (from secret manager; never literal here)
CITADEL_CITADEL_MASTER_KEY=a1b2c3...  # 64 hex chars
CITADEL_CITADEL_ANCHOR_INTERVAL=100

# Identity — required; server fails to start without it
CITADEL_CITADEL_SINAUTH_ISSUER_URL=https://auth.sin.to

# Enforcement — both off (soft mode) until product/producer prerequisites
# are met; see ADR-004/005/006. Flip deliberately, not as a default.
CITADEL_CITADEL_ENFORCE_IDENTITY=false
CITADEL_CITADEL_ENFORCE_SIGNATURES=false
```

## Full example — dev env

```bash
# Matches docker-compose.yml
CITADEL_PORT=8099
CITADEL_LOG_LEVEL=debug

CITADEL_DB_URL=postgres://citadel:citadel_secret@localhost:5434/citadel?sslmode=disable
CITADEL_CITADEL_MASTER_KEY=                 # empty OK for dev
CITADEL_CITADEL_ANCHOR_INTERVAL=100

CITADEL_CITADEL_SINAUTH_ISSUER_URL=http://localhost:8100  # local sinauth; required, no fallback
CITADEL_CITADEL_ENFORCE_IDENTITY=false
CITADEL_CITADEL_ENFORCE_SIGNATURES=false
```

## Validation at startup

`config.Load()` itself still does **not** validate required fields — it
emits WARN logs via `WarnIfInsecure()` (for `CITADEL_DB_URL` and
`CITADEL_CITADEL_MASTER_KEY`) and lets the process continue; a missing
`CITADEL_DB_URL` then fails on the first real query, not at startup.

`CITADEL_CITADEL_SINAUTH_ISSUER_URL` is the one exception: `NewServer`
constructs the sinauth verifier during startup and returns an error —
**the process exits** — if the issuer URL is empty, unreachable, or its
OIDC discovery document can't be fetched. This was a deliberate choice in
[ADR-005](../adrs/005-sinauth-identity-bridge.md): an AuthN gate with no
way to verify tokens is a worse failure mode than refusing to start.

Full strict validation of every required field at startup remains a
known gap for the rest of the config surface; v1.1 is the tracked
follow-up. In the meantime, operators must eyeball the startup logs for
`WARNING:` lines for `CITADEL_DB_URL`/`CITADEL_CITADEL_MASTER_KEY`.

## Configuration changes at runtime

CITADEL does not support hot-reload. Changing any env var requires a
process restart. For HA deployments with an active/passive pair:

1. Update config on the standby.
2. Restart standby, verify healthy.
3. Failover (transfer leader lease).
4. Update + restart former primary.

This keeps the chain writable throughout the transition.

## Insecure configuration detection

On startup CITADEL logs `WARNING:` for:

- Empty `CITADEL_DB_URL` (certain failure)
- Empty `CITADEL_CITADEL_MASTER_KEY` (anchor signing disabled)

Scrape these in your observability layer (`structured_log_level == "WARN" AND message STARTS_WITH "WARNING:"`) and alert. A production
process should have zero startup WARNINGs.

## What CITADEL does *not* configure

- **JWT issuance.** CITADEL validates sinauth-issued bearer tokens
  (`actor_token`/`verifier_token`) against `CITADEL_CITADEL_SINAUTH_ISSUER_URL`'s
  JWKS — it does not mint tokens itself. Token issuance is entirely
  sinauth's concern. See [ADR-005](../adrs/005-sinauth-identity-bridge.md).
  The older local `sessions` table this section used to describe was
  dropped in that ADR — nothing in the ecosystem ever wrote to it.
- **Ed25519 signing-key custody.** CITADEL stores registered *public*
  keys (`signing_keys` table) but never generates or holds a private key
  — `citadel keygen` runs entirely on the Operator's/Verifier's own
  machine. See [ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md).
- **Rate limits.** In v1.0.0 CITADEL does not rate-limit at the API
  layer (MARSHAL Gate 4/AUGUR's per-actor frequency check is a
  behavioral heuristic, not an API rate limit). Ingress-level rate
  limits (Envoy, Traefik) are the current control.
- **TLS.** Termination is at the ingress. CITADEL listens on plain
  HTTP by design — put it on a private network behind TLS ingress.

## Related

- [Deployment](./deployment.md) — how these knobs map onto K8s / docker
- [Operator runbook](./operator-runbook.md) — which knobs to touch when
- [SECURITY.md § Key management](../SECURITY.md) — `MASTER_KEY` rotation runbook
- [Troubleshooting](./troubleshooting.md) — what misconfiguration looks like
