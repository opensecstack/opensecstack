# OpenScrub Configuration

> Status: v1.0.0. All env vars consumed by the API process and the
> loader. The dashboard's runtime config is set at build time via Vite
> env vars (`VITE_*`).
>
> **Source of truth** for the API: [`internal/config/config.go`](../internal/config/config.go).
> If this page disagrees with the code, the code wins — please file a docs bug.

## API process (`openscrub-api`)

The table below lists every variable read by `config.FromEnv()`. "Required" means
either the docker-compose `${VAR:?…}` guard refuses to start without it, or the
runtime [`Config.Validate`](../internal/config/config.go) refuses to boot a
non-dev process. Variables grouped by domain.

### Server

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENSCRUB_HTTP_ADDR` | string (host:port) | `:8087` | no | REST API bind address. |
| `OPENSCRUB_LOG_LEVEL` | string | `info` | no | `trace` / `debug` / `info` / `warn` / `error`. **Read directly by the zerolog initialiser at startup, not by `config.FromEnv`** — that's why it does not appear on the `Config` struct. Treat it like `RUST_LOG` for the dataplane: a logger-only knob. |
| `OPENSCRUB_NODE` | string | OS hostname (fallback `openscrub-edge`) | no | Node identifier embedded in CITADEL evidence so events from different edges are distinguishable. |
| `OPENSCRUB_DEV_MODE` | bool (`1`/`true`/`yes`/`on`) | `false` | no | Relaxes `Validate()` (allows the build-time pepper). Never enable in production. |

> **Prometheus exposition** is served on the main HTTP port at
> `/api/v1/metrics` and is **JWT-gated**. There is no separate metrics
> listener — the previous `OPENSCRUB_METRICS_BIND` env var has been
> removed. Provision a long-lived "readonly" JWT and load it into the
> scraper via `authorization.credentials_file` (see
> [../deploy/prometheus.yml](../deploy/prometheus.yml)).

### Database

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENSCRUB_DB_URL` | string (pgx URL) | empty (in-memory store, dev only) | yes for prod | Postgres connection string. Empty selects the in-memory store; never use that in production. |
| `OPENSCRUB_DB_MAX_CONNS` | int (>0) | `16` | no | Caps the `pgxpool` size. Tune alongside Postgres `max_connections`. |

### Auth (JWT verifier + login issuer)

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENSCRUB_JWT_SECRET` | CSV of strings | empty (dev mode tolerates) | yes for prod | HS256 secret(s). Comma-separated for rotation: `primary,next,previous`. ≥32 random bytes per slot. |
| `OPENSCRUB_JWT_ISSUER` | string | `openscrub` | no | Expected `iss` claim. |
| `OPENSCRUB_TOKEN_TTL` | duration (Go syntax: `1h`, `15m`) | `1h` | no | Access-token lifetime issued by `/api/v1/auth/login`. |
| `OPENSCRUB_USERS` | CSV of `user:role:sha256hex` | empty | yes if you want `/auth/login` enabled (compose requires it) | Login issuer credential list, parsed by `auth.NewCredentialStore`. Empty disables the login endpoint (operators mint JWTs out-of-band against `OPENSCRUB_JWT_SECRET`). |
| `OPENSCRUB_PASSWORD_PEPPER` | string | build-time placeholder `openscrub-default-pepper-CHANGE-ME` | yes when `OPENSCRUB_USERS` is set and `DEV_MODE=false` | Mixed into every login hash. `Validate()` refuses to boot if this is the placeholder while `OPENSCRUB_USERS` is set and `OPENSCRUB_DEV_MODE` is unset. |

### CITADEL evidence emitter

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENSCRUB_CITADEL_API_URL` | string (URL) | empty | no | CITADEL base URL. Empty disables evidence emission. |
| `OPENSCRUB_CITADEL_HMAC_SECRET` | string | empty | no | Legacy single HMAC-SHA256 key. Superseded by `_HMAC_SECRETS` when both are set. |
| `OPENSCRUB_CITADEL_HMAC_SECRETS` | CSV of strings | empty | no | 3-slot rotation list `primary,next,previous`. Mirrors the JWT rotation convention. Takes precedence over the singular form. |
| `OPENSCRUB_CITADEL_KEY_ID` | string | empty | no | Legacy single key id, paired with `_HMAC_SECRET`. |
| `OPENSCRUB_CITADEL_KEY_IDS` | CSV of strings | empty | no | Key id list aligned by index with `_HMAC_SECRETS[i]`. |
| `OPENSCRUB_CITADEL_DRY_RUN` | bool | `false` | no | When true, evidence is built and signed but not POSTed; useful for first-deploy smoke tests. |
| `OPENSCRUB_CITADEL_PROJECT_ID` | string | `openscrub` | no | `project_id` field on every `POST /api/v1/worm/emit` call and the Kerkese `ProjectID` on governed (MARSHAL-evaluated) manual rule-creation requests. See [citadel-integration.md](citadel-integration.md). |
| `OPENSCRUB_CITADEL_SOURCE` | string | `openscrub` | no | **Currently dead / not wired to code.** Set in `docker-compose.yml` and `.env.example`, but `config.FromEnv` does not read it and the CITADEL client hardcodes `"source": "openscrub"` literally in `internal/citadel/client.go`'s `wrapWORMEmit`. Changing this env var has no effect today. |
| `OPENSCRUB_MITIGATION_MIN_DURATION` | duration | `5s` | no | Minimum closed-window duration before a mitigation row is forwarded to CITADEL. Filters out flap noise. |

### ThreatFlow IOC puller

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENSCRUB_THREATFLOW_API_URL` | string (URL) | empty | no | ThreatFlow base URL. Empty disables IOC pull. |
| `OPENSCRUB_THREATFLOW_TOKEN` | string | empty | no | Bearer token for ThreatFlow. |
| `OPENSCRUB_THREATFLOW_INTERVAL` | duration | `15m` | no | Pull cadence. |

### Dataplane transport

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENSCRUB_DATAPLANE_TRANSPORT` | string (`noop` / `uds`) | `noop` | yes for prod (Helm sets `uds`) | Dataplane RPC transport. `noop` is a no-op stub for dev; `uds` connects to the Rust loader over the Unix socket. |
| `OPENSCRUB_DATAPLANE_SOCKET` | string (path) | `/run/openscrub/dataplane.sock` | no | Unix-socket path. Must match the loader's `--ipc-socket`. |

## Loader process (compose service `openscrub-dataplane`, binary `openscrub-loader`)

The Rust loader is configured via **CLI flags**, not env vars (see
[`rust/dataplane/src/main.rs`](../rust/dataplane/src/main.rs)). The
table below lists every flag.

| Flag | Default | Description |
|---|---|---|
| `--iface` | (required) | NIC name to attach XDP to (`eth0`, `ens3`, `lo`). |
| `--mode` | `driver` | `driver` (production), `skb` (generic / Docker-Desktop), `hardware` (NIC-offload). |
| `--bpf-object` | compile-time `DEFAULT_BPF_OBJECT_PATH` | Path to the compiled BPF object. |
| `--stats-interval-secs` | `10` | Stats log cadence (`0` disables). |
| `--ipc-socket` | `/run/openscrub/dataplane.sock` | Unix socket the IPC RPC server binds. The Go control plane connects here. Empty disables the server (loader-only smoke runs). |

The deploy unit files / Helm chart wrap these flags around the values
passed by operators; the env vars `OPENSCRUB_IFACE`, `OPENSCRUB_XDP_MODE`,
`OPENSCRUB_BPF_PIN_DIR`, and `OPENSCRUB_LOG_LEVEL` you may see in
[`.env.example`](../.env.example) are read by the wrapper scripts under
[`deploy/`](../deploy/) and translated into the CLI flags above. The
loader binary itself does not read the environment beyond `RUST_LOG`
(via `tracing_subscriber`'s `EnvFilter`).

## Dashboard build-time (`web/`)

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | empty (same-origin) | Override only if the SPA is served from a different origin than the API. The Vite dev server proxies `/api` → `http://localhost:8087` automatically; in prod nginx fronts both. |
| `VITE_DEFAULT_LOCALE` | `sq` | `sq` or `en`. |

## Sample `.env`

See [.env.example](../.env.example) at the module root.

## Secrets handling

- **No silent defaults.** Both docker-compose and Helm fail-closed if
  the operator has not provided values. The compose file uses
  `${VAR:?…}` so unset vars stop the stack at parse time. The Helm
  chart refuses to render unless either `secrets.existingSecret` is
  set, or `secrets.generateOnInstall` is explicitly `true` (the
  default for first-install convenience). The single exception is
  `OPENSCRUB_PASSWORD_PEPPER`: a build-time placeholder
  (`openscrub-default-pepper-CHANGE-ME`) lets a fresh `make compose-up`
  boot, but `Config.Validate` refuses to keep running with that value
  unless `OPENSCRUB_DEV_MODE=1` or `OPENSCRUB_USERS` is empty.
- **Helm**: secrets live in a `Secret` referenced by name. Either
  pre-create one (recommended for prod, set
  `secrets.existingSecret=<name>`) with keys `jwtSecret`,
  `postgresPassword`, `threatflowToken`, `citadelHmacSecret`, or let
  the chart generate one on first install (`generateOnInstall=true`).
  Generated Secrets are annotated `helm.sh/resource-policy: keep`,
  so `helm upgrade` will not rotate them; rotate by deleting the
  Secret manually and reinstalling, or by external rotation that
  patches the Secret in place.
- **docker-compose**: every secret is read from `.env` via
  `${VAR:?explanation}`. Generate with `openssl rand -base64 32`.
- Never commit a real `.env`. The repo `.gitignore` excludes it.
- Rotate `OPENSCRUB_JWT_SECRET` to invalidate all active sessions.
