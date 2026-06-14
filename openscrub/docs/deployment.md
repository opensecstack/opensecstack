# OpenScrub Deployment

> v1.0.0. Two supported topologies: Docker Compose (single host, dev
> + small edge sites) and Helm/Kubernetes (production, DaemonSet
> loader on edge nodes).

## Kernel requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| Linux kernel | 5.15 | 6.1 LTS or newer |
| BPF features | `CAP_BPF` (kernel ≥5.8) | CO-RE BTF |
| XDP attach mode | `skb` (generic) | `drv` (driver, line-rate) |
| NIC driver | any with XDP-skb support | `mlx5`, `i40e`, `ixgbe`, `bnxt`, `ena` for `drv` mode |

`drv` (driver) mode delivers near line-rate drops; `skb` (generic)
mode works on any NIC but adds a per-packet overhead of ~150 ns.
`hw` (hardware-offload) mode is opt-in and supported only on a
narrow set of NICs.

## Required Linux capabilities (loader)

The loader process needs these effective capabilities:

- `CAP_BPF` — load BPF programs and create maps (kernel ≥5.8).
- `CAP_NET_ADMIN` — attach XDP to a NIC.
- `CAP_SYS_RESOURCE` — raise the `RLIMIT_MEMLOCK` for older kernels.

On kernel <5.8, replace `CAP_BPF` with `CAP_SYS_ADMIN`. Avoid this if
possible — it is a much larger privilege grant.

In Kubernetes the loader runs as a DaemonSet with **`privileged: false`**,
an explicit capability set (`CAP_BPF`, `CAP_NET_ADMIN`,
`CAP_SYS_RESOURCE` added on top of `drop: [ALL]`),
`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
and `hostNetwork: true` (required because XDP attaches to a host
NIC, not the pod veth). It is scheduled onto edge nodes via the
`openscrub.opensecstack.org/edge=true` node label. `privileged: true`
is deliberately avoided because it would also disable seccomp and
AppArmor — see [security/security-checklist.md § Capabilities &
privilege](security/security-checklist.md) and
[security/threat-model.md](security/threat-model.md) #4.

## Required sysctls

Set on every node that runs the loader:

```
net.core.bpf_jit_enable=1
kernel.unprivileged_bpf_disabled=1   # belt-and-braces
net.core.devconf_inherit_init_net=1
```

`unprivileged_bpf_disabled=1` is part of the threat-model mitigation
for kernel attack surface — see [security/threat-model.md](security/threat-model.md).

## Filesystem mounts (loader)

| Path | Mount | Purpose |
|---|---|---|
| `/sys/fs/bpf` | `bpffs` | Pin maps so they persist across loader restarts. |
| `/run/openscrub` | `tmpfs` or hostPath | Holds the Unix control socket. Mode `0770`, group `openscrub`. |

## Docker Compose (single host)

```bash
cp .env.example .env
# Edit OPENSCRUB_IFACE, OPENSCRUB_JWT_SECRET, etc.

docker compose -f deploy/docker-compose.yml up -d

curl http://localhost:8087/api/v1/health
```

For dev on macOS / Windows, set `OPENSCRUB_XDP_MODE=skb` (the loader
will warn that XDP is non-functional on Docker-Desktop kernels but
the API + dashboard still come up for UI development).

## Helm / Kubernetes

```bash
helm install openscrub deploy/helm/openscrub \
  --namespace openscrub --create-namespace \
  --set env.jwtSecret="$(openssl rand -base64 32)" \
  --set env.threatflowApiUrl="https://threatflow.internal" \
  --set env.threatflowToken="…" \
  --set env.citadelApiUrl="https://citadel.internal" \
  --set env.citadelHmacSecret="…"
```

Label the edge nodes that should run the loader:

```bash
kubectl label node <edge-node> openscrub.opensecstack.org/edge=true
```

The loader DaemonSet is the only workload that holds Linux
capabilities (`CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_RESOURCE`); it
still runs with `privileged: false`. The API, dashboard, and
Postgres run unprivileged with no caps.

## Verification

```bash
# 1. health
curl http://<api>:8087/api/v1/health
# {"status":"ok","db":"ok","loader":"ok","version":"1.0.0"}

# 2. login
TOKEN=$(curl -s -X POST http://<api>:8087/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"operator","password":"…"}' | jq -r .access_token)

# 3. add a test rule
curl -X POST http://<api>:8087/api/v1/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cidr":"192.0.2.1/32","type":"block","ttl_seconds":60}'

# 4. send a packet from 192.0.2.1 (or simulate via hping3) and confirm
#    /api/v1/mitigations shows it.
```

End-to-end test: [tests/integration/run.sh](../tests/integration/run.sh).

## Upgrades

- API and dashboard: rolling Deployment update is safe.
- Loader: in-place pod replacement detaches the XDP program for
  roughly 1–3 seconds. For zero-gap upgrades, drain one node at a
  time; new loader replays rule state from Postgres on start.
- Postgres: standard `pg_dump` / restore. Migrations run by the API
  on boot (see `internal/db/migrations/`).
