# OpenScrub FAQ

Conceptual questions about what OpenScrub is, what it isn't, and how
it fits the opensecstack ecosystem. For symptom-driven debugging,
jump to [troubleshooting.md](troubleshooting.md). For getting
started, see [quick-start.md](quick-start.md).

---

## Why XDP, not iptables / nftables?

XDP runs at NIC ingress, *before* the kernel allocates an `skb`. A
drop at XDP costs ~50 ns on commodity hardware in `drv` mode; the
equivalent iptables/nftables drop costs ~µs and pulls the packet
through the full kernel network stack first. Under a flood, that
difference is the difference between dropping at line rate and
collapsing under cache pressure.

The LPM-trie BPF map also gives O(log W) lookup over ~1 M prefixes,
which scales with ThreatFlow's IOC output. iptables's linear chain
match does not.

For the full architectural reasoning see
[architecture.md § Why XDP and not iptables / nftables](architecture.md).

---

## What's the minimum kernel?

**Linux 5.15.** The loader refuses older kernels and exits with a
loud error — see
[troubleshooting.md § "kernel too old"](troubleshooting.md). The
floor is set by the BPF verifier hardening that closes a class of
verifier-bypass attacks; refusing to load is intentional, not
conservative.

The recommended kernel is **6.1 LTS or newer**. Bumping the floor is
an ADR-level decision.

---

## Does it work without `CAP_BPF`?

Only on kernels < 5.8, by substituting `CAP_SYS_ADMIN`. **Don't.**
`CAP_SYS_ADMIN` is a much larger privilege grant and undoes most of
the threat-model containment for the loader process — see
[deployment.md § Required Linux capabilities](deployment.md) and
[security/threat-model.md](security/threat-model.md).

On supported kernels (5.15+) the loader needs `CAP_BPF` +
`CAP_NET_ADMIN` + `CAP_SYS_RESOURCE`, and nothing else. The Compose
file in [deploy/docker-compose.yml](../deploy/docker-compose.yml)
demonstrates the minimum cap set with `cap_drop: ALL` +
`security_opt: no-new-privileges`. The Helm chart matches.

---

## Can I run on AWS / GCP / Azure?

Yes, with caveats:

- **AWS** — `ena` driver supports XDP-drv. EC2 instance types with
  ENA work. SR-IOV-only instances (some older types) fall back to
  XDP-skb mode, slower but functional. EC2 Nitro Enclaves and
  Lambda are not target environments.
- **GCP** — gVE NIC supports XDP-skb only; no driver-XDP. Plan for
  the ~150 ns per-packet overhead that adds.
- **Azure** — accelerated networking (mlx4/mlx5) supports XDP-drv.
  The default Hyper-V synthetic NIC is XDP-skb.

DPDK-style userspace bypass is explicitly **not** supported —
OpenScrub assumes the kernel network stack is the path of record so
the host's regular sockets keep working.

In all three clouds, run loaders on **dedicated edge nodes** rather
than mixing them into application nodes; XDP attach is per-NIC, and
mixing breaks tenancy.

---

## Why not just use AWS Shield / Cloudflare / a commercial scrubber?

You may want to use both. OpenScrub addresses two gaps that
commercial scrubbers don't:

- **Audit-grade evidence.** A commercial scrubber's CSV export is
  not WORM, not signed, and not chained. NIS2 Article 21(2)(c)
  wants documented mitigation evidence; OpenScrub emits signed
  `openscrub.mitigation` events into CITADEL — see
  [citadel-integration.md](citadel-integration.md).
- **On-prem, line-rate L3/L4** for what you can drop locally. The
  CPU cost of an XDP drop is the same regardless of who owns the
  source code; owning the source code matters for review.

OpenScrub is **not** a substitute for upstream BGP-based scrubbing
past NIC capacity. It is the on-prem first line.

---

## How does it integrate with ThreatFlow?

OpenScrub pulls the malicious-IP feed from ThreatFlow on a fixed
interval (`OPENSCRUB_THREATFLOW_INTERVAL`, default 60 s in code,
typically 15 min in production) and reconciles it against existing
`source = 'threatflow'` rules — adds new ones, withdraws ones that
dropped from the feed. There's no human in the loop and no
copy-paste. See
[threatflow-integration.md](threatflow-integration.md).

Set `OPENSCRUB_THREATFLOW_API_URL` empty to disable the puller.

---

## What happens when the ratelimit map fills?

The map cap is **100 000 entries** (compile-time, see
[`ebpf/openscrub.bpf.c`](../ebpf/openscrub.bpf.c)). When the loader
tries to insert into a full map, it returns an error to the API,
which surfaces as `503 dataplane_full` on `POST /api/v1/rules` and
`openscrub_dataplane_op_total{op="add",outcome="full"}` advancing.

Existing rate-limited entries continue to enforce. Operationally,
either lower TTLs to reclaim slots faster, consolidate single-IP
rules into wider blocklist CIDRs, or rebuild the loader with a
larger cap. See
[operator-handbook.md § Ratelimit map full](operator-handbook.md).

---

## Is IPv6 fully supported?

Partially. As of v1.0.0:

- **Blocklist**: yes — `blocklist_v6` LPM-trie is part of the data
  plane (see
  [`rust/dataplane/README.md`](../rust/dataplane/README.md)).
  IPv6 CIDR rules behave identically to IPv4.
- **Ratelimit**: IPv4 only. The `ratelimit` BPF map is keyed on
  IPv4 source.
- **SYN cookies**: IPv4 only.

IPv6 ratelimit and SYN cookie are tracked for a follow-up. If you
need them, the gap is documented and PRs are welcome — see
[../CONTRIBUTING.md § Adding a new rule type](../CONTRIBUTING.md).

---

## Can I run multiple loaders on one host?

**No.** XDP attach is per-NIC; two loaders racing for the same NIC
is undefined behaviour. The DaemonSet pattern enforces one-per-node
in Kubernetes; the Compose file's `network_mode: host` plus the
explicit `OPENSCRUB_IFACE` enforces it locally. If you need to
filter on multiple NICs, run multiple `openscrub-loader` instances
each with a different `OPENSCRUB_IFACE` — they share `/sys/fs/bpf`
under different pin paths.

---

## How do I add a custom IOC source besides ThreatFlow?

Two patterns:

- **Push** — your custom source authenticates as an operator and
  POSTs rules directly to `/api/v1/rules` with `source: "custom"`.
  This is the simplest route and works today.
- **Pull** — fork the puller in [`internal/ioc/`](../internal/ioc/),
  add a new feed adapter, and wire it into the goroutine schedule.
  This is the right shape if your feed needs delta diffing,
  allow-list overlap, or the safety guards already implemented for
  ThreatFlow.

Either way, set `source` distinctly so audit queries and dashboards
can split by feed origin.

---

## Does it interfere with the normal kernel TCP stack?

No. XDP runs *before* the kernel stack; a packet that XDP returns
`XDP_PASS` for proceeds through the regular `skb` path, untouched.
There's no NAT, no payload rewrite, no socket interception. Hosts
that forward packets they don't terminate (gateway nodes) work
unchanged.

The one caveat: if you misconfigure a `0.0.0.0/0` blocklist rule,
you will drop everything including SSH. The API rejects prefix < /8
by default for exactly this reason — see
[api.md § dangerous_cidr](api.md).

---

## What's the perf overhead per pps?

In `drv` mode on commodity hardware (Mellanox `mlx5`, Intel `i40e`,
Broadcom `bnxt`):

- **Drop path** (LPM hit): ~50 ns per packet, ~0% userspace CPU.
- **Pass path** (LPM miss): ~10 ns per packet on top of the normal
  kernel stack. Effectively free.
- **Ratelimit branch**: ~80 ns per packet for the token-bucket
  update.

In `skb` (generic) mode add ~150 ns per packet across the board —
that's the cost of the generic-XDP path. Use `drv` in production;
`skb` is a fallback for NICs without driver XDP support.

Benchmarks live next to the kernel-version matrix; the headline is
**line rate at 64-byte packets** on `drv` mode for the supported
NICs.

---

## How do I disable SYN cookies for one listener?

SYN-cookie generation is per-listener-port via the `syncookie` rule
type (see [`internal/rules/rule.go`](../internal/rules/rule.go)).
Withdraw the rule via `DELETE /api/v1/rules/{id}` and the loader
removes the SYN-cookie path for that port. The kernel's own
SYN-cookie behaviour (`net.ipv4.tcp_syncookies`) is untouched —
OpenScrub's path is XDP-side and independent.

To turn SYN cookies off entirely for a port, withdraw all
`syncookie` rules for that `port`. To turn it off everywhere, do
not create any.

---

## Where is the audit log?

Three places, all consistent:

- **`audit_log` table in Postgres** — every rule mutation, every
  TTL expiry, every IOC pull. Append-only by policy, never updated
  in place.
- **CITADEL WORM ledger** — every mutation also fires an
  `openscrub.rule_change` event, and every distinct mitigation
  fires an `openscrub.mitigation` event. HMAC-SHA256 signed; see
  [citadel-integration.md](citadel-integration.md).
- **API process logs** — structured JSON via `zerolog`, useful for
  short-term forensics. Not a retention surface.

The Postgres `audit_log` is the operator's working surface; the
CITADEL WORM ledger is the auditor's. Both are populated by the
same write path so they don't drift.

---

## How is OpenScrub licensed?

**Apache-2.0**, same as APIGuard, ThreatFlow, CyberPath, SecureLab.
See [../LICENSE](../LICENSE) and
[../../ECOSYSTEM.md § Licensing Model](../../ECOSYSTEM.md#licensing-model).
The audit-grade core (CITADEL, VertGuard) is AGPL; OpenScrub is a
tool platform that produces evidence that flows into it.

---

## How do I report a security issue?

See [../SECURITY.md](../SECURITY.md). **Do not** open a public
GitHub issue for a kernel-attack-surface finding — XDP map
injection, BPF verifier bypass, loader privilege escalation, and
rule poisoning are treated as critical-severity by default. Use the
GitHub Security Advisory or `security@opensecstack.org` (PGP
preferred).

---

## See also

- [quick-start.md](quick-start.md)
- [api.md](api.md)
- [configuration.md](configuration.md)
- [deployment.md](deployment.md)
- [architecture.md](architecture.md)
- [security/threat-model.md](security/threat-model.md)
- [troubleshooting.md](troubleshooting.md)
- [operator-handbook.md](operator-handbook.md)
- [threatflow-integration.md](threatflow-integration.md)
- [citadel-integration.md](citadel-integration.md)
- [../README.md](../README.md)
- [../ROADMAP.md](../ROADMAP.md)
- [../CONTRIBUTING.md](../CONTRIBUTING.md)
- [../SECURITY.md](../SECURITY.md)
