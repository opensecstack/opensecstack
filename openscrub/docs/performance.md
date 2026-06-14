# OpenScrub Performance Characteristics

OpenScrub is a DDoS mitigation tool. Performance **is** the
feature: if the data plane cannot drop attack traffic faster than
the attacker can send it, the rest of the system is irrelevant.

This document covers the methodology, the rough numbers we expect
on commodity hardware, the per-feature cost, and — importantly —
where OpenScrub stops being the right answer and you should reach
for [APIGuard](../../apiguard/docs/) or upstream scrubbing.

> **Important.** All headline numbers in this document are
> **approximate** and derived from publicly-published XDP
> benchmarks (Cloudflare, the Linux kernel documentation, the
> Express Data Path paper). They are **not** measurements from a
> specific OpenScrub build — concrete `make bench` numbers will
> land alongside the v1.0.0 reference rig. Treat them as
> order-of-magnitude budgets, not commitments.

---

## Methodology

The reference rig:

| Component | Spec |
|---|---|
| Sender | `pktgen` (in-kernel) on a separate host, generating 64-byte UDP at line rate |
| Receiver (DUT) | OpenScrub running native-mode XDP on the test NIC |
| NIC | 25 GbE, multi-queue, MSI-X with one IRQ per queue |
| CPU | Modern x86_64, IRQs pinned to dedicated cores, RPS off (XDP runs before RPS) |
| Kernel | 5.15+ (LTS); `bpf_tcp_gen_syncookie` requires 5.8+ |
| Test target | A `blocklist` rule covering the sender's source CIDR; observe `STAT_PACKETS_DROPPED` increase via [`StatsReader`](../rust/dataplane/src/stats.rs) |

`make test-integration` exercises the API contract via
[`tests/integration/run.sh`](../tests/integration/run.sh) but does
**not** drive line-rate traffic — the shell harness fires ~100
packets via `hping3` to verify the wiring, not throughput.
Throughput numbers come from a separate pktgen benchmark not yet
checked into this repo.

---

## Headline numbers (approximate)

These are what we expect on the reference rig. They mirror the
public Cloudflare XDP_DROP measurements and the upstream kernel
samples.

| Mode | Small-packet drop rate | Notes |
|---|---|---|
| **Driver / native XDP** | ~10–14 Mpps per core, scaling roughly linearly across NIC queues until PCIe / NIC firmware saturates | Drop happens before `skb` allocation. This is the design point. |
| **SKB / generic XDP** | ~2–4 Mpps total | Falls back to a generic XDP path that allocates an `skb` first. Significantly slower; only useful for development on NICs without driver support. |
| **Offloaded XDP** | NIC-dependent; not in scope for v1.0.0 | Some NICs (Netronome, BlueField) can JIT XDP into NIC firmware. OpenScrub will work but the maps move into NIC SRAM, with smaller caps. Not tested. |

Reach driver-mode rates with multi-queue NICs and one IRQ per
core; pin each queue's IRQ to its own CPU. Without affinity the
cost of cross-CPU cache misses on map updates dominates.

> **Approximation note.** Cloudflare published 10 Mpps per core on
> XDP_DROP in their 2018 blog series; modern silicon (e.g. CX-6,
> E810) hits 14+ Mpps under similar conditions. We expect
> OpenScrub's drop path to land in that band because it is
> dominated by the same primitives — LPM lookup + counter
> increment.

---

## Per-feature data-plane cost

The XDP program in
[`ebpf/openscrub.bpf.c`](../ebpf/openscrub.bpf.c) does up to four
things per packet: bounds checks, blocklist lookup, ratelimit
lookup, syncookie path. Approximate per-packet cost:

| Stage | Cost (approx) | Notes |
|---|---|---|
| Ethernet + IP header bounds check | < 5 ns | A handful of pointer comparisons, predictably branched. |
| `blocklist_v4` LPM lookup | ~30–50 ns | One hash-table walk per prefix length present in the trie. Dominated by the tallest prefix. |
| `blocklist_v6` LPM lookup | ~40–80 ns | Larger key (16 B vs 4 B) and typically a sparser trie. |
| `ratelimit` HASH lookup + token-bucket update | ~80 ns | One `bpf_map_lookup_elem` + a few arithmetic ops + write-back to the value. Hot path is the lookup. |
| `bpf_ktime_get_ns` | ~10–20 ns | Called inside the token-bucket refill. |
| `try_syncookie_reply` (full path) | ~600 ns | Dominated by `bpf_tcp_gen_syncookie` (kernel helper) and `bpf_csum_diff` over the TCP header. Only on TCP SYN to a registered listener. Returns `XDP_TX` so the packet never enters the stack. |

These figures are **per-packet**; an XDP program processing 10
Mpps on one core has roughly 100 ns per packet of total budget.
OpenScrub's `XDP_DROP` path stays inside that budget; the
syncookie path does not — by design, syncookies trade per-packet
cost for absorbing a SYN flood without reaching `tcp_v4_rcv`.

### Stat counters are PERCPU

Every verdict ends with `stat_inc()`, which writes to a
`PERCPU_ARRAY`. The increment is a per-CPU local write, no
cross-CPU contention. Userspace sums the per-CPU values via
[`StatsReader`](../rust/dataplane/src/stats.rs); the read side is
the only place that pays for the fan-in.

---

## Map sizing tradeoffs

| Map | Cap (v1.0.0) | Memory (approx) | Lookup cost | Notes |
|---|---|---|---|---|
| `blocklist_v4` | 100 000 | ~9 MB | LPM walk | Doubling the cap roughly doubles the locked memory; the lookup cost is bounded by the tallest prefix, not the entry count. |
| `blocklist_v6` | 50 000 | ~7 MB | LPM walk | v6 keys are 4× wider; halving the cap keeps the trie comfortably in cache. |
| `ratelimit` | 100 000 | ~8 MB | HASH lookup | Per-packet on every IPv4 packet that passes the blocklist. Stays in L2 well past 100k entries. |
| `syncookie_listeners` | 4 096 | <1 MB | HASH lookup | Only checked on TCP SYN. 4096 listeners is overkill for a single host but cheap. |

See [data-model.md](data-model.md#capacity-model) for the full
memory budget. Total locked-kernel-memory ceiling at full caps is
~24 MB. Operators must raise `RLIMIT_MEMLOCK` accordingly — see
[deployment.md](deployment.md).

---

## Bottlenecks to watch

Bottlenecks rarely come from the XDP program itself; they come
from the surrounding kernel plumbing. In rough order of impact:

### NIC queue affinity / IRQ pinning

A multi-queue NIC delivers packets across N queues; each queue
fires an MSI-X IRQ. Without explicit pinning, the IRQs migrate
across CPUs and every map update incurs a cache miss. **Pin one
IRQ per CPU and disable `irqbalance`** on the OpenScrub host.

### RPS / RFS

Receive Packet Steering and Receive Flow Steering operate on
`skb`s — well after XDP. Leave them off for the OpenScrub
ingress NIC; they only add CPU cost on packets XDP did not
already drop.

### Locked-memory ulimit

BPF maps consume locked kernel memory. If `RLIMIT_MEMLOCK` is
too low the loader fails with `EPERM` from `bpf(BPF_MAP_CREATE)`
and the program never attaches. Set `LimitMEMLOCK=infinity` (or
a generous explicit value) in the systemd unit.

### Ratelimit cross-CPU race (intentional)

The `ratelimit` HASH map is shared across CPUs; concurrent
`ratelimit_allow()` calls on the same source IP race on
`tokens` / `last_refill_ns`. The race is bounded (over- or
under-shoot by ~NCPU tokens per refill window) and acceptable —
see [data-model.md](data-model.md#why-hash-not-percpu_hash-for-ratelimit)
for why we accept this rather than switching to `PERCPU_HASH`.

### Postgres connection pool

Out-of-band of the data plane: the Go API uses a `pgxpool`. Under
a burst of `POST /api/v1/rules` (e.g. an IOC bundle landing) the
pool can saturate. Default `max_open_conns` is 25; raise it for
ingest-heavy deployments. Postgres is **not** in the per-packet
path, so DB latency does not affect drop rate.

---

## When *not* to use OpenScrub

OpenScrub is a layer-3 / layer-4 mitigation tool. It is the wrong
answer for:

- **Application-layer (L7) attacks** — slowloris, HTTP flood
  against expensive endpoints, JSON-bomb POST bodies. The XDP
  program sees bytes, not requests; it cannot tell a legitimate
  POST from a malicious one. Use [APIGuard](../../apiguard/docs/)
  in front of the application for L7 rate limiting and rule-based
  WAF.
- **Encrypted payload inspection** — XDP runs before TLS
  termination. There is no plaintext to inspect at the data plane.
  Terminate TLS at APIGuard or a dedicated reverse proxy and apply
  L7 rules there.
- **Volumetric attacks larger than your uplink** — if the attack
  exceeds the NIC's line rate (e.g. a 100 Gbps flood at a 25 Gbps
  port), no in-host mitigation can help. The packets are dropped
  by the upstream router or never delivered. Use a transit
  scrubbing provider; OpenScrub mitigates *what reaches the host*.
- **Stateful per-flow tracking** — connection counts per source,
  TLS-SNI-keyed limits, half-open ratios. v1.0.0 does not track
  per-flow state. See Limitations below.

---

## Limitations (v1.0.0)

Honest list of what OpenScrub v1.0.0 does **not** do:

- **No IPv6 ratelimit.** The `ratelimit` BPF map is keyed by a
  4-byte IPv4 address; v6 sources can be blocklisted but not
  rate-limited. Tracked for v1.1.
- **No IPv6 syncookie.** `try_syncookie_reply` only handles the
  IPv4 path. v6 SYN floods fall through to the kernel TCP stack.
- **No per-flow tracking.** The token bucket is per-source-IP, not
  per-(src, dst, port, proto). A single source attacking many
  ports is rate-limited as one bucket; many sources attacking one
  port get one bucket each.
- **No L7 awareness.** See "When not to use OpenScrub".
- **Cross-CPU race in the token bucket** — bounded and intentional;
  see above.
- **No NIC offload.** v1.0.0 targets driver-mode XDP. Hardware
  offload (Netronome, BlueField) may work but is unverified.
- **Single-NIC attach.** The loader attaches to one ifindex per
  process. Multi-NIC hosts run one OpenScrub instance per NIC.

---

## Reproducing benchmarks

A pktgen-based throughput harness will land alongside the v1.0.0
reference build under `tests/perf/` (not present in v1.0.0 GA).
Until then, the recommended manual procedure is:

```bash
# 1. Bring up the stack
make compose-up

# 2. Create a blocklist rule for the sender's source
curl -X POST http://localhost:8087/api/v1/rules \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"type":"blocklist","cidr":"203.0.113.0/24","ttl_seconds":600}'

# 3. From the sender host, drive pktgen
echo "rem_device_all"  > /proc/net/pktgen/kpktgend_0
echo "add_device eth1" > /proc/net/pktgen/kpktgend_0
echo "src_min 203.0.113.1" > /proc/net/pktgen/eth1
echo "src_max 203.0.113.254" > /proc/net/pktgen/eth1
echo "count 100000000"  > /proc/net/pktgen/eth1
echo "start" > /proc/net/pktgen/pgctrl

# 4. Read counters on the DUT
curl http://localhost:8087/api/v1/metrics
```

Compare `pps_dropped` against the sender's pktgen rate. A 25 GbE
NIC at 64-byte frames tops out near 37 Mpps line rate; a healthy
multi-queue OpenScrub host should sustain double-digit Mpps drop.
**Hardware-specific. Numbers from your rig will differ.**

---

## See also

- [architecture.md](architecture.md) — control-plane / data-plane split
- [data-model.md](data-model.md) — BPF map schema and capacity
- [deployment.md](deployment.md) — IRQ pinning, ulimits, kernel knobs
- [testing.md](testing.md) — perf-regression CI hooks
- [troubleshooting.md](troubleshooting.md) — diagnosing low drop rates
