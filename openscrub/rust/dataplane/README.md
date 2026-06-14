# openscrub-dataplane

Rust userspace for the OpenScrub XDP/eBPF data plane.

Two artefacts:

- **`openscrub_dataplane`** (lib) — public `MapWriter` + `StatsReader`
  API. Agent B (Go control plane) consumes this through a thin FFI or
  Unix-socket wrapper.
- **`openscrub-loader`** (bin) — pins the XDP program to a NIC and
  keeps it attached for the lifetime of the process.

## Build

The data plane is split between a C kernel object and Rust userspace.

```bash
# 1. Compile the BPF object (Linux + clang + libbpf-dev required)
make -C openscrub/ebpf

# 2. Build the Rust crate
cd openscrub/rust/dataplane
cargo build --release
```

On non-Linux hosts the crate still builds — the loader returns
`DataplaneError::UnsupportedPlatform` from `attach()`, but `MapWriter`
remains usable in detached mode (everything is recorded into an
in-memory shadow). This lets Agent B compile and run unit tests
without a kernel.

## Run

```bash
# Requires: Linux ≥ 5.10, CAP_BPF + CAP_NET_ADMIN, openscrub.bpf.o present
sudo ./target/release/openscrub-loader \
    --iface eth0 \
    --mode driver \
    --bpf-object ../../ebpf/openscrub.bpf.o
```

Modes:
- `driver` — native XDP, requires NIC support (best performance)
- `skb` — generic skb mode, works anywhere
- `hardware` — Smart NIC offload

## BPF map layout

| Map | Type | Key | Value | Purpose |
|---|---|---|---|---|
| `blocklist_v4` | `LPM_TRIE` | `(prefixlen, ipv4)` | `u8` (1 = drop) | Drop traffic from CIDR |
| `blocklist_v6` | `LPM_TRIE` | `(prefixlen, ipv6)` | `u8` (1 = drop) | Drop IPv6 traffic |
| `ratelimit` | `HASH` | IPv4 src (BE) | `ratelimit_value` | Token-bucket rate limit |
| `stats` | `PERCPU_ARRAY` | `stat_kind` enum | `u64` counter | Telemetry |

The Rust types in `loader_linux.rs` (`LpmV4Key`, `LpmV6Key`,
`RatelimitValue`) are `#[repr(C)]` mirrors of the C structs — keep
them in lock-step with `openscrub.bpf.c` when changing the schema.

## Public API for Agent B

```rust
use openscrub_dataplane::{Loader, MapWriter, RatelimitRule, AttachMode};
use ipnet::Ipv4Net;
use std::str::FromStr;

let mut loader = Loader::from_default_path();
loader.attach("eth0", AttachMode::Driver).await?;

let writer: MapWriter = loader.map_writer();      // cloneable handle
writer.add_blocklist_v4(Ipv4Net::from_str("203.0.113.0/24")?)?;
writer.set_ratelimit(RatelimitRule::new("198.51.100.7".parse()?, 1000)?)?;

let stats = loader.stats_reader().read()?;
println!("dropped={}", stats.packets_dropped);
```

`MapWriter` is `Clone + Send + Sync`. Calls before `attach()` succeed
and are buffered into a shadow that the loader replays into the BPF
maps once attached — Agent B never has to special-case "loader not
ready yet".

## Test

```bash
cargo test                      # unit + integration (no privileges)
sudo cargo test -- --ignored    # live-kernel tests (Linux only)
```

The ignored integration test requires:
- Linux host
- `CAP_BPF` + `CAP_NET_ADMIN`
- `openscrub.bpf.o` built

## Licence

Apache-2.0.
