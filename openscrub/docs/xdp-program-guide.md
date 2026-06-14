# XDP/eBPF Program Guide

## Overview

OpenScrub uses XDP (eXpress Data Path) programs compiled to eBPF bytecode and attached to network interfaces at the driver or native layer. Packet filtering decisions are made inside the kernel before the kernel networking stack processes the frame, giving sub-microsecond drop latency.

The XDP programs live under `ebpf/` and are compiled separately from the Go runtime.

---

## Source Files

| File | Purpose |
|------|---------|
| `ebpf/openscrub_kern.c` | Entry dispatcher — parses Ethernet/IP headers and branches to per-protocol handlers |
| `ebpf/rate_limiter.c` | Token-bucket rate limiter shared across programs via BPF maps |
| `ebpf/syn_flood.c` | SYN cookie validation and per-source SYN rate tracking |
| `ebpf/udp_flood.c` | UDP source/dest-port rate limiting and reflection amplification drops |
| `ebpf/icmp_flood.c` | ICMP type/code filtering, echo-request rate limiting |

All programs return one of `XDP_DROP`, `XDP_PASS`, or `XDP_TX`. The dispatcher in `openscrub_kern.c` decides which per-protocol program runs based on the IP protocol field.

---

## Build

**Requirements:**

- clang >= 14
- llvm-strip
- Linux kernel headers >= 5.15
- libbpf >= 1.0

**Build command:**

```bash
cd ebpf
make
```

The `ebpf/Makefile` compiles each `.c` file to a `.o` ELF object using:

```
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu \
  -c <file>.c -o <file>.o
```

`llvm-strip -g` is applied after compilation to remove debug sections not needed at load time. Output objects are placed in `ebpf/bin/`.

To rebuild only a specific program:

```bash
make syn_flood.o
```

---

## Runtime Loading

`internal/mitigation/xdp/loader.go` handles program loading and interface attachment using the `cilium/ebpf` Go library.

Load sequence:

1. `LoadCollection()` opens the compiled `.o` object and pins maps under `/sys/fs/bpf/openscrub/`.
2. `AttachXDP()` links the program to the target interface with `XDP_FLAGS_DRV_MODE` (falls back to `XDP_FLAGS_SKB_MODE` if driver offload is unavailable).
3. A file descriptor is retained; calling `Detach()` removes the program from the interface.

The interface name and mode are read from `openscrub.yaml` under `mitigation.xdp`.

---

## BPF Map Layout

Defined in `internal/mitigation/xdp/maps.go`:

| Map name | Type | Key | Value | Purpose |
|----------|------|-----|-------|---------|
| `blocklist` | LPM trie | IPv4/IPv6 prefix | `u8` action | Source IP block list |
| `rate_counters` | LRU hash | `u32` src IP | `u64` pps counter | Per-source packet count |
| `syn_cookies` | Hash | `u32` src IP | `u64` cookie state | SYN cookie tracking |
| `config` | Array | `u32` index | `u64` threshold | Per-program thresholds |
| `stats` | Per-CPU array | `u32` index | `u64` counter | Drop/pass telemetry |

Maps are shared between the eBPF programs and the Go control plane. The Go side updates `blocklist` and `config`; the eBPF side updates counters.

---

## Rule Lifecycle

`internal/mitigation/xdp/rules.go` manages block rule CRUD:

- `AddRule(prefix net.IPNet)` — inserts into the `blocklist` LPM trie.
- `RemoveRule(prefix net.IPNet)` — deletes from the trie.
- `FlushRules()` — clears the entire trie (used during safe rollback).
- Rules are persisted in the database and reloaded on process restart via `SyncRules()`.

Rule changes take effect immediately because the eBPF program reads the map on each packet.

---

## Adding a New XDP Program

1. Create `ebpf/<name>.c`. Include `openscrub_kern.h` for shared helpers.
2. Register the protocol or condition in the dispatcher (`openscrub_kern.c`).
3. Add the object target to `ebpf/Makefile`.
4. Add any new maps to `internal/mitigation/xdp/maps.go` and define their schema.
5. Call `LoadCollection()` with the new object path in `loader.go`.
6. Write a unit test under `tests/xdp/` using `bpf_prog_test_run`.

Do not reuse map names across programs without confirming the key/value layout is identical.
