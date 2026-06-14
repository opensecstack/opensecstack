# ADR-001: Use XDP/eBPF for packet filtering instead of iptables/nftables

## Status
Accepted

## Context
OpenScrub must absorb and filter volumetric DDoS traffic at multi-million packets per second (Mpps) without becoming a bottleneck itself. The classic Linux path — iptables or nftables — operates inside the kernel networking stack, after the kernel has allocated an `sk_buff` for each packet, traversed several hook points, and handed the packet off to Netfilter. Under attack conditions (5–20 Mpps or more) this path introduces non-trivial per-packet overhead and becomes CPU-saturated well before line rate.

XDP (eXpress Data Path) executes an eBPF program at the NIC driver level, before `sk_buff` allocation. Packets that match drop rules never enter the kernel networking stack at all, reducing CPU cost per dropped packet by an order of magnitude. This is the correct architectural layer for a scrubbing platform whose primary job is bulk drop of attack traffic.

## Decision

- XDP filter programs are written in restricted C and compiled with clang/LLVM to BPF bytecode.
- Programs are loaded and attached to interfaces via libbpf (Go bindings through `cilium/ebpf`).
- The drop decision is expressed as an XDP action: `XDP_DROP` for attack traffic, `XDP_PASS` for clean traffic forwarded into the stack.
- iptables/nftables is retained as a fallback mitigation path for NICs or virtual drivers that do not support XDP native or offload mode (e.g., virtio in some hypervisors).
- Filter rules are compiled from OpenScrub's internal rule representation; no hand-editing of BPF object files is expected post-deployment.

## Consequences

**Positive:**
- Drop throughput scales close to NIC line rate; CPU overhead per dropped packet is minimal.
- Maps and per-CPU counters in eBPF provide low-latency telemetry without leaving kernel space.

**Negative:**
- Requires Linux kernel >= 5.6 and XDP-capable NIC drivers (e.g., i40e, mlx5, ixgbe). Unsupported NICs fall back to iptables.
- The clang/LLVM toolchain must be present in the build environment; the compiled BPF object must be rebuilt when the kernel ABI changes (kernel updates may require recompilation).
- Debugging XDP programs is less ergonomic than iptables rules; `bpf_trace_printk` and `bpftool` are the primary introspection tools.
- Team must maintain competency in BPF C and libbpf/`cilium/ebpf` APIs.
