// SPDX-License-Identifier: Apache-2.0
//
// OpenScrub data plane userspace library.
//
// Public surface:
//   - `Loader`       — attaches the XDP program to a NIC.
//   - `MapWriter`    — mutates blocklist + ratelimit BPF maps.
//   - `StatsReader`  — reads PERCPU stat counters.
//   - `Stats`        — aggregated counter snapshot.
//
// Agent B (Go control plane) calls into MapWriter through a thin FFI
// wrapper or a Unix-socket RPC; the API is intentionally
// rule-oriented (`add_blocklist_v4(prefix)`) so the transport choice
// is invisible to callers.

pub mod error;
pub mod ipc;
pub mod maps;
pub mod stats;

#[cfg(not(target_os = "linux"))]
mod loader_stub;
#[cfg(target_os = "linux")]
mod loader_linux;

#[cfg(target_os = "linux")]
pub use loader_linux::Loader;
#[cfg(not(target_os = "linux"))]
pub use loader_stub::Loader;

pub use error::{DataplaneError, Result};
pub use maps::{Blocklist, MapWriter, RatelimitRule};
pub use stats::{Stats, StatsReader};

/// Default location of the compiled BPF object relative to the workspace.
///
/// `Loader::attach` reads this path at runtime; the eBPF Makefile in
/// `openscrub/ebpf/` produces it. Override with the `OPENSCRUB_BPF_OBJ`
/// env var or by passing an explicit path to `Loader::new`.
pub const DEFAULT_BPF_OBJECT_PATH: &str = "../../ebpf/openscrub.bpf.o";

/// Name of the XDP program inside the BPF object (must match
/// `SEC("xdp")` symbol in `openscrub.bpf.c`).
pub const XDP_PROGRAM_NAME: &str = "openscrub_xdp";

// Map names — keep in sync with `SEC(".maps")` declarations in the C source.
pub const MAP_BLOCKLIST_V4: &str = "blocklist_v4";
pub const MAP_BLOCKLIST_V6: &str = "blocklist_v6";
pub const MAP_RATELIMIT: &str = "ratelimit";
pub const MAP_STATS: &str = "stats";
pub const MAP_SYNCOOKIE_LISTENERS: &str = "syncookie_listeners";
