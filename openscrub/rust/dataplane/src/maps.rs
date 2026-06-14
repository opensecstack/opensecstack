// SPDX-License-Identifier: Apache-2.0
//
// MapWriter — the public, transport-agnostic API that Agent B (Go
// control plane) calls to mutate the data plane.
//
// On Linux with a loaded BPF program the writes hit live BPF maps via
// Aya. Off-Linux (or before `Loader::attach`) the writes are buffered
// in an in-memory shadow that the loader replays once it attaches —
// this lets unit tests and Windows builds exercise the API without a
// running kernel.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::error::{DataplaneError, Result};

/// One rate-limit rule applied to a single source IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatelimitRule {
    pub src: Ipv4Addr,
    /// Refill rate in packets per second.
    pub rate_pps: u32,
}

impl RatelimitRule {
    pub fn new(src: Ipv4Addr, rate_pps: u32) -> Result<Self> {
        if rate_pps == 0 {
            return Err(DataplaneError::InvalidRate(rate_pps));
        }
        Ok(Self { src, rate_pps })
    }
}

/// In-memory shadow of the BPF maps. Stays consistent with the kernel
/// side once `Loader::attach` finishes.
#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    pub v4: HashSet<Ipv4Net>,
    pub v6: HashSet<Ipv6Net>,
    pub ratelimit: HashMap<Ipv4Addr, u32>,
    /// TCP destination ports (host order) for which SYN cookie
    /// mitigation is enabled in the XDP program.
    pub syncookie_listeners: HashSet<u16>,
}

/// Cloneable, thread-safe handle to the data plane's mutable state.
///
/// Construct via [`MapWriter::new_detached`] for tests and pre-attach
/// usage; the loader replaces it with a kernel-backed writer once
/// `Loader::attach` succeeds.
#[derive(Clone)]
pub struct MapWriter {
    inner: Arc<Mutex<MapWriterInner>>,
}

struct MapWriterInner {
    shadow: Blocklist,
    backend: Backend,
}

enum Backend {
    /// Pure in-memory; no kernel side. Used in tests and on Windows.
    Detached,
    /// Live BPF maps. The Linux loader installs this variant.
    #[cfg(target_os = "linux")]
    Bpf(crate::loader_linux::BpfMapHandles),
}

impl MapWriter {
    /// Build a detached MapWriter that records all mutations into an
    /// in-memory shadow. No kernel calls. Always available.
    pub fn new_detached() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MapWriterInner {
                shadow: Blocklist::default(),
                backend: Backend::Detached,
            })),
        }
    }

    /// Add an IPv4 prefix to the blocklist.
    pub fn add_blocklist_v4(&self, prefix: Ipv4Net) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.shadow.v4.insert(prefix);
        sync_v4_add(&mut g.backend, prefix)
    }

    /// Remove an IPv4 prefix from the blocklist. Returns Ok even if the
    /// prefix was not present.
    pub fn remove_blocklist_v4(&self, prefix: Ipv4Net) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.shadow.v4.remove(&prefix);
        sync_v4_remove(&mut g.backend, prefix)
    }

    /// Add an IPv6 prefix to the blocklist.
    pub fn add_blocklist_v6(&self, prefix: Ipv6Net) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.shadow.v6.insert(prefix);
        sync_v6_add(&mut g.backend, prefix)
    }

    /// Remove an IPv6 prefix from the blocklist.
    pub fn remove_blocklist_v6(&self, prefix: Ipv6Net) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.shadow.v6.remove(&prefix);
        sync_v6_remove(&mut g.backend, prefix)
    }

    /// Install or update a per-source rate limit.
    pub fn set_ratelimit(&self, rule: RatelimitRule) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.shadow.ratelimit.insert(rule.src, rule.rate_pps);
        sync_ratelimit_set(&mut g.backend, rule)
    }

    /// Remove a rate limit rule.
    pub fn clear_ratelimit(&self, src: Ipv4Addr) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.shadow.ratelimit.remove(&src);
        sync_ratelimit_clear(&mut g.backend, src)
    }

    /// Enable SYN cookie mitigation for a TCP listener (dst port,
    /// host order). The XDP program will mint cookies and reply with
    /// SYN-ACK for inbound SYNs to this port.
    pub fn enable_syncookie(&self, port: u16) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.shadow.syncookie_listeners.insert(port);
        sync_syncookie_set(&mut g.backend, port)
    }

    /// Disable SYN cookie mitigation for a port.
    pub fn disable_syncookie(&self, port: u16) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.shadow.syncookie_listeners.remove(&port);
        sync_syncookie_clear(&mut g.backend, port)
    }

    /// Snapshot of the current shadow state.
    pub fn snapshot(&self) -> Blocklist {
        self.inner.lock().unwrap().shadow.clone()
    }

    /// Total number of installed rules across all map types.
    pub fn len(&self) -> usize {
        let g = self.inner.lock().unwrap();
        g.shadow.v4.len()
            + g.shadow.v6.len()
            + g.shadow.ratelimit.len()
            + g.shadow.syncookie_listeners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn attach_backend(&self, handles: crate::loader_linux::BpfMapHandles) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        // Replay the shadow into the freshly attached maps so the
        // kernel side starts in sync with what userspace already
        // believes is installed.
        for prefix in &g.shadow.v4 {
            handles.add_v4(*prefix)?;
        }
        for prefix in &g.shadow.v6 {
            handles.add_v6(*prefix)?;
        }
        for (src, rate) in &g.shadow.ratelimit {
            handles.set_ratelimit(*src, *rate)?;
        }
        for port in &g.shadow.syncookie_listeners {
            handles.set_syncookie(*port)?;
        }
        g.backend = Backend::Bpf(handles);
        Ok(())
    }
}

impl Default for MapWriter {
    fn default() -> Self {
        Self::new_detached()
    }
}

// ── Backend dispatch helpers ────────────────────────────────────────

fn sync_v4_add(backend: &mut Backend, prefix: Ipv4Net) -> Result<()> {
    match backend {
        Backend::Detached => Ok(()),
        #[cfg(target_os = "linux")]
        Backend::Bpf(h) => h.add_v4(prefix),
    }
}

fn sync_v4_remove(backend: &mut Backend, prefix: Ipv4Net) -> Result<()> {
    match backend {
        Backend::Detached => Ok(()),
        #[cfg(target_os = "linux")]
        Backend::Bpf(h) => h.remove_v4(prefix),
    }
}

fn sync_v6_add(backend: &mut Backend, prefix: Ipv6Net) -> Result<()> {
    match backend {
        Backend::Detached => Ok(()),
        #[cfg(target_os = "linux")]
        Backend::Bpf(h) => h.add_v6(prefix),
    }
}

fn sync_v6_remove(backend: &mut Backend, prefix: Ipv6Net) -> Result<()> {
    match backend {
        Backend::Detached => Ok(()),
        #[cfg(target_os = "linux")]
        Backend::Bpf(h) => h.remove_v6(prefix),
    }
}

fn sync_ratelimit_set(backend: &mut Backend, rule: RatelimitRule) -> Result<()> {
    match backend {
        Backend::Detached => Ok(()),
        #[cfg(target_os = "linux")]
        Backend::Bpf(h) => h.set_ratelimit(rule.src, rule.rate_pps),
    }
}

fn sync_ratelimit_clear(backend: &mut Backend, src: Ipv4Addr) -> Result<()> {
    match backend {
        Backend::Detached => Ok(()),
        #[cfg(target_os = "linux")]
        Backend::Bpf(h) => h.clear_ratelimit(src),
    }
}

fn sync_syncookie_set(backend: &mut Backend, port: u16) -> Result<()> {
    match backend {
        Backend::Detached => Ok(()),
        #[cfg(target_os = "linux")]
        Backend::Bpf(h) => h.set_syncookie(port),
    }
}

fn sync_syncookie_clear(backend: &mut Backend, port: u16) -> Result<()> {
    match backend {
        Backend::Detached => Ok(()),
        #[cfg(target_os = "linux")]
        Backend::Bpf(h) => h.clear_syncookie(port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn detached_writer_records_v4_prefixes() {
        let w = MapWriter::new_detached();
        w.add_blocklist_v4(Ipv4Net::from_str("10.0.0.0/8").unwrap()).unwrap();
        w.add_blocklist_v4(Ipv4Net::from_str("192.168.1.0/24").unwrap()).unwrap();
        assert_eq!(w.snapshot().v4.len(), 2);
    }

    #[test]
    fn detached_writer_remove_is_idempotent() {
        let w = MapWriter::new_detached();
        let p = Ipv4Net::from_str("203.0.113.0/24").unwrap();
        w.add_blocklist_v4(p).unwrap();
        w.remove_blocklist_v4(p).unwrap();
        w.remove_blocklist_v4(p).unwrap(); // second remove must not error
        assert!(w.snapshot().v4.is_empty());
    }

    #[test]
    fn detached_writer_records_v6_prefixes() {
        let w = MapWriter::new_detached();
        w.add_blocklist_v6(Ipv6Net::from_str("2001:db8::/32").unwrap()).unwrap();
        assert_eq!(w.snapshot().v6.len(), 1);
    }

    #[test]
    fn ratelimit_rejects_zero_rate() {
        let r = RatelimitRule::new(Ipv4Addr::new(1, 2, 3, 4), 0);
        assert!(matches!(r, Err(DataplaneError::InvalidRate(0))));
    }

    #[test]
    fn ratelimit_set_and_clear() {
        let w = MapWriter::new_detached();
        let r = RatelimitRule::new(Ipv4Addr::new(1, 2, 3, 4), 1000).unwrap();
        w.set_ratelimit(r).unwrap();
        assert_eq!(w.snapshot().ratelimit.len(), 1);
        w.clear_ratelimit(r.src).unwrap();
        assert!(w.snapshot().ratelimit.is_empty());
    }

    #[test]
    fn writer_is_clone_and_thread_safe() {
        let w = MapWriter::new_detached();
        let w2 = w.clone();
        let handle = std::thread::spawn(move || {
            w2.add_blocklist_v4(Ipv4Net::from_str("10.0.0.0/8").unwrap()).unwrap();
        });
        handle.join().unwrap();
        assert_eq!(w.snapshot().v4.len(), 1);
    }

    #[test]
    fn len_counts_all_rule_types() {
        let w = MapWriter::new_detached();
        w.add_blocklist_v4(Ipv4Net::from_str("10.0.0.0/8").unwrap()).unwrap();
        w.add_blocklist_v6(Ipv6Net::from_str("2001:db8::/32").unwrap()).unwrap();
        w.set_ratelimit(RatelimitRule::new(Ipv4Addr::new(1, 1, 1, 1), 100).unwrap()).unwrap();
        assert_eq!(w.len(), 3);
        assert!(!w.is_empty());
    }

    #[test]
    fn fresh_writer_is_empty() {
        let w = MapWriter::new_detached();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn syncookie_enable_and_disable() {
        let w = MapWriter::new_detached();
        w.enable_syncookie(443).unwrap();
        w.enable_syncookie(8443).unwrap();
        assert_eq!(w.snapshot().syncookie_listeners.len(), 2);
        w.disable_syncookie(443).unwrap();
        w.disable_syncookie(443).unwrap(); // idempotent
        assert_eq!(w.snapshot().syncookie_listeners.len(), 1);
    }
}
