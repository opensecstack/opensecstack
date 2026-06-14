// SPDX-License-Identifier: Apache-2.0
//
// StatsReader — aggregates the PERCPU_ARRAY counters from the BPF
// data plane into a single snapshot. On non-Linux builds the reader
// returns a zeroed snapshot so callers (Agent B's metrics endpoint)
// can compile and run without a kernel.

use std::sync::{Arc, Mutex};

use crate::error::Result;

/// Aggregated counter snapshot. Names mirror `enum stat_kind` in
/// `openscrub.bpf.c`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub packets_ratelimited: u64,
    pub packets_malformed: u64,
    pub syn_cookies_sent: u64,
}

impl Stats {
    pub fn total_seen(&self) -> u64 {
        self.packets_passed
            + self.packets_dropped
            + self.packets_ratelimited
            + self.packets_malformed
    }
}

#[derive(Clone)]
pub struct StatsReader {
    inner: Arc<Mutex<StatsInner>>,
}

struct StatsInner {
    backend: StatsBackend,
}

enum StatsBackend {
    /// Pure in-memory counter — used in tests.
    Detached(Stats),
    #[cfg(target_os = "linux")]
    Bpf(crate::loader_linux::BpfStatsHandle),
}

impl StatsReader {
    pub fn new_detached() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StatsInner {
                backend: StatsBackend::Detached(Stats::default()),
            })),
        }
    }

    pub fn read(&self) -> Result<Stats> {
        let g = self.inner.lock().unwrap();
        match &g.backend {
            StatsBackend::Detached(s) => Ok(*s),
            #[cfg(target_os = "linux")]
            StatsBackend::Bpf(h) => h.read(),
        }
    }

    /// Test helper — overrides the in-memory counter on a detached reader.
    #[cfg(test)]
    pub(crate) fn set_for_test(&self, s: Stats) {
        let mut g = self.inner.lock().unwrap();
        g.backend = StatsBackend::Detached(s);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn attach_backend(&self, handle: crate::loader_linux::BpfStatsHandle) {
        let mut g = self.inner.lock().unwrap();
        g.backend = StatsBackend::Bpf(handle);
    }
}

impl Default for StatsReader {
    fn default() -> Self {
        Self::new_detached()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_reader_starts_zero() {
        let r = StatsReader::new_detached();
        assert_eq!(r.read().unwrap(), Stats::default());
    }

    #[test]
    fn total_seen_sums_all_packet_buckets() {
        let s = Stats {
            packets_passed: 10,
            packets_dropped: 5,
            packets_ratelimited: 2,
            packets_malformed: 1,
            syn_cookies_sent: 99, // not part of total_seen
        };
        assert_eq!(s.total_seen(), 18);
    }

    #[test]
    fn set_for_test_updates_snapshot() {
        let r = StatsReader::new_detached();
        r.set_for_test(Stats { packets_dropped: 42, ..Default::default() });
        assert_eq!(r.read().unwrap().packets_dropped, 42);
    }
}
