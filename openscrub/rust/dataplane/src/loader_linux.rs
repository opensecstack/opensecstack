// SPDX-License-Identifier: Apache-2.0
//
// Linux Loader — loads the BPF object via Aya, attaches the XDP
// program to a NIC, and exposes live BPF map handles to MapWriter and
// StatsReader.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aya::maps::{HashMap as AyaHashMap, LpmTrie, PerCpuArray};
use aya::programs::{Xdp, XdpFlags};
use aya::{Bpf, BpfLoader};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::error::{AttachMode, DataplaneError, Result};
use crate::maps::MapWriter;
use crate::stats::{Stats, StatsReader};
use crate::{
    MAP_BLOCKLIST_V4, MAP_BLOCKLIST_V6, MAP_RATELIMIT, MAP_STATS, MAP_SYNCOOKIE_LISTENERS,
    XDP_PROGRAM_NAME,
};

/// Layout must match `struct ratelimit_value` in `openscrub.bpf.c`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RatelimitValue {
    tokens: u64,
    last_refill_ns: u64,
    rate_pps: u32,
    _pad: u32,
}

/// LPM trie key for IPv4 — must match `struct lpm_v4_key`.
#[repr(C)]
#[derive(Clone, Copy)]
struct LpmV4Key {
    prefixlen: u32,
    addr: u32, // network byte order
}

/// LPM trie key for IPv6 — must match `struct lpm_v6_key`.
#[repr(C)]
#[derive(Clone, Copy)]
struct LpmV6Key {
    prefixlen: u32,
    addr: [u8; 16],
}

unsafe impl aya::Pod for RatelimitValue {}
unsafe impl aya::Pod for LpmV4Key {}
unsafe impl aya::Pod for LpmV6Key {}

const STAT_PACKETS_PASSED: u32 = 0;
const STAT_PACKETS_DROPPED: u32 = 1;
const STAT_PACKETS_RATELIMITED: u32 = 2;
const STAT_PACKETS_MALFORMED: u32 = 3;
const STAT_SYN_COOKIES_SENT: u32 = 4;

/// Live handles to the BPF maps. Cloneable; clones share the same
/// underlying maps via `Arc<Mutex<Bpf>>`.
#[derive(Clone)]
pub struct BpfMapHandles {
    bpf: Arc<Mutex<Bpf>>,
}

impl BpfMapHandles {
    pub(crate) fn add_v4(&self, prefix: Ipv4Net) -> Result<()> {
        let mut bpf = self.bpf.lock().unwrap();
        let mut map: LpmTrie<_, LpmV4Key, u8> = LpmTrie::try_from(
            bpf.map_mut(MAP_BLOCKLIST_V4)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_BLOCKLIST_V4.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;
        let key = aya::maps::lpm_trie::Key::new(
            prefix.prefix_len() as u32,
            LpmV4Key {
                prefixlen: prefix.prefix_len() as u32,
                addr: u32::from(prefix.network()).to_be(),
            },
        );
        map.insert(&key, 1u8, 0)
            .map_err(|e| DataplaneError::Other(e.into()))?;
        Ok(())
    }

    pub(crate) fn remove_v4(&self, prefix: Ipv4Net) -> Result<()> {
        let mut bpf = self.bpf.lock().unwrap();
        let mut map: LpmTrie<_, LpmV4Key, u8> = LpmTrie::try_from(
            bpf.map_mut(MAP_BLOCKLIST_V4)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_BLOCKLIST_V4.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;
        let key = aya::maps::lpm_trie::Key::new(
            prefix.prefix_len() as u32,
            LpmV4Key {
                prefixlen: prefix.prefix_len() as u32,
                addr: u32::from(prefix.network()).to_be(),
            },
        );
        let _ = map.remove(&key); // idempotent
        Ok(())
    }

    pub(crate) fn add_v6(&self, prefix: Ipv6Net) -> Result<()> {
        let mut bpf = self.bpf.lock().unwrap();
        let mut map: LpmTrie<_, LpmV6Key, u8> = LpmTrie::try_from(
            bpf.map_mut(MAP_BLOCKLIST_V6)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_BLOCKLIST_V6.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;
        let key = aya::maps::lpm_trie::Key::new(
            prefix.prefix_len() as u32,
            LpmV6Key {
                prefixlen: prefix.prefix_len() as u32,
                addr: prefix.network().octets(),
            },
        );
        map.insert(&key, 1u8, 0)
            .map_err(|e| DataplaneError::Other(e.into()))?;
        Ok(())
    }

    pub(crate) fn remove_v6(&self, prefix: Ipv6Net) -> Result<()> {
        let mut bpf = self.bpf.lock().unwrap();
        let mut map: LpmTrie<_, LpmV6Key, u8> = LpmTrie::try_from(
            bpf.map_mut(MAP_BLOCKLIST_V6)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_BLOCKLIST_V6.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;
        let key = aya::maps::lpm_trie::Key::new(
            prefix.prefix_len() as u32,
            LpmV6Key {
                prefixlen: prefix.prefix_len() as u32,
                addr: prefix.network().octets(),
            },
        );
        let _ = map.remove(&key);
        Ok(())
    }

    pub(crate) fn set_ratelimit(&self, src: Ipv4Addr, rate_pps: u32) -> Result<()> {
        let mut bpf = self.bpf.lock().unwrap();
        let mut map: AyaHashMap<_, u32, RatelimitValue> = AyaHashMap::try_from(
            bpf.map_mut(MAP_RATELIMIT)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_RATELIMIT.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;
        let key = u32::from(src).to_be();
        let value = RatelimitValue {
            tokens: 0,
            last_refill_ns: 0,
            rate_pps,
            _pad: 0,
        };
        map.insert(key, value, 0)
            .map_err(|e| DataplaneError::Other(e.into()))?;
        Ok(())
    }

    pub(crate) fn clear_ratelimit(&self, src: Ipv4Addr) -> Result<()> {
        let mut bpf = self.bpf.lock().unwrap();
        let mut map: AyaHashMap<_, u32, RatelimitValue> = AyaHashMap::try_from(
            bpf.map_mut(MAP_RATELIMIT)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_RATELIMIT.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;
        let key = u32::from(src).to_be();
        let _ = map.remove(&key);
        Ok(())
    }

    pub(crate) fn set_syncookie(&self, port: u16) -> Result<()> {
        let mut bpf = self.bpf.lock().unwrap();
        let mut map: AyaHashMap<_, u16, u8> = AyaHashMap::try_from(
            bpf.map_mut(MAP_SYNCOOKIE_LISTENERS)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_SYNCOOKIE_LISTENERS.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;
        map.insert(port, 1u8, 0)
            .map_err(|e| DataplaneError::Other(e.into()))?;
        Ok(())
    }

    pub(crate) fn clear_syncookie(&self, port: u16) -> Result<()> {
        let mut bpf = self.bpf.lock().unwrap();
        let mut map: AyaHashMap<_, u16, u8> = AyaHashMap::try_from(
            bpf.map_mut(MAP_SYNCOOKIE_LISTENERS)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_SYNCOOKIE_LISTENERS.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;
        let _ = map.remove(&port);
        Ok(())
    }
}

/// Live handle to the PERCPU stats array.
#[derive(Clone)]
pub struct BpfStatsHandle {
    bpf: Arc<Mutex<Bpf>>,
}

impl BpfStatsHandle {
    pub(crate) fn read(&self) -> Result<Stats> {
        let bpf = self.bpf.lock().unwrap();
        let map: PerCpuArray<_, u64> = PerCpuArray::try_from(
            bpf.map(MAP_STATS)
                .ok_or_else(|| DataplaneError::MapNotFound(MAP_STATS.into()))?,
        )
        .map_err(|e| DataplaneError::Other(e.into()))?;

        let sum = |idx: u32| -> Result<u64> {
            let values = map
                .get(&idx, 0)
                .map_err(|e| DataplaneError::Other(e.into()))?;
            Ok(values.iter().sum())
        };

        Ok(Stats {
            packets_passed: sum(STAT_PACKETS_PASSED)?,
            packets_dropped: sum(STAT_PACKETS_DROPPED)?,
            packets_ratelimited: sum(STAT_PACKETS_RATELIMITED)?,
            packets_malformed: sum(STAT_PACKETS_MALFORMED)?,
            syn_cookies_sent: sum(STAT_SYN_COOKIES_SENT)?,
        })
    }
}

pub struct Loader {
    bpf_object_path: PathBuf,
    map_writer: MapWriter,
    stats_reader: StatsReader,
    bpf: Option<Arc<Mutex<Bpf>>>,
    attached_iface: Option<String>,
}

impl Loader {
    pub fn new(bpf_object_path: impl Into<PathBuf>) -> Self {
        Self {
            bpf_object_path: bpf_object_path.into(),
            map_writer: MapWriter::new_detached(),
            stats_reader: StatsReader::new_detached(),
            bpf: None,
            attached_iface: None,
        }
    }

    pub fn from_default_path() -> Self {
        Self::new(crate::DEFAULT_BPF_OBJECT_PATH)
    }

    pub fn map_writer(&self) -> MapWriter {
        self.map_writer.clone()
    }

    pub fn stats_reader(&self) -> StatsReader {
        self.stats_reader.clone()
    }

    pub fn bpf_object_path(&self) -> &Path {
        &self.bpf_object_path
    }

    pub async fn attach(&mut self, iface: &str, mode: AttachMode) -> Result<()> {
        if !self.bpf_object_path.exists() {
            return Err(DataplaneError::BpfObjectMissing(
                self.bpf_object_path.display().to_string(),
            ));
        }

        let mut bpf = BpfLoader::new()
            .load_file(&self.bpf_object_path)
            .map_err(|e| DataplaneError::Other(e.into()))?;

        let program: &mut Xdp = bpf
            .program_mut(XDP_PROGRAM_NAME)
            .ok_or_else(|| DataplaneError::ProgramNotFound(XDP_PROGRAM_NAME.into()))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| DataplaneError::Other(e.into()))?;

        program
            .load()
            .map_err(|e| DataplaneError::Other(e.into()))?;

        let flags = match mode {
            AttachMode::Driver => XdpFlags::DRV_MODE,
            AttachMode::Skb => XdpFlags::SKB_MODE,
            AttachMode::Hardware => XdpFlags::HW_MODE,
        };

        program
            .attach(iface, flags)
            .map_err(|e| DataplaneError::AttachFailed {
                iface: iface.into(),
                mode,
                source: e.into(),
            })?;

        let bpf = Arc::new(Mutex::new(bpf));
        self.map_writer
            .attach_backend(BpfMapHandles { bpf: bpf.clone() })?;
        self.stats_reader
            .attach_backend(BpfStatsHandle { bpf: bpf.clone() });
        self.bpf = Some(bpf);
        self.attached_iface = Some(iface.into());
        Ok(())
    }

    pub async fn detach(&mut self) -> Result<()> {
        // Dropping `Bpf` automatically detaches the program.
        self.bpf = None;
        self.attached_iface = None;
        Ok(())
    }

    pub fn attached_iface(&self) -> Option<&str> {
        self.attached_iface.as_deref()
    }
}
