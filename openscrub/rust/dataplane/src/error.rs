// SPDX-License-Identifier: Apache-2.0

use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DataplaneError>;

#[derive(Debug, Error)]
pub enum DataplaneError {
    #[error("BPF object not found at {0}; run `make -C openscrub/ebpf` first")]
    BpfObjectMissing(String),

    #[error("XDP program `{0}` not found in BPF object")]
    ProgramNotFound(String),

    #[error("BPF map `{0}` not found in BPF object")]
    MapNotFound(String),

    #[error("interface `{0}` not found")]
    InterfaceNotFound(String),

    #[error("XDP attach failed on `{iface}` ({mode:?}): {source}")]
    AttachFailed {
        iface: String,
        mode: AttachMode,
        #[source]
        source: anyhow::Error,
    },

    #[error("invalid CIDR `{0}`")]
    InvalidCidr(String),

    #[error("rate must be > 0 packets/sec, got {0}")]
    InvalidRate(u32),

    #[error("operation not supported on this platform — Linux + CAP_BPF required")]
    UnsupportedPlatform,

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Native driver mode (best performance, NIC must support XDP).
    Driver,
    /// Generic skb mode (works on any NIC, lower performance).
    Skb,
    /// Hardware offload (Smart NIC).
    Hardware,
}
