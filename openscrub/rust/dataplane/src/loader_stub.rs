// SPDX-License-Identifier: Apache-2.0
//
// Non-Linux stub Loader. Lets the crate compile on Windows / macOS so
// developers can iterate on MapWriter without a kernel. All `attach`
// calls return `DataplaneError::UnsupportedPlatform`.

use std::path::{Path, PathBuf};

use crate::error::{AttachMode, DataplaneError, Result};
use crate::maps::MapWriter;
use crate::stats::StatsReader;

pub struct Loader {
    bpf_object_path: PathBuf,
    map_writer: MapWriter,
    stats_reader: StatsReader,
}

impl Loader {
    pub fn new(bpf_object_path: impl Into<PathBuf>) -> Self {
        Self {
            bpf_object_path: bpf_object_path.into(),
            map_writer: MapWriter::new_detached(),
            stats_reader: StatsReader::new_detached(),
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

    /// Always errors on non-Linux platforms.
    pub async fn attach(&mut self, _iface: &str, _mode: AttachMode) -> Result<()> {
        Err(DataplaneError::UnsupportedPlatform)
    }

    /// No-op detach.
    pub async fn detach(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_loader_constructs() {
        let l = Loader::from_default_path();
        assert!(l.bpf_object_path().ends_with("openscrub.bpf.o"));
        assert!(l.map_writer().is_empty());
    }

    #[tokio::test]
    async fn stub_attach_errors_with_unsupported_platform() {
        let mut l = Loader::from_default_path();
        let err = l.attach("lo", AttachMode::Skb).await.unwrap_err();
        assert!(matches!(err, DataplaneError::UnsupportedPlatform));
    }
}
