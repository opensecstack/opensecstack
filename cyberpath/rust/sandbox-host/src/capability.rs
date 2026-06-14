use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CapabilityBag {
    pub fs_allowlist: Vec<PathBuf>,
    pub network_allow: bool,
    pub fuel_limit: u64,
    pub memory_limit_bytes: u64,
}

impl Default for CapabilityBag {
    fn default() -> Self {
        default_capabilities()
    }
}

pub fn default_capabilities() -> CapabilityBag {
    CapabilityBag {
        fs_allowlist: vec![
            PathBuf::from("/lab"),
            PathBuf::from("/scratch"),
            PathBuf::from("/etc/lab.json"),
        ],
        network_allow: false,
        fuel_limit: 1_000_000_000,
        memory_limit_bytes: 512 * 1024 * 1024,
    }
}

#[derive(Debug, serde::Deserialize)]
struct NetworkSpec {
    #[serde(default)]
    egress_whitelist: Vec<String>,
}

impl Default for NetworkSpec {
    fn default() -> Self {
        NetworkSpec { egress_whitelist: vec![] }
    }
}

#[derive(Debug, serde::Deserialize)]
struct LabManifest {
    #[serde(default = "default_time_limit")]
    time_limit_seconds: u64,
    #[serde(default)]
    network: NetworkSpec,
}

fn default_time_limit() -> u64 {
    1800
}

/// Parse a YAML lab manifest from raw bytes and return a `CapabilityBag`.
///
/// On parse error, logs a warning and returns `default_capabilities()`.
pub fn from_lab_manifest_bytes(data: &[u8]) -> CapabilityBag {
    match serde_yaml::from_slice::<LabManifest>(data) {
        Ok(manifest) => CapabilityBag {
            fs_allowlist: default_capabilities().fs_allowlist,
            network_allow: !manifest.network.egress_whitelist.is_empty(),
            fuel_limit: manifest.time_limit_seconds * 1_000_000,
            memory_limit_bytes: 512 * 1024 * 1024,
        },
        Err(err) => {
            tracing::warn!(error = %err, "from_lab_manifest_bytes: failed to parse YAML, using defaults");
            default_capabilities()
        }
    }
}

/// Build a `CapabilityBag` from the lab manifest stored on disk.
///
/// Reads `{CYBERPATH_LAB_MANIFEST_DIR}/{lab_id}/lab.yaml` (env var defaults
/// to `content/tracks`). If the file is missing or unreadable, falls back to
/// `default_capabilities()`.
pub fn from_lab_manifest(lab_id: &str) -> CapabilityBag {
    let base_dir = std::env::var("CYBERPATH_LAB_MANIFEST_DIR")
        .unwrap_or_else(|_| "content/tracks".to_string());
    let manifest_path = PathBuf::from(&base_dir).join(lab_id).join("lab.yaml");

    match std::fs::read(&manifest_path) {
        Ok(data) => {
            tracing::debug!(lab_id, path = %manifest_path.display(), "from_lab_manifest: loaded manifest");
            from_lab_manifest_bytes(&data)
        }
        Err(err) => {
            tracing::debug!(lab_id, path = %manifest_path.display(), error = %err, "from_lab_manifest: manifest not found, using defaults");
            default_capabilities()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_capabilities_deny_network() {
        assert!(!default_capabilities().network_allow);
    }

    #[test]
    fn default_capabilities_has_lab_in_fs_allowlist() {
        let bag = default_capabilities();
        assert!(
            bag.fs_allowlist.iter().any(|p| p == &PathBuf::from("/lab")),
            "default allowlist must include /lab"
        );
    }

    #[test]
    fn default_capabilities_fuel_limit_positive() {
        assert!(default_capabilities().fuel_limit > 0);
    }

    #[test]
    fn default_capabilities_memory_limit_is_512mib() {
        assert_eq!(default_capabilities().memory_limit_bytes, 512 * 1024 * 1024);
    }

    #[test]
    fn from_lab_manifest_returns_valid_bag() {
        let bag = from_lab_manifest("phishing/recognise-spear");
        assert!(bag.fuel_limit > 0);
        assert!(!bag.fs_allowlist.is_empty());
    }

    #[test]
    fn manifest_bytes_maps_time_limit_to_fuel() {
        let yaml = b"time_limit_seconds: 600\nnetwork:\n  egress_whitelist: []\n";
        let bag = from_lab_manifest_bytes(yaml);
        assert_eq!(bag.fuel_limit, 600 * 1_000_000);
    }

    #[test]
    fn manifest_bytes_empty_egress_means_no_network() {
        let yaml = b"time_limit_seconds: 1800\nnetwork:\n  egress_whitelist: []\n";
        let bag = from_lab_manifest_bytes(yaml);
        assert!(!bag.network_allow);
    }

    #[test]
    fn manifest_bytes_nonempty_egress_allows_network() {
        let yaml = b"time_limit_seconds: 1800\nnetwork:\n  egress_whitelist:\n    - taxii.lab.opensecstack.io\n";
        let bag = from_lab_manifest_bytes(yaml);
        assert!(bag.network_allow);
    }

    #[test]
    fn manifest_bytes_invalid_yaml_returns_defaults() {
        let bag = from_lab_manifest_bytes(b"{{{{ not yaml");
        assert_eq!(bag.fuel_limit, default_capabilities().fuel_limit);
    }

    #[test]
    fn manifest_bytes_missing_time_limit_uses_default() {
        let yaml = b"network:\n  egress_whitelist: []\n";
        let bag = from_lab_manifest_bytes(yaml);
        assert_eq!(bag.fuel_limit, 1800 * 1_000_000);
    }
}
