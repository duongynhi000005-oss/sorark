use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

/// Stellar Mainnet minimum TTL for temporary entries (`16` ledgers, ~80 seconds).
pub const MAINNET_MIN_TEMP_ENTRY_TTL: u32 = 16;
/// Stellar Mainnet minimum TTL for persistent/instance entries (`4,096` ledgers, ~5.6 hours).
pub const MAINNET_MIN_PERSISTENT_ENTRY_TTL: u32 = 4_096;
/// Stellar Mainnet maximum TTL for any ledger entry (`3,110,400` ledgers, ~180 days).
pub const MAINNET_MAX_ENTRY_TTL: u32 = 3_110_400;
/// Default WASM size warning threshold (`48 KiB`).
pub const DEFAULT_WASM_WARN_BYTES: usize = 49_152;
/// Stellar Mainnet ledger entry hard size limit (`64 KiB`).
pub const MAINNET_LEDGER_ENTRY_MAX_BYTES: usize = 65_536;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to parse TOML in `{path}`: {source}")]
    Toml {
        path: String,
        #[source]
        source: toml::de::Error,
    },
}

/// Workspace or project configuration loaded from `sorark.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SorarkConfig {
    /// Minimum allowed TTL extension target for persistent/instance entries.
    pub min_persistent_ttl: u32,
    /// Minimum allowed TTL extension target for temporary entries.
    pub min_temp_ttl: u32,
    /// Maximum allowed TTL extension target (Mainnet default: `3,110,400` ledgers).
    pub max_entry_ttl: u32,
    /// Compiled `.wasm` size threshold (in bytes) that triggers a warning.
    pub wasm_warn_bytes: usize,
    /// Compiled `.wasm` size hard ceiling (in bytes) that triggers an error.
    pub wasm_max_bytes: usize,
    /// List of rule IDs disabled globally (e.g. `["ARK-UPG-002"]`).
    pub disabled_rules: Vec<String>,
    /// Directory or file path substrings to exclude when scanning directories.
    pub exclude_paths: Vec<String>,
    /// Treat warnings as errors in CLI exit code calculation.
    pub fail_on_warnings: bool,
}

impl Default for SorarkConfig {
    fn default() -> Self {
        Self {
            min_persistent_ttl: MAINNET_MIN_PERSISTENT_ENTRY_TTL,
            min_temp_ttl: MAINNET_MIN_TEMP_ENTRY_TTL,
            max_entry_ttl: MAINNET_MAX_ENTRY_TTL,
            wasm_warn_bytes: DEFAULT_WASM_WARN_BYTES,
            wasm_max_bytes: MAINNET_LEDGER_ENTRY_MAX_BYTES,
            disabled_rules: Vec::new(),
            exclude_paths: vec!["target".to_string(), ".git".to_string()],
            fail_on_warnings: false,
        }
    }
}

impl SorarkConfig {
    /// Loads a `SorarkConfig` from a TOML file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let raw = std::fs::read_to_string(path_ref).map_err(|source| ConfigError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&raw, &path_ref.display().to_string())
    }

    /// Parses a `SorarkConfig` from a TOML string.
    pub fn from_toml_str(raw: &str, label: &str) -> Result<Self, ConfigError> {
        toml::from_str(raw).map_err(|source| ConfigError::Toml {
            path: label.to_string(),
            source,
        })
    }

    /// Returns `true` if `rule_id` is enabled under this configuration.
    #[must_use]
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        !self
            .disabled_rules
            .iter()
            .any(|r| r.eq_ignore_ascii_case(rule_id))
    }

    /// Returns a set of disabled rule IDs normalized to uppercase.
    #[must_use]
    pub fn disabled_rule_set(&self) -> HashSet<String> {
        self.disabled_rules
            .iter()
            .map(|r| r.to_ascii_uppercase())
            .collect()
    }

    /// Generates a documented starter `sorark.toml` template.
    #[must_use]
    pub fn default_toml_template() -> &'static str {
        r#"# SORARK Configuration (sorark.toml)
# Stellar Mainnet State Archival & Resource Limits

# Minimum persistent/instance TTL in ledgers (Mainnet default: 4096 ledgers / ~5.6 hours)
min_persistent_ttl = 4096

# Minimum temporary entry TTL in ledgers (Mainnet default: 16 ledgers / ~80 seconds)
min_temp_ttl = 16

# Maximum entry TTL in ledgers (Mainnet default: 3,110,400 ledgers / ~180 days)
max_entry_ttl = 3110400

# Compiled WASM size thresholds in bytes (48 KiB warning, 64 KiB hard limit)
wasm_warn_bytes = 49152
wasm_max_bytes = 65536

# Treat warnings as non-zero exit codes in CI
fail_on_warnings = false

# Disable specific rule IDs if needed (e.g. ["ARK-UPG-002"])
disabled_rules = []

# Paths to skip during recursive workspace scans
exclude_paths = ["target", ".git"]
"#
    }
}
