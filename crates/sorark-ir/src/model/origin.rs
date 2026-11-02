//! Provenance metadata describing where a [`ContractModule`](super::ContractModule) came from.

use serde::{Deserialize, Serialize};

/// Origin metadata for a normalized Soroban contract module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceOrigin {
    /// Parsed from one or more Rust source files (`.rs`).
    RustSource { path: String },
    /// Decoded from the SEP-0048 custom sections of a compiled WebAssembly binary (`.wasm`).
    WasmBinary {
        path: String,
        byte_size: usize,
        protocol_version: Option<u32>,
        pre_release_version: Option<u32>,
        rs_soroban_env_version: Option<String>,
        rustc_version: Option<String>,
    },
}

impl SourceOrigin {
    /// Returns the file or directory path this module was loaded from.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::RustSource { path } | Self::WasmBinary { path, .. } => path,
        }
    }

    /// Returns the Soroban protocol version declared in `contractenvmetav0`, if known.
    ///
    /// Always `None` for Rust sources, which do not carry an environment meta section.
    #[must_use]
    pub fn protocol_version(&self) -> Option<u32> {
        match self {
            Self::WasmBinary {
                protocol_version, ..
            } => *protocol_version,
            Self::RustSource { .. } => None,
        }
    }
}
