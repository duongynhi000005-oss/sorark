//! Data structures holding WebAssembly metrics and inspection reports.

use serde::{Deserialize, Serialize};
use sorark_ir::{ContractModule, Diagnostic};

/// Low-level WebAssembly and SEP-0048 metadata metrics extracted from a `.wasm` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmMetrics {
    /// Total size of the `.wasm` binary in bytes.
    pub byte_size: usize,
    /// Total number of WebAssembly exports (functions, memories, tables, globals).
    pub export_count: usize,
    /// Names of exported contract functions.
    pub exported_functions: Vec<String>,
    /// Total number of host imports referenced by the module.
    pub import_count: usize,
    /// Initial linear memory pages requested (each page is 64 KiB).
    pub initial_memory_pages: Option<u64>,
    /// Maximum linear memory pages allowed, if specified.
    pub max_memory_pages: Option<u64>,
    /// Whether the SEP-0048 `contractspecv0` custom section is present.
    pub has_contractspecv0: bool,
    /// Whether the SEP-0048 `contractenvmetav0` custom section is present.
    pub has_contractenvmetav0: bool,
    /// Whether the SEP-0048 `contractmetav0` custom section is present.
    pub has_contractmetav0: bool,
    /// Stellar protocol version extracted from `contractenvmetav0`.
    pub protocol_version: Option<u32>,
    /// Pre-release version extracted from `contractenvmetav0`.
    pub pre_release_version: Option<u32>,
    /// `soroban-env-common` crate version extracted from `contractmetav0` (`rssdkver`).
    pub rs_soroban_env_version: Option<String>,
    /// Rust compiler version extracted from `contractmetav0` (`rsver`).
    pub rustc_version: Option<String>,
}

impl WasmMetrics {
    /// Initializes an empty [`WasmMetrics`] record for a binary of `byte_size` bytes.
    #[must_use]
    pub const fn with_byte_size(byte_size: usize) -> Self {
        Self {
            byte_size,
            export_count: 0,
            exported_functions: Vec::new(),
            import_count: 0,
            initial_memory_pages: None,
            max_memory_pages: None,
            has_contractspecv0: false,
            has_contractenvmetav0: false,
            has_contractmetav0: false,
            protocol_version: None,
            pre_release_version: None,
            rs_soroban_env_version: None,
            rustc_version: None,
        }
    }
}

/// Full report returned when inspecting a compiled Soroban `.wasm` binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmInspectionReport {
    /// Unified [`ContractModule`] reconstructed from `contractspecv0` XDR entries.
    pub module: ContractModule,
    /// Binary size, export/import counts, and SEP-0048 metadata metrics.
    pub metrics: WasmMetrics,
    /// Resource budget and SEP-0048 metadata diagnostics (`ARK-WASM-001`).
    pub diagnostics: Vec<Diagnostic>,
}
