//! Error types for the `sorark-wasm` WebAssembly and XDR inspection engine.

use thiserror::Error;

/// Errors that can occur when reading, parsing, or decoding a Soroban `.wasm` binary.
#[derive(Debug, Error)]
pub enum WasmEngineError {
    /// Failed to read the `.wasm` binary from disk.
    #[error("Failed to read WASM file `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// `wasmparser` rejected the binary as malformed WebAssembly.
    #[error("Invalid WebAssembly binary in `{path}`: {message}")]
    WasmParse { path: String, message: String },

    /// `stellar-xdr` failed to decode an XDR entry inside a SEP-0048 custom section.
    #[error("Failed to decode Stellar XDR section `{section}` in `{path}`: {source}")]
    XdrDecode {
        path: String,
        section: &'static str,
        #[source]
        source: stellar_xdr::Error,
    },
}
