//! Error types for the `sorark-ast` Rust static analysis engine.

use thiserror::Error;

/// Errors that can occur while scanning and parsing Soroban Rust source files.
#[derive(Debug, Error)]
pub enum AstEngineError {
    /// Failed to read a file or directory on disk.
    #[error("Failed to read path `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// `syn` encountered invalid Rust syntax in a `.rs` file.
    #[error("Rust syntax error in `{file}`: {source}")]
    Syntax {
        file: String,
        #[source]
        source: syn::Error,
    },

    /// Target directory contained no `.rs` source files after exclusions.
    #[error("No Rust source files (`.rs`) found under `{path}`")]
    NoRustFiles { path: String },
}
