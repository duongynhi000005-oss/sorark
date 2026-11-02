//! Command-line argument definitions (`clap`) for the `sorark` binary.

use crate::format::OutputFormat;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Top-level CLI parser for `sorark`.
#[derive(Debug, Parser)]
#[command(
    name = "sorark",
    version,
    about = "SORARK: State Archival, Storage-Tier Safety, and Upgrade-Compatibility Analyzer for Stellar Soroban",
    long_about = "Analyzes Stellar Soroban smart contracts (Rust source and compiled .wasm binaries) for 64 KiB instance storage bombs, missing extend_ttl archival hazards, temporary storage exploits, and state-corrupting v1-to-v2 upgrade mutations."
)]
pub struct Cli {
    /// Path to an optional `sorark.toml` configuration file.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Treat warning-level diagnostics as non-zero exit code failures.
    #[arg(long, global = true)]
    pub deny_warnings: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Supported subcommands for the `sorark` CLI.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run static storage-tier, TTL archival, and upgrade-auth checks on a Soroban Rust project or `.wasm` binary.
    Lint {
        /// Path to a Soroban project directory, `.rs` file, or compiled `.wasm` file.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format (`text`, `json`, `sarif`, `markdown`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        /// Filter output to only a specific rule ID (e.g. `ARK-STOR-001`).
        #[arg(long)]
        rule: Option<String>,
    },

    /// Check storage-layout (`ScMap`/`ScVec`) and ABI upgrade safety between two contract versions (`v1` vs `v2`).
    Diff {
        /// Path to the baseline (`v1`) contract (Rust directory, `.rs` file, or `.wasm` binary).
        #[arg(long)]
        old: PathBuf,

        /// Path to the candidate (`v2`) contract (Rust directory, `.rs` file, or `.wasm` binary).
        #[arg(long)]
        new: PathBuf,

        /// Output format (`text`, `json`, `sarif`, `markdown`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Inspect a compiled Soroban `.wasm` binary's SEP-0048 XDR specification and ledger byte budget.
    Inspect {
        /// Path to the compiled `.wasm` contract file.
        wasm: PathBuf,

        /// Output format (`text`, `json`, `markdown`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// List all built-in SORARK analysis rules, severities, and remediations.
    Rules {
        /// Output format (`text`, `json`, `markdown`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Create a documented `sorark.toml` configuration file in the target directory.
    Init {
        /// Destination path for the generated configuration file.
        #[arg(long, default_value = "sorark.toml")]
        output: PathBuf,

        /// Overwrite existing configuration file if present.
        #[arg(long)]
        force: bool,
    },
}
