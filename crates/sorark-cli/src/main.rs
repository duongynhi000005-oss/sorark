mod format;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use format::{OutputFormat, render_diagnostics, render_wasm_inspection};
use sorark_ast::scan_rust_path;
use sorark_diff::compare_contract_modules;
use sorark_ir::{ContractModule, Diagnostic, Severity, SorarkConfig, builtin_rule_catalog};
use sorark_wasm::inspect_wasm_file;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "sorark",
    version,
    about = "SORARK: State Archival, Storage-Tier Safety, and Upgrade-Compatibility Analyzer for Stellar Soroban",
    long_about = "Analyzes Stellar Soroban smart contracts (Rust source and compiled .wasm binaries) for 64 KiB instance storage bombs, missing extend_ttl archival hazards, temporary storage exploits, and state-corrupting v1-to-v2 upgrade mutations."
)]
struct Cli {
    /// Path to an optional `sorark.toml` configuration file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Treat warning-level diagnostics as non-zero exit code failures.
    #[arg(long, global = true)]
    deny_warnings: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn execute(cli: Cli) -> Result<ExitCode> {
    let mut config = load_config(cli.config.as_deref())?;
    if cli.deny_warnings {
        config.fail_on_warnings = true;
    }

    match cli.command {
        Commands::Lint { path, format, rule } => {
            let mut diagnostics = if is_wasm_path(&path) {
                let report = inspect_wasm_file(&path, &config)?;
                report.diagnostics
            } else {
                let report = scan_rust_path(&path, &config)?;
                report.diagnostics
            };

            if let Some(rule_filter) = rule {
                diagnostics.retain(|d| d.rule_id.eq_ignore_ascii_case(&rule_filter));
            }

            let rendered = render_diagnostics(&diagnostics, format)?;
            print!("{rendered}");
            Ok(exit_code_for_diagnostics(
                &diagnostics,
                config.fail_on_warnings,
            ))
        }

        Commands::Diff { old, new, format } => {
            let old_module = load_contract_module(&old, &config).with_context(|| {
                format!(
                    "Failed to load baseline (--old) contract `{}`",
                    old.display()
                )
            })?;
            let new_module = load_contract_module(&new, &config).with_context(|| {
                format!(
                    "Failed to load candidate (--new) contract `{}`",
                    new.display()
                )
            })?;

            let diff_report = compare_contract_modules(&old_module, &new_module, &config);
            let rendered = render_diagnostics(&diff_report.diagnostics, format)?;
            print!("{rendered}");
            Ok(exit_code_for_diagnostics(
                &diff_report.diagnostics,
                config.fail_on_warnings,
            ))
        }

        Commands::Inspect { wasm, format } => {
            let report = inspect_wasm_file(&wasm, &config)?;
            let rendered = render_wasm_inspection(&report, format)?;
            print!("{rendered}");
            Ok(exit_code_for_diagnostics(
                &report.diagnostics,
                config.fail_on_warnings,
            ))
        }

        Commands::Rules { format } => {
            let catalog = builtin_rule_catalog();
            match format {
                OutputFormat::Json | OutputFormat::Sarif => {
                    println!("{}", serde_json::to_string_pretty(&catalog)?);
                }
                OutputFormat::Markdown => {
                    println!("| Rule ID | Category | Default Severity | Title | Description |");
                    println!("| :--- | :--- | :--- | :--- | :--- |");
                    for r in &catalog {
                        println!(
                            "| `{}` | `{}` | **{}** | {} | {} |",
                            r.id, r.category, r.default_severity, r.title, r.description
                        );
                    }
                }
                OutputFormat::Text => {
                    for r in &catalog {
                        println!(
                            "{:<14} [{:<8}] ({})\n  {}\n  Remediation: {}\n",
                            r.id, r.default_severity, r.category, r.title, r.remediation
                        );
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Init { output, force } => {
            if output.exists() && !force {
                bail!(
                    "Configuration file `{}` already exists. Pass `--force` to overwrite it.",
                    output.display()
                );
            }
            std::fs::write(&output, SorarkConfig::default_toml_template())
                .with_context(|| format!("Failed to write `{}`", output.display()))?;
            println!("Created SORARK configuration at `{}`", output.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn load_config(explicit_path: Option<&Path>) -> Result<SorarkConfig> {
    if let Some(path) = explicit_path {
        return Ok(SorarkConfig::from_file(path)?);
    }
    let default_path = Path::new("sorark.toml");
    if default_path.exists() {
        return Ok(SorarkConfig::from_file(default_path)?);
    }
    Ok(SorarkConfig::default())
}

fn is_wasm_path(path: &Path) -> bool {
    path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("wasm")
}

fn load_contract_module(path: &Path, config: &SorarkConfig) -> Result<ContractModule> {
    if is_wasm_path(path) {
        let report = inspect_wasm_file(path, config)?;
        Ok(report.module)
    } else {
        let report = scan_rust_path(path, config)?;
        Ok(report.context.module)
    }
}

fn exit_code_for_diagnostics(diagnostics: &[Diagnostic], fail_on_warnings: bool) -> ExitCode {
    let has_failure = diagnostics.iter().any(|d| {
        d.severity == Severity::Error || (fail_on_warnings && d.severity == Severity::Warning)
    });
    if has_failure {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
