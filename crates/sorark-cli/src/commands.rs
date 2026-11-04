//! Execution handlers for each `sorark` CLI subcommand (`lint`, `diff`, `inspect`, `rules`, `init`).

use crate::cli::{Cli, Commands};
use crate::format::{
    OutputFormat, render_diagnostics, render_rule_catalog, render_wasm_inspection,
};
use anyhow::{Context, Result, bail};
use sorark_ast::scan_rust_path;
use sorark_diff::compare_contract_modules;
use sorark_ir::{
    ContractModule, Diagnostic, Severity, SorarkConfig, StorageTier, builtin_rule_catalog,
};
use sorark_wasm::inspect_wasm_file;
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

/// Dispatches the parsed [`Cli`] arguments to the selected subcommand handler.
pub fn execute(cli: Cli) -> Result<ExitCode> {
    let mut config = load_config(cli.config.as_deref())?;
    if cli.deny_warnings {
        config.fail_on_warnings = true;
    }

    match cli.command {
        Commands::Lint {
            path,
            format,
            rule,
            suggest_patch,
        } => run_lint(&path, format, rule.as_deref(), suggest_patch, &config),
        Commands::Diff { old, new, format } => run_diff(&old, &new, format, &config),
        Commands::Inspect { wasm, format } => run_inspect(&wasm, format, &config),
        Commands::Rules { format } => run_rules(format),
        Commands::Init { output, force } => run_init(&output, force),
    }
}

/// Executes `sorark lint` against either a compiled `.wasm` file or a Rust source path.
fn run_lint(
    path: &Path,
    format: OutputFormat,
    rule_filter: Option<&str>,
    suggest_patch: bool,
    config: &SorarkConfig,
) -> Result<ExitCode> {
    let (mut diagnostics, ast_ctx) = if is_wasm_path(path) {
        (inspect_wasm_file(path, config)?.diagnostics, None)
    } else {
        let report = scan_rust_path(path, config)?;
        (report.diagnostics, Some(report.context))
    };

    if let Some(filter) = rule_filter {
        diagnostics.retain(|d| d.rule_id.eq_ignore_ascii_case(filter));
    }

    let rendered = render_diagnostics(&diagnostics, format)?;
    print!("{rendered}");

    if suggest_patch
        && let Some(ctx) = ast_ctx.as_ref()
    {
        let patch = render_missing_ttl_patches(&diagnostics, ctx, config);
        if !patch.is_empty() {
            print!("\n{patch}");
        }
    }

    Ok(exit_code_for_diagnostics(
        &diagnostics,
        config.fail_on_warnings,
    ))
}

/// Synthesizes unified diff patches (`--- a/...`, `+++ b/...`) inserting `extend_ttl` calls
/// immediately after `ARK-STOR-002` unextended `instance()` or `persistent()` storage writes.
fn render_missing_ttl_patches(
    diagnostics: &[Diagnostic],
    ctx: &sorark_ast::parser::AstAnalysisContext,
    config: &SorarkConfig,
) -> String {
    let threshold = config.min_persistent_ttl;
    let extend_to = threshold.saturating_mul(4).min(config.max_entry_ttl).max(threshold);
    let mut out = String::new();

    for diag in diagnostics.iter().filter(|d| d.rule_id == "ARK-STOR-002") {
        let Some(span) = diag.span.as_ref() else {
            continue;
        };
        let matching_op = ctx
            .functions
            .iter()
            .filter(|f| f.file == span.file)
            .flat_map(|f| f.storage_ops.iter())
            .find(|op| op.line == span.line);

        let Ok(file_text) = std::fs::read_to_string(&span.file) else {
            continue;
        };
        let lines: Vec<&str> = file_text.lines().collect();
        if span.line == 0 || span.line > lines.len() {
            continue;
        }
        let target_line = lines[span.line - 1];
        let indent: String = target_line
            .chars()
            .take_while(|c| c.is_whitespace())
            .collect();

        let ttl_stmt = match matching_op {
            Some(op) if op.tier == StorageTier::Instance => {
                format!("{indent}env.storage().instance().extend_ttl({threshold}, {extend_to});")
            }
            Some(op) => {
                let key_arg = op.key_expr.as_deref().unwrap_or("&key");
                format!(
                    "{indent}env.storage().persistent().extend_ttl({key_arg}, {threshold}, {extend_to});"
                )
            }
            None => format!("{indent}env.storage().persistent().extend_ttl(&key, {threshold}, {extend_to});"),
        };

        let normalized_path = span.file.replace('\\', "/");
        let _ = writeln!(out, "--- a/{normalized_path}");
        let _ = writeln!(out, "+++ b/{normalized_path}");
        let _ = writeln!(out, "@@ -{},1 +{},2 @@", span.line, span.line);
        let _ = writeln!(out, " {target_line}");
        let _ = writeln!(out, "+{ttl_stmt}");
    }

    out
}

/// Executes `sorark diff` between a baseline (`--old`) and candidate (`--new`) contract.
fn run_diff(
    old: &Path,
    new: &Path,
    format: OutputFormat,
    config: &SorarkConfig,
) -> Result<ExitCode> {
    let old_module = load_contract_module(old, config).with_context(|| {
        format!(
            "Failed to load baseline (--old) contract `{}`",
            old.display()
        )
    })?;
    let new_module = load_contract_module(new, config).with_context(|| {
        format!(
            "Failed to load candidate (--new) contract `{}`",
            new.display()
        )
    })?;

    let diff_report = compare_contract_modules(&old_module, &new_module, config);
    let rendered = render_diagnostics(&diff_report.diagnostics, format)?;
    print!("{rendered}");
    Ok(exit_code_for_diagnostics(
        &diff_report.diagnostics,
        config.fail_on_warnings,
    ))
}

/// Executes `sorark inspect` on a compiled `.wasm` binary.
fn run_inspect(wasm: &Path, format: OutputFormat, config: &SorarkConfig) -> Result<ExitCode> {
    let report = inspect_wasm_file(wasm, config)?;
    let rendered = render_wasm_inspection(&report, format)?;
    print!("{rendered}");
    Ok(exit_code_for_diagnostics(
        &report.diagnostics,
        config.fail_on_warnings,
    ))
}

/// Executes `sorark rules` to print the built-in SORARK rule catalog.
fn run_rules(format: OutputFormat) -> Result<ExitCode> {
    let catalog = builtin_rule_catalog();
    let rendered = render_rule_catalog(&catalog, format)?;
    print!("{rendered}");
    Ok(ExitCode::SUCCESS)
}

/// Executes `sorark init` to generate a documented `sorark.toml` configuration file.
fn run_init(output: &Path, force: bool) -> Result<ExitCode> {
    if output.exists() && !force {
        bail!(
            "Configuration file `{}` already exists. Pass `--force` to overwrite it.",
            output.display()
        );
    }
    std::fs::write(output, SorarkConfig::default_toml_template())
        .with_context(|| format!("Failed to write `{}`", output.display()))?;
    println!("Created SORARK configuration at `{}`", output.display());
    Ok(ExitCode::SUCCESS)
}

/// Loads `sorark.toml` from `explicit_path`, or from `./sorark.toml` if present,
/// falling back to [`SorarkConfig::default`].
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

/// Returns `true` if `path` points to a `.wasm` file on disk.
fn is_wasm_path(path: &Path) -> bool {
    path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("wasm")
}

/// Loads a [`ContractModule`] from either a compiled `.wasm` binary or a Rust source path.
fn load_contract_module(path: &Path, config: &SorarkConfig) -> Result<ContractModule> {
    if is_wasm_path(path) {
        let report = inspect_wasm_file(path, config)?;
        Ok(report.module)
    } else {
        let report = scan_rust_path(path, config)?;
        Ok(report.context.module)
    }
}

/// Computes the process [`ExitCode`] (`0` when clean, `1` when blocking diagnostics exist).
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
