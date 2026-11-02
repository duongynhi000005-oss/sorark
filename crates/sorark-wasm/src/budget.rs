//! `ARK-WASM-001` resource budget and SEP-0048 custom section diagnostics.

use crate::metrics::WasmMetrics;
use sorark_ir::{Confidence, Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan};

/// Evaluates `ARK-WASM-001` diagnostics for a compiled `.wasm` binary:
/// 1. Binary byte size vs. Stellar ledger entry limits (`wasm_max_bytes` / `wasm_warn_bytes`).
/// 2. Presence of SEP-0048 `contractspecv0` and `contractenvmetav0` sections.
pub(crate) fn evaluate_wasm_diagnostics(
    path_label: &str,
    metrics: &WasmMetrics,
    config: &SorarkConfig,
) -> Vec<Diagnostic> {
    if !config.is_rule_enabled("ARK-WASM-001") {
        return Vec::new();
    }

    let mut out = Vec::new();
    check_wasm_byte_size(path_label, metrics, config, &mut out);
    check_required_custom_sections(path_label, metrics, &mut out);
    out
}

/// Checks whether the `.wasm` binary exceeds the error or warning byte-size thresholds.
fn check_wasm_byte_size(
    path_label: &str,
    metrics: &WasmMetrics,
    config: &SorarkConfig,
    out: &mut Vec<Diagnostic>,
) {
    let span = SourceSpan::new(path_label, 1, 1);

    if metrics.byte_size > config.wasm_max_bytes {
        out.push(
            Diagnostic::builder(
                "ARK-WASM-001",
                "WASM Binary Exceeds Stellar Ledger Entry Size Limit",
                RuleCategory::ResourceBudget,
                Severity::Error,
            )
            .confidence(Confidence::High)
            .message(format!(
                "Compiled contract `{path_label}` is {} bytes ({:.1} KiB), exceeding the Stellar Mainnet ledger entry maximum of {} bytes (64.0 KiB).",
                metrics.byte_size,
                metrics.byte_size as f64 / 1024.0,
                config.wasm_max_bytes
            ))
            .help(
                "Configure `[profile.release]` with `opt-level = \"z\"`, `lto = true`, `codegen-units = 1`, `strip = \"symbols\"` and build via `stellar contract build`.",
            )
            .span(span)
            .build(),
        );
    } else if metrics.byte_size > config.wasm_warn_bytes {
        out.push(
            Diagnostic::builder(
                "ARK-WASM-001",
                "WASM Binary Approaching Stellar Ledger Size Limit",
                RuleCategory::ResourceBudget,
                Severity::Warning,
            )
            .confidence(Confidence::High)
            .message(format!(
                "Compiled contract `{path_label}` is {} bytes ({:.1} KiB), exceeding the warning threshold of {} bytes ({:.1} KiB).",
                metrics.byte_size,
                metrics.byte_size as f64 / 1024.0,
                config.wasm_warn_bytes,
                config.wasm_warn_bytes as f64 / 1024.0
            ))
            .help(
                "Reduce WASM binary size to minimize Soroban contract code rent and invocation instruction overhead.",
            )
            .span(span)
            .build(),
        );
    }
}

/// Emits warnings when standard SEP-0048 custom sections (`contractspecv0` or
/// `contractenvmetav0`) are missing from the `.wasm` binary.
fn check_required_custom_sections(
    path_label: &str,
    metrics: &WasmMetrics,
    out: &mut Vec<Diagnostic>,
) {
    if !metrics.has_contractspecv0 {
        out.push(
            Diagnostic::builder(
                "ARK-WASM-001",
                "Missing SEP-0048 `contractspecv0` Custom Section",
                RuleCategory::ResourceBudget,
                Severity::Warning,
            )
            .confidence(Confidence::High)
            .message(format!(
                "WASM binary `{path_label}` does not contain a `contractspecv0` section. Stellar SDKs, explorers, and upgrade compatibility checkers cannot inspect its interface."
            ))
            .help(
                "Ensure the contract uses `#[contract]` and `#[contractimpl]` from `soroban-sdk` and is compiled without stripping custom sections.",
            )
            .span(SourceSpan::new(path_label, 1, 1))
            .build(),
        );
    }

    if !metrics.has_contractenvmetav0 {
        out.push(
            Diagnostic::builder(
                "ARK-WASM-001",
                "Missing SEP-0048 `contractenvmetav0` Custom Section",
                RuleCategory::ResourceBudget,
                Severity::Warning,
            )
            .confidence(Confidence::High)
            .message(format!(
                "WASM binary `{path_label}` does not contain a `contractenvmetav0` section declaring its target Soroban host protocol version."
            ))
            .help(
                "Compile the contract using `soroban-sdk` on target `wasm32-unknown-unknown` or `wasm32v1-none`.",
            )
            .span(SourceSpan::new(path_label, 1, 1))
            .build(),
        );
    }
}
