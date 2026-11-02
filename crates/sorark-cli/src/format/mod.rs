//! Output formatting dispatchers (`Text`, `Json`, `Sarif`, and `Markdown`) for `sorark-cli`.

mod inspect;
mod json;
mod markdown;
mod sarif;
mod text;

use clap::ValueEnum;
use inspect::render_wasm_inspection_text;
use json::render_diagnostics_json;
use markdown::{render_diagnostics_markdown, render_rules_markdown};
use sarif::render_diagnostics_sarif;
use serde::Serialize;
use sorark_ir::{Diagnostic, RuleDescriptor, Severity};
use sorark_wasm::WasmInspectionReport;
use text::{render_diagnostics_text, render_rules_text};

/// Supported output formats for `sorark` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable Rust compiler-style terminal output.
    Text,
    /// Schema-versioned JSON report.
    Json,
    /// OASIS SARIF v2.1.0 JSON document for GitHub Code Scanning.
    Sarif,
    /// GitHub-Flavored Markdown table for PR comments and CI job summaries.
    Markdown,
}

/// Aggregate count of findings grouped by [`Severity`].
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DiagnosticCounts {
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub total: usize,
}

impl DiagnosticCounts {
    /// Computes aggregate counts across a slice of [`Diagnostic`]s.
    #[must_use]
    pub fn from_slice(diagnostics: &[Diagnostic]) -> Self {
        let mut errors = 0;
        let mut warnings = 0;
        let mut infos = 0;
        for d in diagnostics {
            match d.severity {
                Severity::Error => errors += 1,
                Severity::Warning => warnings += 1,
                Severity::Info => infos += 1,
            }
        }
        Self {
            errors,
            warnings,
            infos,
            total: diagnostics.len(),
        }
    }
}

/// Renders a slice of [`Diagnostic`] items in the requested [`OutputFormat`].
pub fn render_diagnostics(
    diagnostics: &[Diagnostic],
    format: OutputFormat,
) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Text => Ok(render_diagnostics_text(diagnostics)),
        OutputFormat::Json => render_diagnostics_json(diagnostics),
        OutputFormat::Sarif => render_diagnostics_sarif(diagnostics),
        OutputFormat::Markdown => Ok(render_diagnostics_markdown(diagnostics)),
    }
}

/// Renders a [`WasmInspectionReport`] in Text, JSON, or Markdown format.
pub fn render_wasm_inspection(
    report: &WasmInspectionReport,
    format: OutputFormat,
) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif => serde_json::to_string_pretty(report),
        OutputFormat::Markdown | OutputFormat::Text => Ok(render_wasm_inspection_text(report)),
    }
}

/// Renders the built-in [`RuleDescriptor`] catalog in the requested [`OutputFormat`].
pub fn render_rule_catalog(
    catalog: &[RuleDescriptor],
    format: OutputFormat,
) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif => serde_json::to_string_pretty(catalog),
        OutputFormat::Markdown => Ok(render_rules_markdown(catalog)),
        OutputFormat::Text => Ok(render_rules_text(catalog)),
    }
}
