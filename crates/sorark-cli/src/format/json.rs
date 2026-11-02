//! Schema-versioned JSON report formatter for SORARK diagnostics.

use super::DiagnosticCounts;
use serde::Serialize;
use sorark_ir::Diagnostic;

/// Top-level JSON envelope emitted by `sorark ... --format json`.
#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    /// Semantic version of the SORARK JSON report schema.
    pub schema_version: &'static str,
    /// Tool identifier (`"sorark"`).
    pub tool: &'static str,
    /// Version of the `sorark` binary that generated this report.
    pub version: &'static str,
    /// Aggregate counts by severity level.
    pub summary: DiagnosticCounts,
    /// Ordered list of findings.
    pub diagnostics: &'a [Diagnostic],
}

/// Serializes `diagnostics` into a pretty-printed [`JsonReport`].
pub(super) fn render_diagnostics_json(
    diagnostics: &[Diagnostic],
) -> Result<String, serde_json::Error> {
    let report = JsonReport {
        schema_version: "1.0.0",
        tool: "sorark",
        version: env!("CARGO_PKG_VERSION"),
        summary: DiagnosticCounts::from_slice(diagnostics),
        diagnostics,
    };
    serde_json::to_string_pretty(&report)
}
