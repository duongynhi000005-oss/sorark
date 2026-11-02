//! Compiler-style plain-text terminal formatter for SORARK diagnostics and rule catalog.

use super::DiagnosticCounts;
use sorark_ir::{Diagnostic, RuleDescriptor, SourceSpan};
use std::fmt::Write as _;

/// Renders a slice of [`Diagnostic`]s in Rust compiler-style terminal text format.
#[must_use]
pub(super) fn render_diagnostics_text(diagnostics: &[Diagnostic]) -> String {
    let mut out = String::new();

    for d in diagnostics {
        let _ = writeln!(out, "{}[{}]: {}", d.severity.as_str(), d.rule_id, d.title);
        if let Some(span) = &d.span {
            append_diagnostic_span(&mut out, span);
        }
        let _ = writeln!(out, "   = note: {}", d.message);
        let _ = writeln!(out, "   = help: {}\n", d.help);
    }

    let counts = DiagnosticCounts::from_slice(diagnostics);
    let _ = writeln!(
        out,
        "sorark summary: {} error(s), {} warning(s), {} info(s)",
        counts.errors, counts.warnings, counts.infos
    );
    out
}

/// Appends the `--> file:line:col` location header and optional code snippet block.
fn append_diagnostic_span(out: &mut String, span: &SourceSpan) {
    let _ = writeln!(out, "  --> {}:{}:{}", span.file, span.line, span.column);
    if let Some(snippet) = &span.snippet
        && !snippet.is_empty()
    {
        out.push_str("   |\n");
        let _ = writeln!(out, "{:>3} | {snippet}", span.line);
        out.push_str("   |\n");
    }
}

/// Renders the built-in [`RuleDescriptor`] catalog in human-readable terminal text format.
#[must_use]
pub(super) fn render_rules_text(catalog: &[RuleDescriptor]) -> String {
    let mut out = String::new();
    for r in catalog {
        let _ = writeln!(
            out,
            "{:<14} [{:<8}] ({})\n  {}\n  Remediation: {}\n",
            r.id, r.default_severity, r.category, r.title, r.remediation
        );
    }
    out
}
