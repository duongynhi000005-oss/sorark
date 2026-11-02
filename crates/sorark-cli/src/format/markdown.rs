//! GitHub-Flavored Markdown table formatter for PR comments and CI job summaries.

use super::DiagnosticCounts;
use sorark_ir::{Diagnostic, RuleDescriptor};
use std::fmt::Write as _;

/// Renders `diagnostics` as a Markdown summary table suitable for GitHub PR comments.
#[must_use]
pub(super) fn render_diagnostics_markdown(diagnostics: &[Diagnostic]) -> String {
    let counts = DiagnosticCounts::from_slice(diagnostics);
    let mut out = String::new();
    out.push_str("## SORARK Soroban Safety & Compatibility Report\n\n");
    let _ = writeln!(
        out,
        "**Summary:** `{}` error(s), `{}` warning(s), `{}` info(s)\n",
        counts.errors, counts.warnings, counts.infos
    );

    if diagnostics.is_empty() {
        out.push_str(
            "✅ **No Soroban storage, TTL archival, or upgrade compatibility issues detected.**\n",
        );
        return out;
    }

    out.push_str("| Severity | Rule | Location | Finding | Remediation |\n");
    out.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
    for d in diagnostics {
        let loc = d
            .span
            .as_ref()
            .map_or_else(|| "`-`".to_string(), |s| format!("`{}:{}`", s.file, s.line));
        let msg = d.message.replace('|', "\\|");
        let help = d.help.replace('|', "\\|");
        let _ = writeln!(
            out,
            "| **{}** | `{}` | {} | {} | {} |",
            d.severity.as_str().to_uppercase(),
            d.rule_id,
            loc,
            msg,
            help
        );
    }
    out
}

/// Renders the built-in [`RuleDescriptor`] catalog as a Markdown table.
#[must_use]
pub(super) fn render_rules_markdown(catalog: &[RuleDescriptor]) -> String {
    let mut out = String::new();
    out.push_str("| Rule ID | Category | Default Severity | Title | Description |\n");
    out.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
    for r in catalog {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | **{}** | {} | {} |",
            r.id, r.category, r.default_severity, r.title, r.description
        );
    }
    out
}
