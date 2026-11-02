//! OASIS SARIF v2.1.0 report formatter for GitHub Code Scanning integration.

use sorark_ir::{Diagnostic, SourceSpan, builtin_rule_catalog};

/// Renders `diagnostics` as a valid SARIF v2.1.0 JSON document.
pub(super) fn render_diagnostics_sarif(
    diagnostics: &[Diagnostic],
) -> Result<String, serde_json::Error> {
    let rules_json = build_sarif_rules();
    let results_json = build_sarif_results(diagnostics);

    let sarif_doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sorark",
                    "informationUri": "https://github.com/sorark-labs/sorark",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules_json
                }
            },
            "results": results_json
        }]
    });

    serde_json::to_string_pretty(&sarif_doc)
}

/// Converts the built-in SORARK rule catalog into SARIF `reportingDescriptor` objects.
fn build_sarif_rules() -> Vec<serde_json::Value> {
    builtin_rule_catalog()
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.title,
                "shortDescription": { "text": r.title },
                "fullDescription": { "text": r.description },
                "help": { "text": r.remediation },
                "defaultConfiguration": {
                    "level": r.default_severity.sarif_level()
                },
                "properties": {
                    "category": r.category.to_string()
                }
            })
        })
        .collect()
}

/// Converts each [`Diagnostic`] into a SARIF `result` object.
fn build_sarif_results(diagnostics: &[Diagnostic]) -> Vec<serde_json::Value> {
    diagnostics
        .iter()
        .map(|d| {
            serde_json::json!({
                "ruleId": d.rule_id,
                "level": d.severity.sarif_level(),
                "message": {
                    "text": format!("{} Remediation: {}", d.message, d.help)
                },
                "locations": build_sarif_locations(d.span.as_ref())
            })
        })
        .collect()
}

/// Builds the SARIF `locations` array from an optional [`SourceSpan`].
fn build_sarif_locations(span: Option<&SourceSpan>) -> Vec<serde_json::Value> {
    let Some(span) = span else {
        return Vec::new();
    };

    vec![serde_json::json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": span.file
            },
            "region": {
                "startLine": span.line.max(1),
                "startColumn": span.column.max(1)
            }
        }
    })]
}
