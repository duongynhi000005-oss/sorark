use clap::ValueEnum;
use serde::Serialize;
use sorark_ir::{Diagnostic, Severity, builtin_rule_catalog};
use sorark_wasm::WasmInspectionReport;

/// Supported output formats for `sorark` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Markdown,
}

#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub schema_version: &'static str,
    pub tool: &'static str,
    pub version: &'static str,
    pub summary: DiagnosticCounts,
    pub diagnostics: &'a [Diagnostic],
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DiagnosticCounts {
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub total: usize,
}

impl DiagnosticCounts {
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
        OutputFormat::Json => {
            let report = JsonReport {
                schema_version: "1.0.0",
                tool: "sorark",
                version: env!("CARGO_PKG_VERSION"),
                summary: DiagnosticCounts::from_slice(diagnostics),
                diagnostics,
            };
            serde_json::to_string_pretty(&report)
        }
        OutputFormat::Sarif => render_diagnostics_sarif(diagnostics),
        OutputFormat::Markdown => Ok(render_diagnostics_markdown(diagnostics)),
    }
}

fn render_diagnostics_text(diagnostics: &[Diagnostic]) -> String {
    let mut out = String::new();
    for d in diagnostics {
        out.push_str(&format!(
            "{}[{}]: {}\n",
            d.severity.as_str(),
            d.rule_id,
            d.title
        ));
        if let Some(span) = &d.span {
            out.push_str(&format!(
                "  --> {}:{}:{}\n",
                span.file, span.line, span.column
            ));
            if let Some(snippet) = &span.snippet
                && !snippet.is_empty()
            {
                out.push_str("   |\n");
                out.push_str(&format!("{:>3} | {}\n", span.line, snippet));
                out.push_str("   |\n");
            }
        }
        out.push_str(&format!("   = note: {}\n", d.message));
        out.push_str(&format!("   = help: {}\n\n", d.help));
    }

    let counts = DiagnosticCounts::from_slice(diagnostics);
    out.push_str(&format!(
        "sorark summary: {} error(s), {} warning(s), {} info(s)\n",
        counts.errors, counts.warnings, counts.infos
    ));
    out
}

fn render_diagnostics_markdown(diagnostics: &[Diagnostic]) -> String {
    let counts = DiagnosticCounts::from_slice(diagnostics);
    let mut out = String::new();
    out.push_str("## SORARK Soroban Safety & Compatibility Report\n\n");
    out.push_str(&format!(
        "**Summary:** `{}` error(s), `{}` warning(s), `{}` info(s)\n\n",
        counts.errors, counts.warnings, counts.infos
    ));

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
        out.push_str(&format!(
            "| **{}** | `{}` | {} | {} | {} |\n",
            d.severity.as_str().to_uppercase(),
            d.rule_id,
            loc,
            msg,
            help
        ));
    }
    out
}

fn render_diagnostics_sarif(diagnostics: &[Diagnostic]) -> Result<String, serde_json::Error> {
    let catalog = builtin_rule_catalog();
    let rules_json: Vec<serde_json::Value> = catalog
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
        .collect();

    let results_json: Vec<serde_json::Value> = diagnostics
        .iter()
        .map(|d| {
            let locations = if let Some(span) = &d.span {
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
            } else {
                Vec::new()
            };

            serde_json::json!({
                "ruleId": d.rule_id,
                "level": d.severity.sarif_level(),
                "message": {
                    "text": format!("{} Remediation: {}", d.message, d.help)
                },
                "locations": locations
            })
        })
        .collect();

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

/// Renders a [`WasmInspectionReport`] in Text, JSON, or Markdown format.
pub fn render_wasm_inspection(
    report: &WasmInspectionReport,
    format: OutputFormat,
) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif => serde_json::to_string_pretty(report),
        OutputFormat::Markdown | OutputFormat::Text => {
            let mut out = String::new();
            out.push_str(&format!(
                "=== SORARK WASM Contract Inspection: {} ===\n",
                report.module.name
            ));
            out.push_str(&format!(
                "Binary Size:          {} bytes ({:.2} KiB / 64.00 KiB limit)\n",
                report.metrics.byte_size,
                report.metrics.byte_size as f64 / 1024.0
            ));
            out.push_str(&format!(
                "Soroban Protocol:     {}\n",
                report
                    .metrics
                    .protocol_version
                    .map_or_else(|| "missing".to_string(), |p| format!("Protocol {p}"))
            ));
            out.push_str(&format!(
                "SEP-0048 Sections:    contractspecv0={}, contractenvmetav0={}, contractmetav0={}\n",
                report.metrics.has_contractspecv0,
                report.metrics.has_contractenvmetav0,
                report.metrics.has_contractmetav0
            ));

            if !report.module.structs.is_empty() {
                out.push_str("\n#[contracttype] Named Structs (ScMap):\n");
                for s in &report.module.structs {
                    let fields: Vec<String> = s
                        .fields
                        .iter()
                        .map(|f| format!("{}: {}", f.name, f.ty))
                        .collect();
                    out.push_str(&format!(
                        "  - struct {} {{ {} }}\n",
                        s.name,
                        fields.join(", ")
                    ));
                }
            }

            if !report.module.tuple_structs.is_empty() {
                out.push_str("\n#[contracttype] Tuple Structs (ScVec):\n");
                for ts in &report.module.tuple_structs {
                    let fields: Vec<String> = ts.fields.iter().map(ToString::to_string).collect();
                    out.push_str(&format!("  - struct {}({})\n", ts.name, fields.join(", ")));
                }
            }

            if !report.module.unions.is_empty() {
                out.push_str("\n#[contracttype] Unions / DataKeys (ScSpecUdtUnionV0):\n");
                for u in &report.module.unions {
                    let cases: Vec<String> = u
                        .cases
                        .iter()
                        .map(|c| {
                            if c.payload.is_empty() {
                                c.name.clone()
                            } else {
                                let p: Vec<String> =
                                    c.payload.iter().map(ToString::to_string).collect();
                                format!("{}({})", c.name, p.join(", "))
                            }
                        })
                        .collect();
                    out.push_str(&format!("  - enum {} {{ {} }}\n", u.name, cases.join(", ")));
                }
            }

            if !report.module.enums.is_empty() {
                out.push_str("\n#[contracttype] Integer Enums (ScSpecUdtEnumV0):\n");
                for e in &report.module.enums {
                    let vars: Vec<String> = e
                        .variants
                        .iter()
                        .map(|v| format!("{} = {}", v.name, v.discriminant))
                        .collect();
                    out.push_str(&format!("  - enum {} {{ {} }}\n", e.name, vars.join(", ")));
                }
            }

            if !report.module.functions.is_empty() {
                out.push_str("\nExported Contract Entrypoints (ScSpecFunctionV0):\n");
                for f in &report.module.functions {
                    let params: Vec<String> = f
                        .params
                        .iter()
                        .map(|p| format!("{}: {}", p.name, p.ty))
                        .collect();
                    out.push_str(&format!(
                        "  - fn {}({}) -> {}\n",
                        f.name,
                        params.join(", "),
                        f.return_type
                    ));
                }
            }

            if !report.diagnostics.is_empty() {
                out.push('\n');
                out.push_str(&render_diagnostics_text(&report.diagnostics));
            }
            Ok(out)
        }
    }
}
