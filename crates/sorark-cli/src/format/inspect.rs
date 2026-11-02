//! Formatter for `sorark inspect` WebAssembly SEP-0048 contract specification reports.

use super::text::render_diagnostics_text;
use sorark_ir::{EnumSpec, FunctionSpec, StructSpec, TupleStructSpec, UnionSpec};
use sorark_wasm::WasmInspectionReport;
use std::fmt::Write as _;

/// Renders a human-readable summary of a [`WasmInspectionReport`].
#[must_use]
pub(super) fn render_wasm_inspection_text(report: &WasmInspectionReport) -> String {
    let mut out = String::new();
    append_header(&mut out, report);
    append_structs(&mut out, &report.module.structs);
    append_tuple_structs(&mut out, &report.module.tuple_structs);
    append_unions(&mut out, &report.module.unions);
    append_enums(&mut out, &report.module.enums);
    append_functions(&mut out, &report.module.functions);

    if !report.diagnostics.is_empty() {
        out.push('\n');
        out.push_str(&render_diagnostics_text(&report.diagnostics));
    }
    out
}

/// Appends the WASM binary size, protocol version, and SEP-0048 custom section summary header.
fn append_header(out: &mut String, report: &WasmInspectionReport) {
    let _ = writeln!(
        out,
        "=== SORARK WASM Contract Inspection: {} ===",
        report.module.name
    );
    let _ = writeln!(
        out,
        "Binary Size:          {} bytes ({:.2} KiB / 64.00 KiB limit)",
        report.metrics.byte_size,
        report.metrics.byte_size as f64 / 1024.0
    );
    let _ = writeln!(
        out,
        "Soroban Protocol:     {}",
        report
            .metrics
            .protocol_version
            .map_or_else(|| "missing".to_string(), |p| format!("Protocol {p}"))
    );
    let _ = writeln!(
        out,
        "SEP-0048 Sections:    contractspecv0={}, contractenvmetav0={}, contractmetav0={}",
        report.metrics.has_contractspecv0,
        report.metrics.has_contractenvmetav0,
        report.metrics.has_contractmetav0
    );
}

/// Appends decoded `#[contracttype]` named structs (`ScMap`).
fn append_structs(out: &mut String, structs: &[StructSpec]) {
    if structs.is_empty() {
        return;
    }
    out.push_str("\n#[contracttype] Named Structs (ScMap):\n");
    for s in structs {
        let fields: Vec<String> = s
            .fields
            .iter()
            .map(|f| format!("{}: {}", f.name, f.ty))
            .collect();
        let _ = writeln!(out, "  - struct {} {{ {} }}", s.name, fields.join(", "));
    }
}

/// Appends decoded `#[contracttype]` positional tuple structs (`ScVec`).
fn append_tuple_structs(out: &mut String, tuple_structs: &[TupleStructSpec]) {
    if tuple_structs.is_empty() {
        return;
    }
    out.push_str("\n#[contracttype] Tuple Structs (ScVec):\n");
    for ts in tuple_structs {
        let fields: Vec<String> = ts.fields.iter().map(ToString::to_string).collect();
        let _ = writeln!(out, "  - struct {}({})", ts.name, fields.join(", "));
    }
}

/// Appends decoded `#[contracttype]` tagged unions (`ScSpecUdtUnionV0`).
fn append_unions(out: &mut String, unions: &[UnionSpec]) {
    if unions.is_empty() {
        return;
    }
    out.push_str("\n#[contracttype] Unions / DataKeys (ScSpecUdtUnionV0):\n");
    for u in unions {
        let cases: Vec<String> = u
            .cases
            .iter()
            .map(|c| {
                if c.payload.is_empty() {
                    c.name.clone()
                } else {
                    let p: Vec<String> = c.payload.iter().map(ToString::to_string).collect();
                    format!("{}({})", c.name, p.join(", "))
                }
            })
            .collect();
        let _ = writeln!(out, "  - enum {} {{ {} }}", u.name, cases.join(", "));
    }
}

/// Appends decoded `#[contracttype]` integer enums (`ScSpecUdtEnumV0`).
fn append_enums(out: &mut String, enums: &[EnumSpec]) {
    if enums.is_empty() {
        return;
    }
    out.push_str("\n#[contracttype] Integer Enums (ScSpecUdtEnumV0):\n");
    for e in enums {
        let vars: Vec<String> = e
            .variants
            .iter()
            .map(|v| format!("{} = {}", v.name, v.discriminant))
            .collect();
        let _ = writeln!(out, "  - enum {} {{ {} }}", e.name, vars.join(", "));
    }
}

/// Appends decoded exported contract entrypoints (`ScSpecFunctionV0`).
fn append_functions(out: &mut String, functions: &[FunctionSpec]) {
    if functions.is_empty() {
        return;
    }
    out.push_str("\nExported Contract Entrypoints (ScSpecFunctionV0):\n");
    for f in functions {
        let params: Vec<String> = f
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name, p.ty))
            .collect();
        let _ = writeln!(
            out,
            "  - fn {}({}) -> {}",
            f.name,
            params.join(", "),
            f.return_type
        );
    }
}
