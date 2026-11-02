//! Soroban WebAssembly SEP-0048 custom section XDR decoder and ledger size analyzer (`sorark-wasm`).
//!
//! Parses compiled Soroban `.wasm` binaries using `wasmparser` and decodes the embedded
//! `contractspecv0` (`ScSpecEntry`), `contractenvmetav0` (`ScEnvMetaEntry`), and
//! `contractmetav0` (`ScMetaEntry`) streams using official `stellar-xdr`.

use serde::{Deserialize, Serialize};
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, EnumSpec, EnumVariantSpec, ErrorEnumSpec,
    FunctionParamSpec, FunctionSpec, RuleCategory, Severity, SorarkConfig, SourceOrigin,
    SourceSpan, StructFieldSpec, StructSpec, TupleStructSpec, TypeRef, UnionCaseSpec, UnionSpec,
};
use std::io::Cursor;
use std::path::Path;
use stellar_xdr::{
    Limited, Limits, ReadXdr, ScEnvMetaEntry, ScMetaEntry, ScSpecEntry, ScSpecFunctionV0,
    ScSpecTypeDef, ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseV0,
    ScSpecUdtUnionV0, WriteXdr,
};
use thiserror::Error;
use wasmparser::{ExternalKind, Parser, Payload};

#[derive(Debug, Error)]
pub enum WasmEngineError {
    #[error("Failed to read WASM file `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Invalid WebAssembly binary in `{path}`: {message}")]
    WasmParse { path: String, message: String },
    #[error("Failed to decode Stellar XDR section `{section}` in `{path}`: {source}")]
    XdrDecode {
        path: String,
        section: &'static str,
        #[source]
        source: stellar_xdr::Error,
    },
}

/// Low-level WebAssembly & SEP-0048 metadata metrics extracted from a `.wasm` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmMetrics {
    pub byte_size: usize,
    pub export_count: usize,
    pub exported_functions: Vec<String>,
    pub import_count: usize,
    pub initial_memory_pages: Option<u64>,
    pub max_memory_pages: Option<u64>,
    pub has_contractspecv0: bool,
    pub has_contractenvmetav0: bool,
    pub has_contractmetav0: bool,
    pub protocol_version: Option<u32>,
    pub pre_release_version: Option<u32>,
    pub rs_soroban_env_version: Option<String>,
    pub rustc_version: Option<String>,
}

/// Full report returned when inspecting a compiled Soroban `.wasm` binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmInspectionReport {
    pub module: ContractModule,
    pub metrics: WasmMetrics,
    pub diagnostics: Vec<Diagnostic>,
}

/// Reads and inspects a compiled Soroban `.wasm` file from disk.
pub fn inspect_wasm_file(
    path: impl AsRef<Path>,
    config: &SorarkConfig,
) -> Result<WasmInspectionReport, WasmEngineError> {
    let path_ref = path.as_ref();
    let label = path_ref.display().to_string();
    let bytes = std::fs::read(path_ref).map_err(|source| WasmEngineError::Io {
        path: label.clone(),
        source,
    })?;
    let module_name = path_ref
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("soroban_wasm")
        .to_string();
    inspect_wasm_bytes(&module_name, &label, &bytes, config)
}

/// Parses a raw `.wasm` byte slice, extracting SEP-0048 XDR specs into a [`ContractModule`]
/// and evaluating `ARK-WASM-001` resource budget checks.
pub fn inspect_wasm_bytes(
    module_name: &str,
    path_label: &str,
    bytes: &[u8],
    config: &SorarkConfig,
) -> Result<WasmInspectionReport, WasmEngineError> {
    let mut metrics = WasmMetrics {
        byte_size: bytes.len(),
        export_count: 0,
        exported_functions: Vec::new(),
        import_count: 0,
        initial_memory_pages: None,
        max_memory_pages: None,
        has_contractspecv0: false,
        has_contractenvmetav0: false,
        has_contractmetav0: false,
        protocol_version: None,
        pre_release_version: None,
        rs_soroban_env_version: None,
        rustc_version: None,
    };

    let mut spec_entries: Vec<ScSpecEntry> = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|err| WasmEngineError::WasmParse {
            path: path_label.to_string(),
            message: err.to_string(),
        })?;

        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let _ = import.map_err(|err| WasmEngineError::WasmParse {
                        path: path_label.to_string(),
                        message: err.to_string(),
                    })?;
                    metrics.import_count += 1;
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|err| WasmEngineError::WasmParse {
                        path: path_label.to_string(),
                        message: err.to_string(),
                    })?;
                    metrics.export_count += 1;
                    if export.kind == ExternalKind::Func {
                        metrics.exported_functions.push(export.name.to_string());
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem = mem.map_err(|err| WasmEngineError::WasmParse {
                        path: path_label.to_string(),
                        message: err.to_string(),
                    })?;
                    metrics.initial_memory_pages = Some(mem.initial);
                    metrics.max_memory_pages = mem.maximum;
                }
            }
            Payload::CustomSection(section) => match section.name() {
                "contractspecv0" => {
                    metrics.has_contractspecv0 = true;
                    let mut limited = Limited::new(Cursor::new(section.data()), Limits::none());
                    for entry_res in ScSpecEntry::read_xdr_iter(&mut limited) {
                        let entry = entry_res.map_err(|source| WasmEngineError::XdrDecode {
                            path: path_label.to_string(),
                            section: "contractspecv0",
                            source,
                        })?;
                        spec_entries.push(entry);
                    }
                }
                "contractenvmetav0" => {
                    metrics.has_contractenvmetav0 = true;
                    let mut limited = Limited::new(Cursor::new(section.data()), Limits::none());
                    for entry_res in ScEnvMetaEntry::read_xdr_iter(&mut limited) {
                        let entry = entry_res.map_err(|source| WasmEngineError::XdrDecode {
                            path: path_label.to_string(),
                            section: "contractenvmetav0",
                            source,
                        })?;
                        match entry {
                            ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(iv) => {
                                metrics.protocol_version = Some(iv.protocol);
                                metrics.pre_release_version = Some(iv.pre_release);
                            }
                        }
                    }
                }
                "contractmetav0" => {
                    metrics.has_contractmetav0 = true;
                    let mut limited = Limited::new(Cursor::new(section.data()), Limits::none());
                    for entry_res in ScMetaEntry::read_xdr_iter(&mut limited) {
                        let entry = entry_res.map_err(|source| WasmEngineError::XdrDecode {
                            path: path_label.to_string(),
                            section: "contractmetav0",
                            source,
                        })?;
                        match entry {
                            ScMetaEntry::ScMetaV0(meta) => {
                                let key = meta.key.to_utf8_string_lossy();
                                let val = meta.val.to_utf8_string_lossy();
                                if key == "rsver" {
                                    metrics.rustc_version = Some(val);
                                } else if key == "rssdkver" {
                                    metrics.rs_soroban_env_version = Some(val);
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    let origin = SourceOrigin::WasmBinary {
        path: path_label.to_string(),
        byte_size: metrics.byte_size,
        protocol_version: metrics.protocol_version,
        pre_release_version: metrics.pre_release_version,
        rs_soroban_env_version: metrics.rs_soroban_env_version.clone(),
        rustc_version: metrics.rustc_version.clone(),
    };

    let mut module = ContractModule::new(module_name, origin);
    for entry in &spec_entries {
        populate_module_from_spec_entry(path_label, entry, &mut module);
    }

    let diagnostics = evaluate_wasm_diagnostics(path_label, &metrics, config);
    Ok(WasmInspectionReport {
        module,
        metrics,
        diagnostics,
    })
}

fn populate_module_from_spec_entry(
    path_label: &str,
    entry: &ScSpecEntry,
    module: &mut ContractModule,
) {
    match entry {
        ScSpecEntry::FunctionV0(f) => {
            module.functions.push(convert_spec_function(path_label, f));
        }
        ScSpecEntry::UdtStructV0(s) => {
            convert_spec_struct(path_label, s, module);
        }
        ScSpecEntry::UdtEnumV0(e) => {
            module.enums.push(convert_spec_enum(path_label, e));
        }
        ScSpecEntry::UdtUnionV0(u) => {
            module.unions.push(convert_spec_union(path_label, u));
        }
        ScSpecEntry::UdtErrorEnumV0(err) => {
            module
                .error_enums
                .push(convert_spec_error_enum(path_label, err));
        }
        ScSpecEntry::EventV0(_) => {}
    }
}

fn convert_spec_function(path_label: &str, f: &ScSpecFunctionV0) -> FunctionSpec {
    let name = f.name.to_utf8_string_lossy();
    let params = f
        .inputs
        .iter()
        .map(|inp| FunctionParamSpec {
            name: inp.name.to_utf8_string_lossy(),
            ty: xdr_typedef_to_typeref(&inp.type_),
        })
        .collect();
    let return_type = match f.outputs.as_slice() {
        [] => TypeRef::Void,
        [single] => xdr_typedef_to_typeref(single),
        many => TypeRef::Tuple(many.iter().map(xdr_typedef_to_typeref).collect()),
    };
    FunctionSpec {
        name,
        params,
        return_type,
        file: Some(path_label.to_string()),
        line: None,
    }
}

fn convert_spec_struct(path_label: &str, s: &ScSpecUdtStructV0, module: &mut ContractModule) {
    let name = s.name.to_utf8_string_lossy();
    // In Soroban XDR specs, tuple structs (`struct Pair(u64, Address)`) are encoded as
    // `ScSpecUdtStructV0` whose field names are sequential 0-indexed numbers ("0", "1", ...).
    let is_tuple_struct = !s.fields.is_empty()
        && s.fields
            .iter()
            .enumerate()
            .all(|(idx, f)| f.name.to_utf8_string_lossy() == idx.to_string());

    if is_tuple_struct {
        let fields = s
            .fields
            .iter()
            .map(|f| xdr_typedef_to_typeref(&f.type_))
            .collect();
        module.tuple_structs.push(TupleStructSpec {
            name,
            fields,
            file: Some(path_label.to_string()),
            line: None,
        });
    } else {
        let fields = s
            .fields
            .iter()
            .map(|f| StructFieldSpec {
                name: f.name.to_utf8_string_lossy(),
                ty: xdr_typedef_to_typeref(&f.type_),
                line: None,
            })
            .collect();
        module.structs.push(StructSpec {
            name,
            fields,
            file: Some(path_label.to_string()),
            line: None,
        });
    }
}

fn convert_spec_enum(path_label: &str, e: &ScSpecUdtEnumV0) -> EnumSpec {
    let name = e.name.to_utf8_string_lossy();
    let variants = e
        .cases
        .iter()
        .map(|c| EnumVariantSpec {
            name: c.name.to_utf8_string_lossy(),
            discriminant: c.value,
            line: None,
        })
        .collect();
    EnumSpec {
        name,
        variants,
        file: Some(path_label.to_string()),
        line: None,
    }
}

fn convert_spec_union(path_label: &str, u: &ScSpecUdtUnionV0) -> UnionSpec {
    let name = u.name.to_utf8_string_lossy();
    let cases = u
        .cases
        .iter()
        .map(|c| match c {
            ScSpecUdtUnionCaseV0::VoidV0(v) => UnionCaseSpec {
                name: v.name.to_utf8_string_lossy(),
                payload: Vec::new(),
                line: None,
            },
            ScSpecUdtUnionCaseV0::TupleV0(t) => UnionCaseSpec {
                name: t.name.to_utf8_string_lossy(),
                payload: t.type_.iter().map(xdr_typedef_to_typeref).collect(),
                line: None,
            },
        })
        .collect();
    UnionSpec {
        name,
        cases,
        file: Some(path_label.to_string()),
        line: None,
    }
}

fn convert_spec_error_enum(path_label: &str, e: &ScSpecUdtErrorEnumV0) -> ErrorEnumSpec {
    let name = e.name.to_utf8_string_lossy();
    let variants = e
        .cases
        .iter()
        .map(|c| EnumVariantSpec {
            name: c.name.to_utf8_string_lossy(),
            discriminant: c.value,
            line: None,
        })
        .collect();
    ErrorEnumSpec {
        name,
        variants,
        file: Some(path_label.to_string()),
        line: None,
    }
}

/// Converts a Stellar XDR [`ScSpecTypeDef`] into a normalized [`TypeRef`].
#[must_use]
pub fn xdr_typedef_to_typeref(td: &ScSpecTypeDef) -> TypeRef {
    match td {
        ScSpecTypeDef::Val => TypeRef::Val,
        ScSpecTypeDef::Bool => TypeRef::Bool,
        ScSpecTypeDef::Void => TypeRef::Void,
        ScSpecTypeDef::Error => TypeRef::Error,
        ScSpecTypeDef::U32 => TypeRef::U32,
        ScSpecTypeDef::I32 => TypeRef::I32,
        ScSpecTypeDef::U64 => TypeRef::U64,
        ScSpecTypeDef::I64 => TypeRef::I64,
        ScSpecTypeDef::Timepoint => TypeRef::Timepoint,
        ScSpecTypeDef::Duration => TypeRef::Duration,
        ScSpecTypeDef::U128 => TypeRef::U128,
        ScSpecTypeDef::I128 => TypeRef::I128,
        ScSpecTypeDef::U256 => TypeRef::U256,
        ScSpecTypeDef::I256 => TypeRef::I256,
        ScSpecTypeDef::Bytes => TypeRef::Bytes,
        ScSpecTypeDef::String => TypeRef::String,
        ScSpecTypeDef::Symbol => TypeRef::Symbol,
        ScSpecTypeDef::Address | ScSpecTypeDef::MuxedAddress => TypeRef::Address,
        ScSpecTypeDef::Option(opt) => {
            TypeRef::Option(Box::new(xdr_typedef_to_typeref(&opt.value_type)))
        }
        ScSpecTypeDef::Result(res) => TypeRef::Result {
            ok: Box::new(xdr_typedef_to_typeref(&res.ok_type)),
            err: Box::new(xdr_typedef_to_typeref(&res.error_type)),
        },
        ScSpecTypeDef::Vec(v) => TypeRef::Vec(Box::new(xdr_typedef_to_typeref(&v.element_type))),
        ScSpecTypeDef::Map(m) => TypeRef::Map {
            key: Box::new(xdr_typedef_to_typeref(&m.key_type)),
            value: Box::new(xdr_typedef_to_typeref(&m.value_type)),
        },
        ScSpecTypeDef::Tuple(t) => {
            TypeRef::Tuple(t.value_types.iter().map(xdr_typedef_to_typeref).collect())
        }
        ScSpecTypeDef::BytesN(b) => TypeRef::BytesN(b.n),
        ScSpecTypeDef::Udt(udt) => TypeRef::Custom(udt.name.to_utf8_string_lossy()),
    }
}

fn evaluate_wasm_diagnostics(
    path_label: &str,
    metrics: &WasmMetrics,
    config: &SorarkConfig,
) -> Vec<Diagnostic> {
    if !config.is_rule_enabled("ARK-WASM-001") {
        return Vec::new();
    }

    let mut out = Vec::new();

    if metrics.byte_size > config.wasm_max_bytes {
        out.push(Diagnostic {
            rule_id: "ARK-WASM-001".to_string(),
            title: "WASM Binary Exceeds Stellar Ledger Entry Size Limit".to_string(),
            severity: Severity::Error,
            confidence: Confidence::High,
            category: RuleCategory::ResourceBudget,
            message: format!(
                "Compiled contract `{path_label}` is {} bytes ({:.1} KiB), exceeding the Stellar Mainnet ledger entry maximum of {} bytes (64.0 KiB).",
                metrics.byte_size,
                metrics.byte_size as f64 / 1024.0,
                config.wasm_max_bytes
            ),
            help: "Configure `[profile.release]` with `opt-level = \"z\"`, `lto = true`, `codegen-units = 1`, `strip = \"symbols\"` and build via `stellar contract build`.".to_string(),
            span: Some(SourceSpan {
                file: path_label.to_string(),
                line: 1,
                column: 1,
                end_line: None,
                snippet: None,
            }),
            contract_item: None,
        });
    } else if metrics.byte_size > config.wasm_warn_bytes {
        out.push(Diagnostic {
            rule_id: "ARK-WASM-001".to_string(),
            title: "WASM Binary Approaching Stellar Ledger Size Limit".to_string(),
            severity: Severity::Warning,
            confidence: Confidence::High,
            category: RuleCategory::ResourceBudget,
            message: format!(
                "Compiled contract `{path_label}` is {} bytes ({:.1} KiB), exceeding the warning threshold of {} bytes ({:.1} KiB).",
                metrics.byte_size,
                metrics.byte_size as f64 / 1024.0,
                config.wasm_warn_bytes,
                config.wasm_warn_bytes as f64 / 1024.0
            ),
            help: "Reduce WASM binary size to minimize Soroban contract code rent and invocation instruction overhead.".to_string(),
            span: Some(SourceSpan {
                file: path_label.to_string(),
                line: 1,
                column: 1,
                end_line: None,
                snippet: None,
            }),
            contract_item: None,
        });
    }

    if !metrics.has_contractspecv0 {
        out.push(Diagnostic {
            rule_id: "ARK-WASM-001".to_string(),
            title: "Missing SEP-0048 `contractspecv0` Custom Section".to_string(),
            severity: Severity::Warning,
            confidence: Confidence::High,
            category: RuleCategory::ResourceBudget,
            message: format!(
                "WASM binary `{path_label}` does not contain a `contractspecv0` section. Stellar SDKs, explorers, and upgrade compatibility checkers cannot inspect its interface."
            ),
            help: "Ensure the contract uses `#[contract]` and `#[contractimpl]` from `soroban-sdk` and is compiled without stripping custom sections.".to_string(),
            span: Some(SourceSpan {
                file: path_label.to_string(),
                line: 1,
                column: 1,
                end_line: None,
                snippet: None,
            }),
            contract_item: None,
        });
    }

    if !metrics.has_contractenvmetav0 {
        out.push(Diagnostic {
            rule_id: "ARK-WASM-001".to_string(),
            title: "Missing SEP-0048 `contractenvmetav0` Custom Section".to_string(),
            severity: Severity::Warning,
            confidence: Confidence::High,
            category: RuleCategory::ResourceBudget,
            message: format!(
                "WASM binary `{path_label}` does not contain a `contractenvmetav0` section declaring its target Soroban host protocol version."
            ),
            help: "Compile the contract using `soroban-sdk` on target `wasm32-unknown-unknown` or `wasm32v1-none`.".to_string(),
            span: Some(SourceSpan {
                file: path_label.to_string(),
                line: 1,
                column: 1,
                end_line: None,
                snippet: None,
            }),
            contract_item: None,
        });
    }

    out
}

/// Builds a valid WebAssembly binary containing encoded `contractenvmetav0` and `contractspecv0`
/// custom sections from `ScSpecEntry` items. Useful for testing and synthetic fixtures.
pub fn encode_soroban_wasm_with_specs(
    protocol_version: u32,
    entries: &[ScSpecEntry],
) -> Result<Vec<u8>, stellar_xdr::Error> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    let env_entry = ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(
        stellar_xdr::ScEnvMetaEntryInterfaceVersion {
            protocol: protocol_version,
            pre_release: 0,
        },
    );
    let env_xdr = env_entry.to_xdr(Limits::none())?;
    append_wasm_custom_section(&mut wasm, "contractenvmetav0", &env_xdr);

    let mut spec_xdr = Vec::new();
    for entry in entries {
        spec_xdr.extend_from_slice(&entry.to_xdr(Limits::none())?);
    }
    append_wasm_custom_section(&mut wasm, "contractspecv0", &spec_xdr);

    Ok(wasm)
}

fn append_wasm_custom_section(wasm: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let name_bytes = name.as_bytes();
    let mut section_body = Vec::new();
    write_leb128_u32(&mut section_body, name_bytes.len() as u32);
    section_body.extend_from_slice(name_bytes);
    section_body.extend_from_slice(payload);

    wasm.push(0x00); // Custom section ID = 0
    write_leb128_u32(wasm, section_body.len() as u32);
    wasm.extend_from_slice(&section_body);
}

fn write_leb128_u32(out: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{
        ScSpecFunctionInputV0, ScSpecUdtStructFieldV0, ScSpecUdtUnionCaseTupleV0,
        ScSpecUdtUnionCaseVoidV0, ScSymbol, StringM, VecM,
    };

    #[test]
    fn decodes_xdr_contractspecv0_and_contractenvmetav0_from_wasm() {
        let struct_entry = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: StringM::try_from("VaultConfig").unwrap(),
            fields: VecM::try_from(vec![
                ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: StringM::try_from("admin").unwrap(),
                    type_: ScSpecTypeDef::Address,
                },
                ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: StringM::try_from("fee_bps").unwrap(),
                    type_: ScSpecTypeDef::U32,
                },
            ])
            .unwrap(),
        });

        let union_entry = ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: StringM::try_from("DataKey").unwrap(),
            cases: VecM::try_from(vec![
                ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                    doc: StringM::default(),
                    name: StringM::try_from("Admin").unwrap(),
                }),
                ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                    doc: StringM::default(),
                    name: StringM::try_from("Balance").unwrap(),
                    type_: VecM::try_from(vec![ScSpecTypeDef::Address]).unwrap(),
                }),
            ])
            .unwrap(),
        });

        let fn_entry = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: StringM::default(),
            name: ScSymbol::try_from("deposit").unwrap(),
            inputs: VecM::try_from(vec![
                ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: StringM::try_from("user").unwrap(),
                    type_: ScSpecTypeDef::Address,
                },
                ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: StringM::try_from("amount").unwrap(),
                    type_: ScSpecTypeDef::I128,
                },
            ])
            .unwrap(),
            outputs: VecM::try_from(vec![ScSpecTypeDef::I128]).unwrap(),
        });

        let wasm_bytes =
            encode_soroban_wasm_with_specs(22, &[struct_entry, union_entry, fn_entry]).unwrap();
        let report =
            inspect_wasm_bytes("vault", "vault.wasm", &wasm_bytes, &SorarkConfig::default())
                .unwrap();

        assert_eq!(report.metrics.protocol_version, Some(22));
        assert!(report.metrics.has_contractspecv0);
        assert!(report.metrics.has_contractenvmetav0);
        assert_eq!(report.module.structs.len(), 1);
        assert_eq!(report.module.structs[0].name, "VaultConfig");
        assert_eq!(report.module.unions.len(), 1);
        assert_eq!(report.module.unions[0].name, "DataKey");
        assert_eq!(report.module.functions.len(), 1);
        assert_eq!(report.module.functions[0].name, "deposit");
        assert!(report.diagnostics.is_empty());
    }
}
