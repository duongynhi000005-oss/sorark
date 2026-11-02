//! Soroban WebAssembly SEP-0048 custom section XDR decoder and ledger size analyzer (`sorark-wasm`).
//!
//! Parses compiled Soroban `.wasm` binaries using `wasmparser` and decodes the embedded
//! `contractspecv0` (`ScSpecEntry`), `contractenvmetav0` (`ScEnvMetaEntry`), and
//! `contractmetav0` (`ScMetaEntry`) streams using official `stellar-xdr`.

pub mod budget;
pub mod convert;
pub mod error;
pub mod fixture;
pub mod metrics;
pub mod sections;

pub use convert::xdr_typedef_to_typeref;
pub use error::WasmEngineError;
pub use fixture::encode_soroban_wasm_with_specs;
pub use metrics::{WasmInspectionReport, WasmMetrics};

use budget::evaluate_wasm_diagnostics;
use convert::populate_module_from_spec_entry;
use sections::parse_wasm_sections;
use sorark_ir::{ContractModule, SorarkConfig, SourceOrigin};
use std::path::Path;

/// Reads and inspects a compiled Soroban `.wasm` file from disk.
///
/// # Errors
///
/// Returns [`WasmEngineError`] if the file cannot be read, is not valid WebAssembly,
/// or contains malformed SEP-0048 XDR custom sections.
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
///
/// # Errors
///
/// Returns [`WasmEngineError`] if `bytes` is not valid WebAssembly or contains malformed
/// SEP-0048 XDR entries.
pub fn inspect_wasm_bytes(
    module_name: &str,
    path_label: &str,
    bytes: &[u8],
    config: &SorarkConfig,
) -> Result<WasmInspectionReport, WasmEngineError> {
    let mut metrics = WasmMetrics::with_byte_size(bytes.len());
    let spec_entries = parse_wasm_sections(path_label, bytes, &mut metrics)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{
        ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef,
        ScSpecUdtStructFieldV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0,
        ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0, ScSymbol, StringM, VecM,
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
