//! Soroban contract storage-layout (`ScVal`/`ScMap`/`ScVec`) and ABI upgrade compatibility
//! diff engine (`sorark-diff`).
//!
//! Compares two normalized [`ContractModule`] snapshots (`v1` vs `v2`, whether parsed from
//! Rust source or decoded from `.wasm` `contractspecv0` sections) to detect state-corrupting
//! storage mutations and breaking interface changes prior to calling `update_current_contract_wasm`.

use serde::{Deserialize, Serialize};
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, RuleCategory, Severity, SorarkConfig, SourceOrigin,
    SourceSpan,
};

/// Extensible trait for comparing two [`ContractModule`] versions (`old` vs `new`).
pub trait DiffRule: Send + Sync {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn category(&self) -> RuleCategory;
    fn default_severity(&self) -> Severity;
    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        config: &SorarkConfig,
    ) -> Vec<Diagnostic>;
}

/// Returns the default suite of Soroban upgrade compatibility rules.
#[must_use]
pub fn default_diff_rules() -> Vec<Box<dyn DiffRule>> {
    vec![
        Box::new(StructLayoutDiffRule),
        Box::new(EnumAndUnionLayoutDiffRule),
        Box::new(FunctionAbiDiffRule),
        Box::new(ErrorEnumDiffRule),
        Box::new(ProtocolVersionDiffRule),
    ]
}

/// Summary report comparing an `old` (`v1`) and `new` (`v2`) contract module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub old_name: String,
    pub new_name: String,
    pub is_upgrade_safe: bool,
    pub diagnostics: Vec<Diagnostic>,
}

/// Compares `old` and `new` [`ContractModule`] specifications using all enabled [`DiffRule`]s.
#[must_use]
pub fn compare_contract_modules(
    old: &ContractModule,
    new: &ContractModule,
    config: &SorarkConfig,
) -> DiffReport {
    let rules = default_diff_rules();
    let mut diagnostics = Vec::new();
    for rule in &rules {
        if config.is_rule_enabled(rule.id()) {
            diagnostics.extend(rule.check_diff(old, new, config));
        }
    }
    let is_upgrade_safe = !diagnostics.iter().any(|d| {
        d.severity == Severity::Error
            || (config.fail_on_warnings && d.severity == Severity::Warning)
    });

    DiffReport {
        old_name: old.name.clone(),
        new_name: new.name.clone(),
        is_upgrade_safe,
        diagnostics,
    }
}

/// `ARK-DIFF-001`: Incompatible `#[contracttype]` struct (`ScMap`) or tuple struct (`ScVec`) layout mutation.
pub struct StructLayoutDiffRule;

impl DiffRule for StructLayoutDiffRule {
    fn id(&self) -> &'static str {
        "ARK-DIFF-001"
    }

    fn title(&self) -> &'static str {
        "Incompatible #[contracttype] Struct Storage Layout Mutation"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::StorageCompatibility
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        _config: &SorarkConfig,
    ) -> Vec<Diagnostic> {
        let mut out = Vec::new();

        // 1. Named structs (serialized on-chain as ScMap keyed by ScSymbol(field_name))
        for old_s in &old.structs {
            let Some(new_s) = new.structs.iter().find(|s| s.name == old_s.name) else {
                // Check if it was converted into a tuple struct!
                if let Some(new_ts) = new.tuple_structs.iter().find(|t| t.name == old_s.name) {
                    out.push(Diagnostic {
                        rule_id: self.id().to_string(),
                        title: self.title().to_string(),
                        severity: Severity::Error,
                        confidence: Confidence::High,
                        category: self.category(),
                        message: format!(
                            "#[contracttype] struct `{}` changed representation from named struct (`ScMap`) in v1 to tuple struct (`ScVec`) in v2. Existing on-chain ledger entries will trap on deserialization.",
                            old_s.name
                        ),
                        help: "Keep the struct as a named-field struct or create a new versioned type (e.g. `StateV2`).".to_string(),
                        span: span_from_opt(&new_ts.file, new_ts.line),
                        contract_item: Some(old_s.name.clone()),
                    });
                }
                continue;
            };

            for old_field in &old_s.fields {
                match new_s.fields.iter().find(|f| f.name == old_field.name) {
                    None => {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Error,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Field `{}.{}` (type `{}`) was removed or renamed in v2. Because Soroban serializes named `#[contracttype]` structs as `ScMap` keyed by `ScSymbol(\"{}\")`, reading or migrating historical entries without this key breaks storage compatibility.",
                                old_s.name, old_field.name, old_field.ty, old_field.name
                            ),
                            help: format!(
                                "Retain field `{}.{}: {}` or introduce a versioned struct (`{}V2`) and migrate state explicitly.",
                                old_s.name, old_field.name, old_field.ty, old_s.name
                            ),
                            span: span_from_opt(&new_s.file, new_s.line),
                            contract_item: Some(format!("{}.{}", old_s.name, old_field.name)),
                        });
                    }
                    Some(new_field) if new_field.ty != old_field.ty => {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Error,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Field `{}.{}` changed type from `{}` in v1 to `{}` in v2. Deserializing existing `ScMap` ledger entries will trap due to `ScVal` type mismatch.",
                                old_s.name, old_field.name, old_field.ty, new_field.ty
                            ),
                            help: format!(
                                "Restore `{}.{}` to `{}` or migrate storage entries via a versioned `DataKey`.",
                                old_s.name, old_field.name, old_field.ty
                            ),
                            span: span_from_opt(&new_s.file, new_field.line.or(new_s.line)),
                            contract_item: Some(format!("{}.{}", old_s.name, old_field.name)),
                        });
                    }
                    Some(_) => {}
                }
            }

            // Check newly added fields on existing struct
            for new_field in &new_s.fields {
                if !old_s.fields.iter().any(|f| f.name == new_field.name) {
                    out.push(Diagnostic {
                        rule_id: self.id().to_string(),
                        title: self.title().to_string(),
                        severity: Severity::Error,
                        confidence: Confidence::High,
                        category: self.category(),
                        message: format!(
                            "Struct `{}` added new field `{}` (`{}`) in v2. Historical on-chain `ScMap` entries persisted by v1 do not contain key `ScSymbol(\"{}\")` and will fail deserialization unless migrated.",
                            new_s.name, new_field.name, new_field.ty, new_field.name
                        ),
                        help: format!(
                            "Wrap state in a versioned `DataKey` variant (e.g. `StateV2({}V2)`) and migrate v1 entries cleanly.",
                            new_s.name
                        ),
                        span: span_from_opt(&new_s.file, new_field.line.or(new_s.line)),
                        contract_item: Some(format!("{}.{}", new_s.name, new_field.name)),
                    });
                }
            }
        }

        // 2. Positional tuple structs (serialized on-chain as ScVec)
        for old_ts in &old.tuple_structs {
            let Some(new_ts) = new.tuple_structs.iter().find(|t| t.name == old_ts.name) else {
                continue;
            };

            if old_ts.fields.len() != new_ts.fields.len() {
                out.push(Diagnostic {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    severity: Severity::Error,
                    confidence: Confidence::High,
                    category: self.category(),
                    message: format!(
                        "Tuple struct `{}` changed element count from {} in v1 to {} in v2 (`ScVec` length mismatch).",
                        old_ts.name,
                        old_ts.fields.len(),
                        new_ts.fields.len()
                    ),
                    help: "Keep positional tuple struct arity identical across upgrades.".to_string(),
                    span: span_from_opt(&new_ts.file, new_ts.line),
                    contract_item: Some(old_ts.name.clone()),
                });
            } else {
                for (idx, (old_ty, new_ty)) in
                    old_ts.fields.iter().zip(new_ts.fields.iter()).enumerate()
                {
                    if old_ty != new_ty {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Error,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Tuple struct `{}` element `.{idx}` changed type from `{old_ty}` in v1 to `{new_ty}` in v2.",
                                old_ts.name
                            ),
                            help: "Preserve positional element types in tuple structs stored on-chain.".to_string(),
                            span: span_from_opt(&new_ts.file, new_ts.line),
                            contract_item: Some(format!("{}.{idx}", old_ts.name)),
                        });
                    }
                }
            }
        }

        out
    }
}

/// `ARK-DIFF-002`: Incompatible `#[contracttype]` enum (`ScSpecUdtEnumV0`) or tagged union (`ScSpecUdtUnionV0`) mutation.
pub struct EnumAndUnionLayoutDiffRule;

impl DiffRule for EnumAndUnionLayoutDiffRule {
    fn id(&self) -> &'static str {
        "ARK-DIFF-002"
    }

    fn title(&self) -> &'static str {
        "Incompatible #[contracttype] Enum or Tagged Union Mutation"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::StorageCompatibility
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        _config: &SorarkConfig,
    ) -> Vec<Diagnostic> {
        let mut out = Vec::new();

        // 1. Unit integer enums (ScSpecUdtEnumV0 -> ScVal::U32)
        for old_e in &old.enums {
            let Some(new_e) = new.enums.iter().find(|e| e.name == old_e.name) else {
                continue;
            };
            for old_v in &old_e.variants {
                match new_e.variants.iter().find(|v| v.name == old_v.name) {
                    None => {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Error,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Enum variant `{}::{}` (discriminant `{}`) was removed in v2. Historical ledger entries storing `{}` will trap.",
                                old_e.name, old_v.name, old_v.discriminant, old_v.discriminant
                            ),
                            help: "Never remove or rename existing enum variants; deprecate them in place.".to_string(),
                            span: span_from_opt(&new_e.file, new_e.line),
                            contract_item: Some(format!("{}::{}", old_e.name, old_v.name)),
                        });
                    }
                    Some(new_v) if new_v.discriminant != old_v.discriminant => {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Error,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Enum variant `{}::{}` changed integer discriminant from `{}` in v1 to `{}` in v2, silently corrupting persisted enum state.",
                                old_e.name, old_v.name, old_v.discriminant, new_v.discriminant
                            ),
                            help: "Append new variants only at the end of the enum and pin explicit integer discriminants.".to_string(),
                            span: span_from_opt(&new_e.file, new_v.line.or(new_e.line)),
                            contract_item: Some(format!("{}::{}", old_e.name, old_v.name)),
                        });
                    }
                    Some(_) => {}
                }
            }
        }

        // 2. Tagged Unions / DataKey Enums (ScSpecUdtUnionV0 -> ScVec([ScSymbol(tag), ...payload]))
        for old_u in &old.unions {
            let Some(new_u) = new.unions.iter().find(|u| u.name == old_u.name) else {
                continue;
            };
            for old_c in &old_u.cases {
                match new_u.cases.iter().find(|c| c.name == old_c.name) {
                    None => {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Error,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Union/DataKey variant `{}::{}` was removed or renamed in v2. Any ledger entry keyed or stored under `ScSymbol(\"{}\")` becomes permanently orphaned or unreadable.",
                                old_u.name, old_c.name, old_c.name
                            ),
                            help: format!(
                                "Keep `{}::{}` intact in v2; append new storage key variants without removing historical ones.",
                                old_u.name, old_c.name
                            ),
                            span: span_from_opt(&new_u.file, new_u.line),
                            contract_item: Some(format!("{}::{}", old_u.name, old_c.name)),
                        });
                    }
                    Some(new_c) if new_c.payload != old_c.payload => {
                        let old_sig: Vec<String> =
                            old_c.payload.iter().map(ToString::to_string).collect();
                        let new_sig: Vec<String> =
                            new_c.payload.iter().map(ToString::to_string).collect();
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Error,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Union/DataKey variant `{}::{}` changed payload layout from `({})` in v1 to `({})` in v2, breaking ledger key lookup and deserialization.",
                                old_u.name,
                                old_c.name,
                                old_sig.join(", "),
                                new_sig.join(", ")
                            ),
                            help: format!(
                                "Create a new variant (e.g. `{}::{}V2(...)`) rather than mutating `{}::{}` in place.",
                                old_u.name, old_c.name, old_u.name, old_c.name
                            ),
                            span: span_from_opt(&new_u.file, new_c.line.or(new_u.line)),
                            contract_item: Some(format!("{}::{}", old_u.name, old_c.name)),
                        });
                    }
                    Some(_) => {}
                }
            }
        }

        out
    }
}

/// `ARK-DIFF-003`: Breaking public contract entrypoint signature change (`ScSpecFunctionV0`).
pub struct FunctionAbiDiffRule;

impl DiffRule for FunctionAbiDiffRule {
    fn id(&self) -> &'static str {
        "ARK-DIFF-003"
    }

    fn title(&self) -> &'static str {
        "Breaking Public Contract Entrypoint Signature Change"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::AbiCompatibility
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        _config: &SorarkConfig,
    ) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        let new_file = match &new.origin {
            SourceOrigin::RustSource { path } | SourceOrigin::WasmBinary { path, .. } => {
                Some(path.clone())
            }
        };

        for old_fn in &old.functions {
            let Some(new_fn) = new.functions.iter().find(|f| f.name == old_fn.name) else {
                out.push(Diagnostic {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    severity: Severity::Warning,
                    confidence: Confidence::High,
                    category: self.category(),
                    message: format!(
                        "Public contract entrypoint `{}` was removed in v2, breaking downstream cross-contract callers and client SDKs.",
                        old_fn.name
                    ),
                    help: format!(
                        "Keep `{}` as a deprecated wrapper or coordinate a major version upgrade with integrators.",
                        old_fn.name
                    ),
                    span: span_from_opt(&new_file, None),
                    contract_item: Some(old_fn.name.clone()),
                });
                continue;
            };

            let old_params: Vec<String> = old_fn
                .params
                .iter()
                .map(|p| format!("{}: {}", p.name, p.ty))
                .collect();
            let new_params: Vec<String> = new_fn
                .params
                .iter()
                .map(|p| format!("{}: {}", p.name, p.ty))
                .collect();

            let old_param_types: Vec<_> = old_fn.params.iter().map(|p| &p.ty).collect();
            let new_param_types: Vec<_> = new_fn.params.iter().map(|p| &p.ty).collect();

            if old_param_types != new_param_types {
                out.push(Diagnostic {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    severity: Severity::Warning,
                    confidence: Confidence::High,
                    category: self.category(),
                    message: format!(
                        "Entrypoint `{}` changed parameters from `({})` in v1 to `({})` in v2.",
                        old_fn.name,
                        old_params.join(", "),
                        new_params.join(", ")
                    ),
                    help: format!(
                        "Add a new versioned entrypoint (e.g. `{}_v2`) if callers still depend on `{}`.",
                        old_fn.name, old_fn.name
                    ),
                    span: span_from_opt(&new_fn.file, new_fn.line),
                    contract_item: Some(old_fn.name.clone()),
                });
            }

            if old_fn.return_type != new_fn.return_type {
                out.push(Diagnostic {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    severity: Severity::Warning,
                    confidence: Confidence::High,
                    category: self.category(),
                    message: format!(
                        "Entrypoint `{}` changed return type from `{}` in v1 to `{}` in v2.",
                        old_fn.name, old_fn.return_type, new_fn.return_type
                    ),
                    help: "Preserve the return type of existing public entrypoints to avoid breaking cross-contract invocations.".to_string(),
                    span: span_from_opt(&new_fn.file, new_fn.line),
                    contract_item: Some(old_fn.name.clone()),
                });
            }
        }

        out
    }
}

/// `ARK-DIFF-004`: Mutated `#[contracterror]` integer error code (`ScSpecUdtErrorEnumV0`).
pub struct ErrorEnumDiffRule;

impl DiffRule for ErrorEnumDiffRule {
    fn id(&self) -> &'static str {
        "ARK-DIFF-004"
    }

    fn title(&self) -> &'static str {
        "Mutated #[contracterror] Error Code Mapping"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::AbiCompatibility
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        _config: &SorarkConfig,
    ) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for old_err in &old.error_enums {
            let Some(new_err) = new.error_enums.iter().find(|e| e.name == old_err.name) else {
                continue;
            };
            for old_v in &old_err.variants {
                match new_err.variants.iter().find(|v| v.name == old_v.name) {
                    None => {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Warning,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Contract error variant `{}::{}` (code `{}`) was removed in v2.",
                                old_err.name, old_v.name, old_v.discriminant
                            ),
                            help: "Keep existing `#[contracterror]` variants and numeric codes stable across releases.".to_string(),
                            span: span_from_opt(&new_err.file, new_err.line),
                            contract_item: Some(format!("{}::{}", old_err.name, old_v.name)),
                        });
                    }
                    Some(new_v) if new_v.discriminant != old_v.discriminant => {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Warning,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Contract error `{}::{}` changed numeric error code from `{}` in v1 to `{}` in v2.",
                                old_err.name, old_v.name, old_v.discriminant, new_v.discriminant
                            ),
                            help: "Preserve explicit integer codes on `#[contracterror]` variants.".to_string(),
                            span: span_from_opt(&new_err.file, new_v.line.or(new_err.line)),
                            contract_item: Some(format!("{}::{}", old_err.name, old_v.name)),
                        });
                    }
                    Some(_) => {}
                }
            }
        }
        out
    }
}

/// `ARK-DIFF-005`: Soroban environment protocol version mismatch in `contractenvmetav0`.
pub struct ProtocolVersionDiffRule;

impl DiffRule for ProtocolVersionDiffRule {
    fn id(&self) -> &'static str {
        "ARK-DIFF-005"
    }

    fn title(&self) -> &'static str {
        "Soroban Environment Protocol Version Mismatch"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::AbiCompatibility
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        _config: &SorarkConfig,
    ) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        if let (
            SourceOrigin::WasmBinary {
                protocol_version: Some(old_proto),
                ..
            },
            SourceOrigin::WasmBinary {
                path: new_path,
                protocol_version: Some(new_proto),
                ..
            },
        ) = (&old.origin, &new.origin)
        {
            if new_proto < old_proto {
                out.push(Diagnostic {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    severity: Severity::Error,
                    confidence: Confidence::High,
                    category: self.category(),
                    message: format!(
                        "WASM upgrade downgrades Soroban environment protocol version from Protocol {old_proto} (v1) to Protocol {new_proto} (v2)."
                    ),
                    help: "Compile the v2 contract with a `soroban-sdk` version targeting at least the v1 protocol version.".to_string(),
                    span: span_from_opt(&Some(new_path.clone()), Some(1)),
                    contract_item: None,
                });
            } else if new_proto > old_proto {
                out.push(Diagnostic {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: self.category(),
                    message: format!(
                        "WASM upgrade advances Soroban environment protocol requirement from Protocol {old_proto} (v1) to Protocol {new_proto} (v2)."
                    ),
                    help: format!(
                        "Verify that the target Stellar network has upgraded to Protocol {new_proto} before executing `update_current_contract_wasm`."
                    ),
                    span: span_from_opt(&Some(new_path.clone()), Some(1)),
                    contract_item: None,
                });
            }
        }
        out
    }
}

fn span_from_opt(file: &Option<String>, line: Option<usize>) -> Option<SourceSpan> {
    file.as_ref().map(|f| SourceSpan {
        file: f.clone(),
        line: line.unwrap_or(1),
        column: 1,
        end_line: None,
        snippet: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sorark_ir::{
        EnumVariantSpec, ErrorEnumSpec, FunctionParamSpec, FunctionSpec, StructFieldSpec,
        StructSpec, TypeRef, UnionCaseSpec, UnionSpec,
    };

    #[test]
    fn catches_struct_field_rename_type_change_union_mutation_and_abi_breakage() {
        let mut v1 = ContractModule::new(
            "vault_v1",
            SourceOrigin::RustSource {
                path: "v1/lib.rs".to_string(),
            },
        );
        v1.structs.push(StructSpec {
            name: "UserVault".to_string(),
            fields: vec![
                StructFieldSpec {
                    name: "owner".to_string(),
                    ty: TypeRef::Address,
                    line: Some(10),
                },
                StructFieldSpec {
                    name: "collateral".to_string(),
                    ty: TypeRef::I128,
                    line: Some(11),
                },
            ],
            file: Some("v1/lib.rs".to_string()),
            line: Some(9),
        });
        v1.unions.push(UnionSpec {
            name: "DataKey".to_string(),
            cases: vec![
                UnionCaseSpec {
                    name: "Admin".to_string(),
                    payload: vec![],
                    line: Some(20),
                },
                UnionCaseSpec {
                    name: "Vault".to_string(),
                    payload: vec![TypeRef::Address],
                    line: Some(21),
                },
            ],
            file: Some("v1/lib.rs".to_string()),
            line: Some(19),
        });
        v1.error_enums.push(ErrorEnumSpec {
            name: "VaultError".to_string(),
            variants: vec![EnumVariantSpec {
                name: "InsufficientFunds".to_string(),
                discriminant: 1,
                line: Some(30),
            }],
            file: Some("v1/lib.rs".to_string()),
            line: Some(29),
        });
        v1.functions.push(FunctionSpec {
            name: "withdraw".to_string(),
            params: vec![FunctionParamSpec {
                name: "amount".to_string(),
                ty: TypeRef::I128,
            }],
            return_type: TypeRef::I128,
            file: Some("v1/lib.rs".to_string()),
            line: Some(40),
        });

        let mut v2 = ContractModule::new(
            "vault_v2",
            SourceOrigin::RustSource {
                path: "v2/lib.rs".to_string(),
            },
        );
        // Renamed `collateral` -> `amount` and changed `owner` type
        v2.structs.push(StructSpec {
            name: "UserVault".to_string(),
            fields: vec![
                StructFieldSpec {
                    name: "owner".to_string(),
                    ty: TypeRef::Symbol,
                    line: Some(10),
                },
                StructFieldSpec {
                    name: "amount".to_string(),
                    ty: TypeRef::I128,
                    line: Some(11),
                },
            ],
            file: Some("v2/lib.rs".to_string()),
            line: Some(9),
        });
        // Changed DataKey::Vault(Address) -> DataKey::Vault(Address, u32)
        v2.unions.push(UnionSpec {
            name: "DataKey".to_string(),
            cases: vec![
                UnionCaseSpec {
                    name: "Admin".to_string(),
                    payload: vec![],
                    line: Some(20),
                },
                UnionCaseSpec {
                    name: "Vault".to_string(),
                    payload: vec![TypeRef::Address, TypeRef::U32],
                    line: Some(21),
                },
            ],
            file: Some("v2/lib.rs".to_string()),
            line: Some(19),
        });
        // Shifted error code 1 -> 2
        v2.error_enums.push(ErrorEnumSpec {
            name: "VaultError".to_string(),
            variants: vec![EnumVariantSpec {
                name: "InsufficientFunds".to_string(),
                discriminant: 2,
                line: Some(30),
            }],
            file: Some("v2/lib.rs".to_string()),
            line: Some(29),
        });
        // Changed withdraw parameter type I128 -> U64
        v2.functions.push(FunctionSpec {
            name: "withdraw".to_string(),
            params: vec![FunctionParamSpec {
                name: "amount".to_string(),
                ty: TypeRef::U64,
            }],
            return_type: TypeRef::I128,
            file: Some("v2/lib.rs".to_string()),
            line: Some(40),
        });

        let report = compare_contract_modules(&v1, &v2, &SorarkConfig::default());
        assert!(!report.is_upgrade_safe);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-001")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-002")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-003")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-004")
        );
    }
}
