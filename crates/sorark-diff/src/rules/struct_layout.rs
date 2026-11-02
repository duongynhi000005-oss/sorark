//! `ARK-DIFF-001`: Incompatible `#[contracttype]` struct (`ScMap`) or tuple struct (`ScVec`)
//! storage layout mutation.

use crate::rule::DiffRule;
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan,
    StructSpec, TupleStructSpec,
};

/// Detects breaking field renames, removals, additions, type changes, or representation changes
/// on `#[contracttype]` structs and tuple structs across contract upgrades.
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
        self.check_named_structs(old, new, &mut out);
        self.check_tuple_structs(old, new, &mut out);
        out
    }
}

impl StructLayoutDiffRule {
    /// Compares named `#[contracttype]` structs (serialized on-chain as `ScMap` keyed by `ScSymbol`).
    fn check_named_structs(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        out: &mut Vec<Diagnostic>,
    ) {
        for old_s in &old.structs {
            let Some(new_s) = new.structs.iter().find(|s| s.name == old_s.name) else {
                self.check_struct_converted_to_tuple(old_s, new, out);
                continue;
            };

            self.check_removed_or_changed_fields(old_s, new_s, out);
            self.check_added_fields(old_s, new_s, out);
        }
    }

    /// Detects when a named struct (`ScMap`) in `v1` was converted into a positional tuple struct
    /// (`ScVec`) in `v2`.
    fn check_struct_converted_to_tuple(
        &self,
        old_s: &StructSpec,
        new: &ContractModule,
        out: &mut Vec<Diagnostic>,
    ) {
        let Some(new_ts) = new.tuple_structs.iter().find(|t| t.name == old_s.name) else {
            return;
        };

        out.push(
            Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                .confidence(Confidence::High)
                .message(format!(
                    "#[contracttype] struct `{}` changed representation from named struct (`ScMap`) in v1 to tuple struct (`ScVec`) in v2. Existing on-chain ledger entries will trap on deserialization.",
                    old_s.name
                ))
                .help("Keep the struct as a named-field struct or create a new versioned type (e.g. `StateV2`).")
                . maybe_span(SourceSpan::from_optional_file(new_ts.file.as_deref(), new_ts.line))
                .contract_item(old_s.name.clone())
                .build(),
        );
    }

    /// Checks whether any field from `old_s` was removed, renamed, or had its type mutated in `new_s`.
    fn check_removed_or_changed_fields(
        &self,
        old_s: &StructSpec,
        new_s: &StructSpec,
        out: &mut Vec<Diagnostic>,
    ) {
        for old_field in &old_s.fields {
            match new_s.fields.iter().find(|f| f.name == old_field.name) {
                None => {
                    out.push(
                        Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                            .confidence(Confidence::High)
                            .message(format!(
                                "Field `{}.{}` (type `{}`) was removed or renamed in v2. Because Soroban serializes named `#[contracttype]` structs as `ScMap` keyed by `ScSymbol(\"{}\")`, reading or migrating historical entries without this key breaks storage compatibility.",
                                old_s.name, old_field.name, old_field.ty, old_field.name
                            ))
                            .help(format!(
                                "Retain field `{}.{}: {}` or introduce a versioned struct (`{}V2`) and migrate state explicitly.",
                                old_s.name, old_field.name, old_field.ty, old_s.name
                            ))
                            .maybe_span(SourceSpan::from_optional_file(new_s.file.as_deref(), new_s.line))
                            .contract_item(format!("{}.{}", old_s.name, old_field.name))
                            .build(),
                    );
                }
                Some(new_field) if new_field.ty != old_field.ty => {
                    out.push(
                        Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                            .confidence(Confidence::High)
                            .message(format!(
                                "Field `{}.{}` changed type from `{}` in v1 to `{}` in v2. Deserializing existing `ScMap` ledger entries will trap due to `ScVal` type mismatch.",
                                old_s.name, old_field.name, old_field.ty, new_field.ty
                            ))
                            .help(format!(
                                "Restore `{}.{}` to `{}` or migrate storage entries via a versioned `DataKey`.",
                                old_s.name, old_field.name, old_field.ty
                            ))
                            .maybe_span(SourceSpan::from_optional_file(
                                new_s.file.as_deref(),
                                new_field.line.or(new_s.line),
                            ))
                            .contract_item(format!("{}.{}", old_s.name, old_field.name))
                            .build(),
                    );
                }
                Some(_) => {}
            }
        }
    }

    /// Checks whether any new fields were added to `new_s` that did not exist in `old_s`.
    fn check_added_fields(
        &self,
        old_s: &StructSpec,
        new_s: &StructSpec,
        out: &mut Vec<Diagnostic>,
    ) {
        for new_field in &new_s.fields {
            if !old_s.fields.iter().any(|f| f.name == new_field.name) {
                out.push(
                    Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                        .confidence(Confidence::High)
                        .message(format!(
                            "Struct `{}` added new field `{}` (`{}`) in v2. Historical on-chain `ScMap` entries persisted by v1 do not contain key `ScSymbol(\"{}\")` and will fail deserialization unless migrated.",
                            new_s.name, new_field.name, new_field.ty, new_field.name
                        ))
                        .help(format!(
                            "Wrap state in a versioned `DataKey` variant (e.g. `StateV2({}V2)`) and migrate v1 entries cleanly.",
                            new_s.name
                        ))
                        .maybe_span(SourceSpan::from_optional_file(
                            new_s.file.as_deref(),
                            new_field.line.or(new_s.line),
                        ))
                        .contract_item(format!("{}.{}", new_s.name, new_field.name))
                        .build(),
                );
            }
        }
    }

    /// Compares positional `#[contracttype]` tuple structs (serialized on-chain as `ScVec`).
    fn check_tuple_structs(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        out: &mut Vec<Diagnostic>,
    ) {
        for old_ts in &old.tuple_structs {
            let Some(new_ts) = new.tuple_structs.iter().find(|t| t.name == old_ts.name) else {
                continue;
            };
            self.compare_single_tuple_struct(old_ts, new_ts, out);
        }
    }

    /// Checks a single tuple struct pair for element count or positional type changes.
    fn compare_single_tuple_struct(
        &self,
        old_ts: &TupleStructSpec,
        new_ts: &TupleStructSpec,
        out: &mut Vec<Diagnostic>,
    ) {
        if old_ts.fields.len() != new_ts.fields.len() {
            out.push(
                Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                    .confidence(Confidence::High)
                    .message(format!(
                        "Tuple struct `{}` changed element count from {} in v1 to {} in v2 (`ScVec` length mismatch).",
                        old_ts.name,
                        old_ts.fields.len(),
                        new_ts.fields.len()
                    ))
                    .help("Keep positional tuple struct arity identical across upgrades.")
                    .maybe_span(SourceSpan::from_optional_file(new_ts.file.as_deref(), new_ts.line))
                    .contract_item(old_ts.name.clone())
                    .build(),
            );
            return;
        }

        for (idx, (old_ty, new_ty)) in old_ts.fields.iter().zip(new_ts.fields.iter()).enumerate() {
            if old_ty != new_ty {
                out.push(
                    Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                        .confidence(Confidence::High)
                        .message(format!(
                            "Tuple struct `{}` element `.{idx}` changed type from `{old_ty}` in v1 to `{new_ty}` in v2.",
                            old_ts.name
                        ))
                        .help("Preserve positional element types in tuple structs stored on-chain.")
                        .maybe_span(SourceSpan::from_optional_file(new_ts.file.as_deref(), new_ts.line))
                        .contract_item(format!("{}.{idx}", old_ts.name))
                        .build(),
                );
            }
        }
    }
}
