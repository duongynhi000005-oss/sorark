//! `ARK-DIFF-002`: Incompatible `#[contracttype]` enum (`ScSpecUdtEnumV0`) or tagged union
//! (`ScSpecUdtUnionV0`) mutation.

use crate::rule::DiffRule;
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, EnumSpec, RuleCategory, Severity, SorarkConfig,
    SourceSpan, UnionSpec,
};

/// Detects variant removals, discriminant shifts, or payload layout mutations on
/// `#[contracttype]` unit enums and tagged unions (such as `DataKey`).
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
        self.check_unit_enums(old, new, &mut out);
        self.check_tagged_unions(old, new, &mut out);
        out
    }
}

impl EnumAndUnionLayoutDiffRule {
    /// Checks unit integer enums (`ScSpecUdtEnumV0` -> `ScVal::U32`) for variant removals or
    /// discriminant changes.
    fn check_unit_enums(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        out: &mut Vec<Diagnostic>,
    ) {
        for old_e in &old.enums {
            let Some(new_e) = new.enums.iter().find(|e| e.name == old_e.name) else {
                continue;
            };
            self.compare_single_enum(old_e, new_e, out);
        }
    }

    /// Compares all variants of a single unit enum between `old_e` and `new_e`.
    fn compare_single_enum(&self, old_e: &EnumSpec, new_e: &EnumSpec, out: &mut Vec<Diagnostic>) {
        for old_v in &old_e.variants {
            match new_e.variants.iter().find(|v| v.name == old_v.name) {
                None => {
                    out.push(
                        Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                            .confidence(Confidence::High)
                            .message(format!(
                                "Enum variant `{}::{}` (discriminant `{}`) was removed in v2. Historical ledger entries storing `{}` will trap.",
                                old_e.name, old_v.name, old_v.discriminant, old_v.discriminant
                            ))
                            .help("Never remove or rename existing enum variants; deprecate them in place.")
                            .maybe_span(SourceSpan::from_optional_file(new_e.file.as_deref(), new_e.line))
                            .contract_item(format!("{}::{}", old_e.name, old_v.name))
                            .build(),
                    );
                }
                Some(new_v) if new_v.discriminant != old_v.discriminant => {
                    out.push(
                        Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                            .confidence(Confidence::High)
                            .message(format!(
                                "Enum variant `{}::{}` changed integer discriminant from `{}` in v1 to `{}` in v2, silently corrupting persisted enum state.",
                                old_e.name, old_v.name, old_v.discriminant, new_v.discriminant
                            ))
                            .help("Append new variants only at the end of the enum and pin explicit integer discriminants.")
                            .maybe_span(SourceSpan::from_optional_file(
                                new_e.file.as_deref(),
                                new_v.line.or(new_e.line),
                            ))
                            .contract_item(format!("{}::{}", old_e.name, old_v.name))
                            .build(),
                    );
                }
                Some(_) => {}
            }
        }
    }

    /// Checks tagged unions / `DataKey` enums (`ScSpecUdtUnionV0` -> `ScVec([ScSymbol(tag), ...])`)
    /// for removed variants or mutated tuple payloads.
    fn check_tagged_unions(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        out: &mut Vec<Diagnostic>,
    ) {
        for old_u in &old.unions {
            let Some(new_u) = new.unions.iter().find(|u| u.name == old_u.name) else {
                continue;
            };
            self.compare_single_union(old_u, new_u, out);
        }
    }

    /// Compares all cases of a single tagged union between `old_u` and `new_u`.
    fn compare_single_union(
        &self,
        old_u: &UnionSpec,
        new_u: &UnionSpec,
        out: &mut Vec<Diagnostic>,
    ) {
        for old_c in &old_u.cases {
            match new_u.cases.iter().find(|c| c.name == old_c.name) {
                None => {
                    out.push(
                        Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                            .confidence(Confidence::High)
                            .message(format!(
                                "Union/DataKey variant `{}::{}` was removed or renamed in v2. Any ledger entry keyed or stored under `ScSymbol(\"{}\")` becomes permanently orphaned or unreadable.",
                                old_u.name, old_c.name, old_c.name
                            ))
                            .help(format!(
                                "Keep `{}::{}` intact in v2; append new storage key variants without removing historical ones.",
                                old_u.name, old_c.name
                            ))
                            .maybe_span(SourceSpan::from_optional_file(new_u.file.as_deref(), new_u.line))
                            .contract_item(format!("{}::{}", old_u.name, old_c.name))
                            .build(),
                    );
                }
                Some(new_c) if new_c.payload != old_c.payload => {
                    let old_sig: Vec<String> =
                        old_c.payload.iter().map(ToString::to_string).collect();
                    let new_sig: Vec<String> =
                        new_c.payload.iter().map(ToString::to_string).collect();
                    out.push(
                        Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                            .confidence(Confidence::High)
                            .message(format!(
                                "Union/DataKey variant `{}::{}` changed payload layout from `({})` in v1 to `({})` in v2, breaking ledger key lookup and deserialization.",
                                old_u.name,
                                old_c.name,
                                old_sig.join(", "),
                                new_sig.join(", ")
                            ))
                            .help(format!(
                                "Create a new variant (e.g. `{}::{}V2(...)`) rather than mutating `{}::{}` in place.",
                                old_u.name, old_c.name, old_u.name, old_c.name
                            ))
                            .maybe_span(SourceSpan::from_optional_file(
                                new_u.file.as_deref(),
                                new_c.line.or(new_u.line),
                            ))
                            .contract_item(format!("{}::{}", old_u.name, old_c.name))
                            .build(),
                    );
                }
                Some(_) => {}
            }
        }
    }
}
