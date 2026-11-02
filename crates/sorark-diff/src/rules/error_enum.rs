//! `ARK-DIFF-004`: Mutated `#[contracterror]` integer error code (`ScSpecUdtErrorEnumV0`).

use crate::rule::DiffRule;
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, ErrorEnumSpec, RuleCategory, Severity, SorarkConfig,
    SourceSpan,
};

/// Detects removed error variants or shifted numeric discriminants in `#[contracterror]` enums.
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
            self.compare_single_error_enum(old_err, new_err, &mut out);
        }
        out
    }
}

impl ErrorEnumDiffRule {
    /// Compares all variants of a single `#[contracterror]` enum between `old_err` and `new_err`.
    fn compare_single_error_enum(
        &self,
        old_err: &ErrorEnumSpec,
        new_err: &ErrorEnumSpec,
        out: &mut Vec<Diagnostic>,
    ) {
        for old_v in &old_err.variants {
            match new_err.variants.iter().find(|v| v.name == old_v.name) {
                None => {
                    out.push(
                        Diagnostic::builder(
                            self.id(),
                            self.title(),
                            self.category(),
                            Severity::Warning,
                        )
                        .confidence(Confidence::High)
                        .message(format!(
                            "Contract error variant `{}::{}` (code `{}`) was removed in v2.",
                            old_err.name, old_v.name, old_v.discriminant
                        ))
                        .help("Keep existing `#[contracterror]` variants and numeric codes stable across releases.")
                        .maybe_span(SourceSpan::from_optional_file(new_err.file.as_deref(), new_err.line))
                        .contract_item(format!("{}::{}", old_err.name, old_v.name))
                        .build(),
                    );
                }
                Some(new_v) if new_v.discriminant != old_v.discriminant => {
                    out.push(
                        Diagnostic::builder(
                            self.id(),
                            self.title(),
                            self.category(),
                            Severity::Warning,
                        )
                        .confidence(Confidence::High)
                        .message(format!(
                            "Contract error `{}::{}` changed numeric error code from `{}` in v1 to `{}` in v2.",
                            old_err.name, old_v.name, old_v.discriminant, new_v.discriminant
                        ))
                        .help("Preserve explicit integer codes on `#[contracterror]` variants.")
                        .maybe_span(SourceSpan::from_optional_file(
                            new_err.file.as_deref(),
                            new_v.line.or(new_err.line),
                        ))
                        .contract_item(format!("{}::{}", old_err.name, old_v.name))
                        .build(),
                    );
                }
                Some(_) => {}
            }
        }
    }
}
