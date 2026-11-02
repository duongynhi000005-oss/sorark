//! `ARK-DIFF-003`: Breaking public contract entrypoint signature change (`ScSpecFunctionV0`).

use crate::rule::DiffRule;
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, FunctionSpec, RuleCategory, Severity, SorarkConfig,
    SourceSpan,
};

/// Detects removed public entrypoints or changes in parameter or return types across upgrades.
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
        let new_file = new.origin.path();

        for old_fn in &old.functions {
            let Some(new_fn) = new.functions.iter().find(|f| f.name == old_fn.name) else {
                out.push(self.build_removed_function_diagnostic(old_fn, new_file));
                continue;
            };

            self.check_function_params(old_fn, new_fn, &mut out);
            self.check_function_return(old_fn, new_fn, &mut out);
        }

        out
    }
}

impl FunctionAbiDiffRule {
    /// Emits a diagnostic when a public contract entrypoint from `v1` is missing in `v2`.
    fn build_removed_function_diagnostic(
        &self,
        old_fn: &FunctionSpec,
        new_file: &str,
    ) -> Diagnostic {
        Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Warning)
            .confidence(Confidence::High)
            .message(format!(
                "Public contract entrypoint `{}` was removed in v2, breaking downstream cross-contract callers and client SDKs.",
                old_fn.name
            ))
            .help(format!(
                "Keep `{}` as a deprecated wrapper or coordinate a major version upgrade with integrators.",
                old_fn.name
            ))
            .span(SourceSpan::new(new_file, 1, 1))
            .contract_item(old_fn.name.clone())
            .build()
    }

    /// Checks whether a public entrypoint's parameter list changed between `old_fn` and `new_fn`.
    fn check_function_params(
        &self,
        old_fn: &FunctionSpec,
        new_fn: &FunctionSpec,
        out: &mut Vec<Diagnostic>,
    ) {
        let old_param_types: Vec<_> = old_fn.params.iter().map(|p| &p.ty).collect();
        let new_param_types: Vec<_> = new_fn.params.iter().map(|p| &p.ty).collect();

        if old_param_types == new_param_types {
            return;
        }

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

        out.push(
            Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Warning)
                .confidence(Confidence::High)
                .message(format!(
                    "Entrypoint `{}` changed parameters from `({})` in v1 to `({})` in v2.",
                    old_fn.name,
                    old_params.join(", "),
                    new_params.join(", ")
                ))
                .help(format!(
                    "Add a new versioned entrypoint (e.g. `{}_v2`) if callers still depend on `{}`.",
                    old_fn.name, old_fn.name
                ))
                .maybe_span(SourceSpan::from_optional_file(
                    new_fn.file.as_deref(),
                    new_fn.line,
                ))
                .contract_item(old_fn.name.clone())
                .build(),
        );
    }

    /// Checks whether a public entrypoint's return type changed between `old_fn` and `new_fn`.
    fn check_function_return(
        &self,
        old_fn: &FunctionSpec,
        new_fn: &FunctionSpec,
        out: &mut Vec<Diagnostic>,
    ) {
        if old_fn.return_type == new_fn.return_type {
            return;
        }

        out.push(
            Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Warning)
                .confidence(Confidence::High)
                .message(format!(
                    "Entrypoint `{}` changed return type from `{}` in v1 to `{}` in v2.",
                    old_fn.name, old_fn.return_type, new_fn.return_type
                ))
                .help("Preserve the return type of existing public entrypoints to avoid breaking cross-contract invocations.")
                .maybe_span(SourceSpan::from_optional_file(new_fn.file.as_deref(), new_fn.line))
                .contract_item(old_fn.name.clone())
                .build(),
        );
    }
}
