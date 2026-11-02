//! `ARK-STOR-004`: Invalid `extend_ttl(threshold, extend_to)` bounds.

use super::AstRule;
use crate::parser::{AstAnalysisContext, ParsedFunction, StorageOp, StorageOpKind};
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan};

/// `ARK-STOR-004`: Flags `extend_ttl(threshold, extend_to)` calls where `threshold > extend_to`
/// (which traps on the Soroban host), `extend_to == 0`, or `extend_to > max_entry_ttl`.
pub struct InvalidTtlBoundsRule;

impl AstRule for InvalidTtlBoundsRule {
    fn id(&self) -> &'static str {
        "ARK-STOR-004"
    }

    fn title(&self) -> &'static str {
        "Invalid or Out-of-Bounds extend_ttl Parameters"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::StateArchival
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check(&self, ctx: &AstAnalysisContext, config: &SorarkConfig) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for func in &ctx.functions {
            for op in &func.storage_ops {
                self.check_op(ctx, func, op, config, &mut out);
            }
        }
        out
    }
}

impl InvalidTtlBoundsRule {
    /// Evaluates `threshold` and `extend_to` bounds for a single `extend_ttl` operation.
    fn check_op(
        &self,
        ctx: &AstAnalysisContext,
        func: &ParsedFunction,
        op: &StorageOp,
        config: &SorarkConfig,
        out: &mut Vec<Diagnostic>,
    ) {
        if op.kind != StorageOpKind::ExtendTtl {
            return;
        }
        if ctx.is_suppressed(&func.file, op.line, self.id()) {
            return;
        }
        let Some((threshold_opt, extend_to_opt)) = op.ttl_bounds else {
            return;
        };

        if let (Some(threshold), Some(extend_to)) = (threshold_opt, extend_to_opt)
            && threshold > extend_to
        {
            out.push(self.build_inverted_bounds_diagnostic(func, op, threshold, extend_to));
        }

        if let Some(extend_to) = extend_to_opt {
            self.check_extend_to_range(func, op, extend_to, config, out);
        }
    }

    /// Builds an error diagnostic when `threshold > extend_to`.
    fn build_inverted_bounds_diagnostic(
        &self,
        func: &ParsedFunction,
        op: &StorageOp,
        threshold: u64,
        extend_to: u64,
    ) -> Diagnostic {
        Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
            .message(format!(
                "Function `{}` calls `extend_ttl` on `{}` storage with `threshold` ({threshold}) > `extend_to` ({extend_to}). The Soroban host traps at runtime when `threshold > extend_to`.",
                func.name, op.tier
            ))
            .help(format!(
                "Swap or adjust arguments so `threshold <= extend_to` (e.g. `extend_ttl(..., {extend_to}, {threshold})`)."
            ))
            .span(SourceSpan::new(&func.file, op.line, op.column).with_snippet(&op.snippet))
            .contract_item(&func.name)
            .build()
    }

    /// Checks `extend_to == 0` and `extend_to > config.max_entry_ttl`.
    fn check_extend_to_range(
        &self,
        func: &ParsedFunction,
        op: &StorageOp,
        extend_to: u64,
        config: &SorarkConfig,
        out: &mut Vec<Diagnostic>,
    ) {
        if extend_to == 0 {
            out.push(
                Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                    .message(format!(
                        "Function `{}` calls `extend_ttl` with `extend_to = 0`, which is invalid.",
                        func.name
                    ))
                    .help(format!(
                        "Set `extend_to` to at least `{}` ledgers.",
                        config.min_persistent_ttl
                    ))
                    .span(SourceSpan::new(&func.file, op.line, op.column).with_snippet(&op.snippet))
                    .contract_item(&func.name)
                    .build(),
            );
        } else if extend_to > u64::from(config.max_entry_ttl) {
            out.push(
                Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Warning)
                    .message(format!(
                        "Function `{}` calls `extend_ttl` with `extend_to = {extend_to}` ledgers, exceeding Stellar Mainnet `max_entry_ttl` ({} ledgers / ~180 days).",
                        func.name, config.max_entry_ttl
                    ))
                    .help(format!(
                        "Cap `extend_to` at or below `{}` ledgers.",
                        config.max_entry_ttl
                    ))
                    .span(SourceSpan::new(&func.file, op.line, op.column).with_snippet(&op.snippet))
                    .contract_item(&func.name)
                    .build(),
            );
        }
    }
}
