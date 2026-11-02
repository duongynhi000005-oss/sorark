//! `ARK-STOR-001`: Unbounded collection or transitively unbounded struct in `env.storage().instance()`.

use super::AstRule;
use crate::parser::{AstAnalysisContext, ParsedFunction, StorageOp};
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan, StorageTier};

/// `ARK-STOR-001`: Flags dynamically sized collections (`Map`, `Vec`, `Bytes`, `String`) or
/// `#[contracttype]` structs transitively containing them when written to `instance()` storage.
pub struct UnboundedInstanceStorageRule;

impl AstRule for UnboundedInstanceStorageRule {
    fn id(&self) -> &'static str {
        "ARK-STOR-001"
    }

    fn title(&self) -> &'static str {
        "Unbounded Collection in Instance Storage"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::StorageSafety
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check(&self, ctx: &AstAnalysisContext, _config: &SorarkConfig) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for func in &ctx.functions {
            for op in &func.storage_ops {
                if let Some(diag) = self.check_op(ctx, func, op) {
                    out.push(diag);
                }
            }
        }
        out
    }
}

impl UnboundedInstanceStorageRule {
    /// Inspects a single storage operation for an unbounded write to `instance()` storage.
    fn check_op(
        &self,
        ctx: &AstAnalysisContext,
        func: &ParsedFunction,
        op: &StorageOp,
    ) -> Option<Diagnostic> {
        if op.tier != StorageTier::Instance || !op.kind.is_mutation() {
            return None;
        }
        if ctx.is_suppressed(&func.file, op.line, self.id()) {
            return None;
        }

        let val_ty = op.inferred_value_type.as_ref()?;
        let chain = ctx.module.unbounded_reason_chain(val_ty)?;
        let key_label = op.key_expr.as_deref().unwrap_or("<key>");

        Some(
            Diagnostic::builder(self.id(), self.title(), self.category(), self.default_severity())
                .message(format!(
                    "Function `{}` stores unbounded value ({chain}) under key `{key_label}` in `env.storage().instance()`. All instance keys share a single 64 KiB ledger entry loaded on every invocation, which can permanently brick the contract.",
                    func.name
                ))
                .help("Move dynamically growing collections to `env.storage().persistent()` using dedicated `DataKey` variants per item.")
                .span(SourceSpan::new(&func.file, op.line, op.column).with_snippet(&op.snippet))
                .contract_item(&func.name)
                .build(),
        )
    }
}
