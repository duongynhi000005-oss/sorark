//! `ARK-STOR-002`: Missing `extend_ttl` on `persistent()` or `instance()` storage mutations.

use super::AstRule;
use crate::parser::{AstAnalysisContext, ParsedFunction, StorageOp};
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan, StorageTier};

/// `ARK-STOR-002`: Flags public contract entrypoints that mutate `persistent()` or `instance()`
/// storage without extending the entry's TTL directly or via a local helper function.
pub struct MissingExtendTtlRule;

impl AstRule for MissingExtendTtlRule {
    fn id(&self) -> &'static str {
        "ARK-STOR-002"
    }

    fn title(&self) -> &'static str {
        "Missing TTL Extension on Persistent/Instance Mutation"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::StateArchival
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, ctx: &AstAnalysisContext, _config: &SorarkConfig) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for func in &ctx.functions {
            if !func.is_contract_entrypoint {
                continue;
            }
            for op in &func.storage_ops {
                if let Some(diag) = self.check_op(ctx, func, op) {
                    out.push(diag);
                }
            }
        }
        out
    }
}

impl MissingExtendTtlRule {
    /// Checks whether a single storage write in `func` is paired with a direct or helper `extend_ttl`.
    fn check_op(
        &self,
        ctx: &AstAnalysisContext,
        func: &ParsedFunction,
        op: &StorageOp,
    ) -> Option<Diagnostic> {
        if !matches!(op.tier, StorageTier::Persistent | StorageTier::Instance)
            || !op.kind.is_mutation()
        {
            return None;
        }
        if ctx.is_suppressed(&func.file, op.line, self.id()) {
            return None;
        }
        if ctx.function_extends_ttl(func, op.tier) {
            return None;
        }

        let key_label = op.key_expr.as_deref().unwrap_or("<key>");
        let help_call = suggested_extend_ttl_call(op.tier);

        Some(
            Diagnostic::builder(self.id(), self.title(), self.category(), self.default_severity())
                .message(format!(
                    "Entrypoint `{}` writes to `{}` storage (key `{key_label}`) without extending its TTL directly or via a helper function. Unextended entries risk unexpected archival after `min_persistent_entry_ttl` (4,096 ledgers).",
                    func.name, op.tier
                ))
                .help(format!(
                    "Add `{help_call}` after mutating state, or suppress with `// sorark-ignore: ARK-STOR-002` if a keeper manages rent."
                ))
                .span(SourceSpan::new(&func.file, op.line, op.column).with_snippet(&op.snippet))
                .contract_item(&func.name)
                .build(),
        )
    }
}

/// Returns the idiomatic `extend_ttl` SDK call snippet for a storage tier.
const fn suggested_extend_ttl_call(tier: StorageTier) -> &'static str {
    match tier {
        StorageTier::Instance => "env.storage().instance().extend_ttl(threshold, extend_to);",
        StorageTier::Persistent => {
            "env.storage().persistent().extend_ttl(&key, threshold, extend_to);"
        }
        StorageTier::Temporary => "",
    }
}
