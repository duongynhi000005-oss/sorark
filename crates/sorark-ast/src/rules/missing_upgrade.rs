//! `ARK-UPG-002`: Stateful contract missing an `update_current_contract_wasm` upgrade mechanism.

use super::AstRule;
use crate::parser::AstAnalysisContext;
use sorark_ir::{Confidence, Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan};

/// `ARK-UPG-002`: Informational check flagging stateful Soroban contracts that mutate ledger
/// state across entrypoints without providing an upgrade handler.
pub struct MissingUpgradeMechanismRule;

impl AstRule for MissingUpgradeMechanismRule {
    fn id(&self) -> &'static str {
        "ARK-UPG-002"
    }

    fn title(&self) -> &'static str {
        "Stateful Contract Missing Upgrade Mechanism"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::UpgradeAuth
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn check(&self, ctx: &AstAnalysisContext, _config: &SorarkConfig) -> Vec<Diagnostic> {
        let entrypoint_count = ctx
            .functions
            .iter()
            .filter(|f| f.is_contract_entrypoint)
            .count();
        let has_state_writes = ctx
            .functions
            .iter()
            .any(|f| f.storage_ops.iter().any(|op| op.kind.is_mutation()));
        let has_upgrade_call = ctx
            .functions
            .iter()
            .any(|f| !f.wasm_upgrade_calls.is_empty());

        if entrypoint_count > 0
            && has_state_writes
            && !has_upgrade_call
            && let Some(first_ep) = ctx.functions.iter().find(|f| f.is_contract_entrypoint)
            && !ctx.is_suppressed(&first_ep.file, first_ep.line, self.id())
        {
            return vec![
                Diagnostic::builder(
                    self.id(),
                    self.title(),
                    self.category(),
                    self.default_severity(),
                )
                .confidence(Confidence::Medium)
                .message(format!(
                    "Contract module `{}` mutates on-chain storage across {entrypoint_count} entrypoint(s) but defines no `update_current_contract_wasm` upgrade handler.",
                    ctx.module.name
                ))
                .help("If the contract is not intentionally immutable, add an admin-gated `upgrade(env: Env, new_wasm_hash: BytesN<32>)` entrypoint or disable `ARK-UPG-002` in `sorark.toml`.")
                .span(SourceSpan::new(&first_ep.file, first_ep.line, first_ep.column))
                .contract_item(&ctx.module.name)
                .build(),
            ];
        }
        Vec::new()
    }
}
