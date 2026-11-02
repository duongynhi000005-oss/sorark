//! `ARK-STOR-003`: Security-critical state stored in ephemeral `.temporary()` storage.

use super::AstRule;
use crate::parser::{AstAnalysisContext, ParsedFunction, StorageOp};
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan, StorageTier};

/// Case-insensitive substrings identifying security-critical keys that must never live in
/// unrecoverable `.temporary()` storage.
const CRITICAL_KEY_PATTERNS: &[&str] = &[
    "admin",
    "owner",
    "balance",
    "allowance",
    "nonce",
    "paused",
    "role",
    "supply",
    "total_supply",
    "guardian",
    "governance",
    "treasury",
    "initialized",
];

/// `ARK-STOR-003`: Flags writes of administrative, access-control, nonce, or balance keys to
/// `env.storage().temporary()`.
pub struct CriticalStateInTempStorageRule;

impl AstRule for CriticalStateInTempStorageRule {
    fn id(&self) -> &'static str {
        "ARK-STOR-003"
    }

    fn title(&self) -> &'static str {
        "Critical State Stored in Ephemeral Temporary Storage"
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

impl CriticalStateInTempStorageRule {
    /// Checks a single temporary storage write against [`CRITICAL_KEY_PATTERNS`].
    fn check_op(
        &self,
        ctx: &AstAnalysisContext,
        func: &ParsedFunction,
        op: &StorageOp,
    ) -> Option<Diagnostic> {
        if op.tier != StorageTier::Temporary || !op.kind.is_mutation() {
            return None;
        }
        if ctx.is_suppressed(&func.file, op.line, self.id()) {
            return None;
        }

        let key_str = op.key_expr.as_deref().unwrap_or("");
        if !is_critical_key_name(key_str) {
            return None;
        }

        Some(
            Diagnostic::builder(self.id(), self.title(), self.category(), self.default_severity())
                .message(format!(
                    "Function `{}` writes security-critical key `{key_str}` to `env.storage().temporary()`. Temporary entries expire in as few as 16 ledgers (~80s) and are permanently deleted without archival restoration, enabling state-reset or replay exploits.",
                    func.name
                ))
                .help("Move administrative, access-control, nonce, and balance entries to `env.storage().instance()` or `env.storage().persistent()`.")
                .span(SourceSpan::new(&func.file, op.line, op.column).with_snippet(&op.snippet))
                .contract_item(&func.name)
                .build(),
        )
    }
}

/// Returns `true` if `key_str` matches any critical key identifier pattern.
fn is_critical_key_name(key_str: &str) -> bool {
    let lower = key_str.to_ascii_lowercase();
    CRITICAL_KEY_PATTERNS.iter().any(|pat| lower.contains(pat))
}
