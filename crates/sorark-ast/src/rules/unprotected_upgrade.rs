//! `ARK-UPG-001`: Calling `update_current_contract_wasm` without a dominating `require_auth()`.

use super::AstRule;
use crate::parser::AstAnalysisContext;
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan};

/// `ARK-UPG-001`: Flags calls to `env.deployer().update_current_contract_wasm(...)` that are not
/// guarded by a direct or helper `require_auth()` check.
pub struct UnprotectedWasmUpgradeRule;

impl AstRule for UnprotectedWasmUpgradeRule {
    fn id(&self) -> &'static str {
        "ARK-UPG-001"
    }

    fn title(&self) -> &'static str {
        "Unprotected Contract WASM Upgrade"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::UpgradeAuth
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check(&self, ctx: &AstAnalysisContext, _config: &SorarkConfig) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for func in &ctx.functions {
            for upg in &func.wasm_upgrade_calls {
                if ctx.is_suppressed(&func.file, upg.line, self.id()) {
                    continue;
                }
                let authorized = upg.auth_seen_before_call || ctx.function_requires_auth(func);
                if !authorized {
                    out.push(
                        Diagnostic::builder(
                            self.id(),
                            self.title(),
                            self.category(),
                            self.default_severity(),
                        )
                        .message(format!(
                            "Function `{}` invokes `update_current_contract_wasm` without verifying caller authorization (`require_auth()`). Any unauthenticated caller can replace the contract bytecode.",
                            func.name
                        ))
                        .help("Load the stored administrator `Address` and call `admin.require_auth()` before `env.deployer().update_current_contract_wasm(...)`.")
                        .span(
                            SourceSpan::new(&func.file, upg.line, upg.column)
                                .with_snippet(&upg.snippet),
                        )
                        .contract_item(&func.name)
                        .build(),
                    );
                }
            }
        }
        out
    }
}
