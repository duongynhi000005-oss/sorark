use crate::parser::{AstAnalysisContext, StorageOpKind};
use sorark_ir::{
    Confidence, Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan, StorageTier,
};

/// Extensible trait for Pass-2 Soroban AST static analysis rules.
///
/// Contributors adding a new AST rule implement this trait and register it in [`default_ast_rules`].
pub trait AstRule: Send + Sync {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn category(&self) -> RuleCategory;
    fn default_severity(&self) -> Severity;
    fn check(&self, ctx: &AstAnalysisContext, config: &SorarkConfig) -> Vec<Diagnostic>;
}

/// Returns the default suite of Pass-2 Soroban AST rules.
#[must_use]
pub fn default_ast_rules() -> Vec<Box<dyn AstRule>> {
    vec![
        Box::new(UnboundedInstanceStorageRule),
        Box::new(MissingExtendTtlRule),
        Box::new(CriticalStateInTempStorageRule),
        Box::new(InvalidTtlBoundsRule),
        Box::new(UnprotectedWasmUpgradeRule),
        Box::new(MissingUpgradeMechanismRule),
    ]
}

/// `ARK-STOR-001`: Unbounded collection or transitively unbounded struct in `env.storage().instance()`.
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
                if op.tier != StorageTier::Instance
                    || !matches!(op.kind, StorageOpKind::Set | StorageOpKind::Update)
                {
                    continue;
                }
                if ctx.is_suppressed(&func.file, op.line, self.id()) {
                    continue;
                }

                if let Some(val_ty) = &op.inferred_value_type
                    && ctx.module.is_type_transitively_unbounded(val_ty)
                {
                    let chain = ctx
                        .module
                        .unbounded_reason_chain(val_ty)
                        .unwrap_or_else(|| format!("`{val_ty}` is dynamically sized"));
                    let key_label = op.key_expr.as_deref().unwrap_or("<key>");
                    out.push(Diagnostic {
                        rule_id: self.id().to_string(),
                        title: self.title().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        category: self.category(),
                        message: format!(
                            "Function `{}` stores unbounded value ({chain}) under key `{key_label}` in `env.storage().instance()`. All instance keys share a single 64 KiB ledger entry loaded on every invocation, which can permanently brick the contract.",
                            func.name
                        ),
                        help: "Move dynamically growing collections to `env.storage().persistent()` using dedicated `DataKey` variants per item.".to_string(),
                        span: Some(SourceSpan {
                            file: func.file.clone(),
                            line: op.line,
                            column: op.column,
                            end_line: None,
                            snippet: Some(op.snippet.clone()),
                        }),
                        contract_item: Some(func.name.clone()),
                    });
                }
            }
        }
        out
    }
}

/// `ARK-STOR-002`: Mutating `persistent()` or `instance()` storage without calling `extend_ttl`
/// directly or via a local helper function.
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
            // Only flag public contract entrypoints (helpers may legitimately delegate TTL management to callers)
            if !func.is_contract_entrypoint {
                continue;
            }
            for op in &func.storage_ops {
                if !matches!(op.tier, StorageTier::Persistent | StorageTier::Instance)
                    || !matches!(op.kind, StorageOpKind::Set | StorageOpKind::Update)
                {
                    continue;
                }
                if ctx.is_suppressed(&func.file, op.line, self.id()) {
                    continue;
                }

                // Two-pass check: did this function or any helper it calls invoke `extend_ttl` on this tier?
                if !ctx.function_extends_ttl(func, op.tier) {
                    let key_label = op.key_expr.as_deref().unwrap_or("<key>");
                    let help_call = match op.tier {
                        StorageTier::Instance => {
                            "env.storage().instance().extend_ttl(threshold, extend_to);"
                        }
                        StorageTier::Persistent => {
                            "env.storage().persistent().extend_ttl(&key, threshold, extend_to);"
                        }
                        StorageTier::Temporary => "",
                    };
                    out.push(Diagnostic {
                        rule_id: self.id().to_string(),
                        title: self.title().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        category: self.category(),
                        message: format!(
                            "Entrypoint `{}` writes to `{}` storage (key `{key_label}`) without extending its TTL directly or via a helper function. Unextended entries risk unexpected archival after `min_persistent_entry_ttl` (4,096 ledgers).",
                            func.name, op.tier
                        ),
                        help: format!("Add `{help_call}` after mutating state, or suppress with `// sorark-ignore: ARK-STOR-002` if a keeper manages rent."),
                        span: Some(SourceSpan {
                            file: func.file.clone(),
                            line: op.line,
                            column: op.column,
                            end_line: None,
                            snippet: Some(op.snippet.clone()),
                        }),
                        contract_item: Some(func.name.clone()),
                    });
                }
            }
        }
        out
    }
}

/// `ARK-STOR-003`: Security-critical state stored in `.temporary()` storage.
pub struct CriticalStateInTempStorageRule;

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
                if op.tier != StorageTier::Temporary
                    || !matches!(op.kind, StorageOpKind::Set | StorageOpKind::Update)
                {
                    continue;
                }
                if ctx.is_suppressed(&func.file, op.line, self.id()) {
                    continue;
                }

                let key_str = op.key_expr.as_deref().unwrap_or("");
                let lower_key = key_str.to_ascii_lowercase();
                let is_critical = CRITICAL_KEY_PATTERNS
                    .iter()
                    .any(|pat| lower_key.contains(pat));

                if is_critical {
                    out.push(Diagnostic {
                        rule_id: self.id().to_string(),
                        title: self.title().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        category: self.category(),
                        message: format!(
                            "Function `{}` writes security-critical key `{key_str}` to `env.storage().temporary()`. Temporary entries expire in as few as 16 ledgers (~80s) and are permanently deleted without archival restoration, enabling state-reset or replay exploits.",
                            func.name
                        ),
                        help: "Move administrative, access-control, nonce, and balance entries to `env.storage().instance()` or `env.storage().persistent()`.".to_string(),
                        span: Some(SourceSpan {
                            file: func.file.clone(),
                            line: op.line,
                            column: op.column,
                            end_line: None,
                            snippet: Some(op.snippet.clone()),
                        }),
                        contract_item: Some(func.name.clone()),
                    });
                }
            }
        }
        out
    }
}

/// `ARK-STOR-004`: Invalid `extend_ttl(threshold, extend_to)` bounds (`threshold > extend_to`, `extend_to == 0`, or `extend_to > max_entry_ttl`).
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
                if op.kind != StorageOpKind::ExtendTtl {
                    continue;
                }
                if ctx.is_suppressed(&func.file, op.line, self.id()) {
                    continue;
                }
                let Some((threshold_opt, extend_to_opt)) = op.ttl_bounds else {
                    continue;
                };

                if let (Some(threshold), Some(extend_to)) = (threshold_opt, extend_to_opt)
                    && threshold > extend_to
                {
                    out.push(Diagnostic {
                        rule_id: self.id().to_string(),
                        title: self.title().to_string(),
                        severity: Severity::Error,
                        confidence: Confidence::High,
                        category: self.category(),
                        message: format!(
                            "Function `{}` calls `extend_ttl` on `{}` storage with `threshold` ({threshold}) > `extend_to` ({extend_to}). The Soroban host traps at runtime when `threshold > extend_to`.",
                            func.name, op.tier
                        ),
                        help: format!("Swap or adjust arguments so `threshold <= extend_to` (e.g. `extend_ttl(..., {extend_to}, {threshold})`)."),
                        span: Some(SourceSpan {
                            file: func.file.clone(),
                            line: op.line,
                            column: op.column,
                            end_line: None,
                            snippet: Some(op.snippet.clone()),
                        }),
                        contract_item: Some(func.name.clone()),
                    });
                }

                if let Some(extend_to) = extend_to_opt {
                    if extend_to == 0 {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Error,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Function `{}` calls `extend_ttl` with `extend_to = 0`, which is invalid.",
                                func.name
                            ),
                            help: format!("Set `extend_to` to at least `{}` ledgers.", config.min_persistent_ttl),
                            span: Some(SourceSpan {
                                file: func.file.clone(),
                                line: op.line,
                                column: op.column,
                                end_line: None,
                                snippet: Some(op.snippet.clone()),
                            }),
                            contract_item: Some(func.name.clone()),
                        });
                    } else if extend_to > u64::from(config.max_entry_ttl) {
                        out.push(Diagnostic {
                            rule_id: self.id().to_string(),
                            title: self.title().to_string(),
                            severity: Severity::Warning,
                            confidence: Confidence::High,
                            category: self.category(),
                            message: format!(
                                "Function `{}` calls `extend_ttl` with `extend_to = {extend_to}` ledgers, exceeding Stellar Mainnet `max_entry_ttl` ({} ledgers / ~180 days).",
                                func.name, config.max_entry_ttl
                            ),
                            help: format!("Cap `extend_to` at or below `{}` ledgers.", config.max_entry_ttl),
                            span: Some(SourceSpan {
                                file: func.file.clone(),
                                line: op.line,
                                column: op.column,
                                end_line: None,
                                snippet: Some(op.snippet.clone()),
                            }),
                            contract_item: Some(func.name.clone()),
                        });
                    }
                }
            }
        }
        out
    }
}

/// `ARK-UPG-001`: Calling `update_current_contract_wasm` without a dominating `require_auth()` check.
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
                    out.push(Diagnostic {
                        rule_id: self.id().to_string(),
                        title: self.title().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        category: self.category(),
                        message: format!(
                            "Function `{}` invokes `update_current_contract_wasm` without verifying caller authorization (`require_auth()`). Any unauthenticated caller can replace the contract bytecode.",
                            func.name
                        ),
                        help: "Load the stored administrator `Address` and call `admin.require_auth()` before `env.deployer().update_current_contract_wasm(...)`.".to_string(),
                        span: Some(SourceSpan {
                            file: func.file.clone(),
                            line: upg.line,
                            column: upg.column,
                            end_line: None,
                            snippet: Some(upg.snippet.clone()),
                        }),
                        contract_item: Some(func.name.clone()),
                    });
                }
            }
        }
        out
    }
}

/// `ARK-UPG-002`: Stateful contract with administrative init flow lacks an upgrade mechanism.
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
        let has_any_entrypoints = ctx.functions.iter().any(|f| f.is_contract_entrypoint);
        let has_state_writes = ctx.functions.iter().any(|f| {
            f.storage_ops
                .iter()
                .any(|op| matches!(op.kind, StorageOpKind::Set | StorageOpKind::Update))
        });
        let has_upgrade_call = ctx
            .functions
            .iter()
            .any(|f| !f.wasm_upgrade_calls.is_empty());

        if has_any_entrypoints
            && has_state_writes
            && !has_upgrade_call
            && let Some(first_ep) = ctx.functions.iter().find(|f| f.is_contract_entrypoint)
            && !ctx.is_suppressed(&first_ep.file, first_ep.line, self.id())
        {
            return vec![Diagnostic {
                rule_id: self.id().to_string(),
                title: self.title().to_string(),
                severity: self.default_severity(),
                confidence: Confidence::Medium,
                category: self.category(),
                message: format!(
                    "Contract module `{}` mutates on-chain storage across {} entrypoint(s) but defines no `update_current_contract_wasm` upgrade handler.",
                    ctx.module.name,
                    ctx.functions.iter().filter(|f| f.is_contract_entrypoint).count()
                ),
                help: "If the contract is not intentionally immutable, add an admin-gated `upgrade(env: Env, new_wasm_hash: BytesN<32>)` entrypoint or disable `ARK-UPG-002` in `sorark.toml`.".to_string(),
                span: Some(SourceSpan {
                    file: first_ep.file.clone(),
                    line: first_ep.line,
                    column: first_ep.column,
                    end_line: None,
                    snippet: None,
                }),
                contract_item: Some(ctx.module.name.clone()),
            }];
        }
        Vec::new()
    }
}
