//! Two-pass Rust AST static analyzer for Soroban smart contracts (`sorark-ast`).
//!
//! Pass 1 collects `#[contracttype]` structs/enums, computes transitive unbounded types,
//! resolves module constants, and builds an intra-module helper function call graph for
//! `extend_ttl` and `require_auth`.
//!
//! Pass 2 executes registered [`AstRule`] implementations against [`AstAnalysisContext`].

pub mod parser;
pub mod rules;

pub use parser::{
    AstAnalysisContext, ParsedFunction, StorageOp, StorageOpKind, WasmUpgradeCall,
    parse_inline_suppressions, parse_rust_source_into_context, parse_single_source,
    syn_type_to_typeref,
};
pub use rules::{
    AstRule, CriticalStateInTempStorageRule, InvalidTtlBoundsRule, MissingExtendTtlRule,
    MissingUpgradeMechanismRule, UnboundedInstanceStorageRule, UnprotectedWasmUpgradeRule,
    default_ast_rules,
};

use sorark_ir::{ContractModule, Diagnostic, SorarkConfig, SourceOrigin};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum AstEngineError {
    #[error("Failed to read path `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Rust syntax error in `{file}`: {source}")]
    Syntax {
        file: String,
        #[source]
        source: syn::Error,
    },
    #[error("No Rust source files (`.rs`) found under `{path}`")]
    NoRustFiles { path: String },
}

/// Result of analyzing a Soroban Rust source file or directory.
#[derive(Debug, Clone)]
pub struct AstScanReport {
    pub context: AstAnalysisContext,
    pub diagnostics: Vec<Diagnostic>,
    pub files_scanned: usize,
}

/// Scans a single `.rs` file or recursively scans a directory of `.rs` files, building a unified
/// [`AstAnalysisContext`] and running all enabled [`AstRule`]s.
pub fn scan_rust_path(
    target_path: impl AsRef<Path>,
    config: &SorarkConfig,
) -> Result<AstScanReport, AstEngineError> {
    let root = target_path.as_ref();
    if !root.exists() {
        return Err(AstEngineError::Io {
            path: root.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "path does not exist"),
        });
    }

    let module_name = root
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("soroban_contract")
        .to_string();

    let mut ctx = AstAnalysisContext {
        module: ContractModule::new(
            module_name,
            SourceOrigin::RustSource {
                path: root.display().to_string(),
            },
        ),
        functions: Vec::new(),
        constants: HashMap::new(),
        inline_suppressions: HashMap::new(),
    };

    let mut rs_files = Vec::new();
    if root.is_file() {
        rs_files.push(root.to_path_buf());
    } else {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !is_excluded_entry(e.path(), &config.exclude_paths))
        {
            let entry = entry.map_err(|err| AstEngineError::Io {
                path: root.display().to_string(),
                source: err.into(),
            })?;
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("rs")
            {
                rs_files.push(entry.path().to_path_buf());
            }
        }
    }

    rs_files.sort();
    if rs_files.is_empty() {
        return Err(AstEngineError::NoRustFiles {
            path: root.display().to_string(),
        });
    }

    for file_path in &rs_files {
        let display_path = file_path.display().to_string();
        let raw = std::fs::read_to_string(file_path).map_err(|source| AstEngineError::Io {
            path: display_path.clone(),
            source,
        })?;
        parse_rust_source_into_context(&display_path, &raw, &mut ctx).map_err(|source| {
            AstEngineError::Syntax {
                file: display_path,
                source,
            }
        })?;
    }

    let diagnostics = run_rules_on_context(&ctx, config);
    Ok(AstScanReport {
        context: ctx,
        diagnostics,
        files_scanned: rs_files.len(),
    })
}

/// Runs all enabled default [`AstRule`]s against an already-constructed [`AstAnalysisContext`].
#[must_use]
pub fn run_rules_on_context(ctx: &AstAnalysisContext, config: &SorarkConfig) -> Vec<Diagnostic> {
    let rules = default_ast_rules();
    let mut diagnostics = Vec::new();
    for rule in &rules {
        if config.is_rule_enabled(rule.id()) {
            diagnostics.extend(rule.check(ctx, config));
        }
    }
    diagnostics
}

fn is_excluded_entry(path: &Path, exclude_patterns: &[String]) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    exclude_patterns.iter().any(|pat| name == pat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_transitive_unbounded_instance_storage_and_missing_ttl() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map};

            #[contracttype]
            pub struct VaultRegistry {
                pub admin: Address,
                pub balances: Map<Address, i128>,
            }

            #[contracttype]
            pub enum DataKey {
                Registry,
                TempAdmin,
            }

            #[contract]
            pub struct VaultContract;

            #[contractimpl]
            impl VaultContract {
                pub fn set_registry(env: Env, reg: VaultRegistry) {
                    env.storage().instance().set(&DataKey::Registry, &reg);
                    env.storage().temporary().set(&DataKey::TempAdmin, &reg.admin);
                }
            }
        "#;

        let ctx = parse_single_source("vault", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());

        assert!(diags.iter().any(|d| d.rule_id == "ARK-STOR-001"));
        assert!(diags.iter().any(|d| d.rule_id == "ARK-STOR-002"));
        assert!(diags.iter().any(|d| d.rule_id == "ARK-STOR-003"));
    }

    #[test]
    fn two_pass_helper_call_graph_suppresses_false_positives_for_ttl_and_auth() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

            const DAY_IN_LEDGERS: u32 = 17_280;

            #[contracttype]
            pub enum DataKey {
                Admin,
                Balance(Address),
            }

            #[contract]
            pub struct SafeVault;

            #[contractimpl]
            impl SafeVault {
                pub fn deposit(env: Env, user: Address, amount: i128) {
                    env.storage().persistent().set(&DataKey::Balance(user.clone()), &amount);
                    bump_balance_ttl(&env, &user);
                }

                pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
                    assert_admin(&env);
                    env.deployer().update_current_contract_wasm(new_wasm_hash);
                }
            }

            fn bump_balance_ttl(env: &Env, user: &Address) {
                env.storage().persistent().extend_ttl(
                    &DataKey::Balance(user.clone()),
                    DAY_IN_LEDGERS,
                    DAY_IN_LEDGERS * 30,
                );
            }

            fn assert_admin(env: &Env) {
                let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
                admin.require_auth();
            }
        "#;

        let ctx = parse_single_source("safe_vault", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());

        assert!(
            diags.is_empty(),
            "Expected zero false positives with helper call-graph, got: {diags:#?}"
        );
    }

    #[test]
    fn detects_invalid_ttl_bounds_and_unprotected_upgrade() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, BytesN, Env};

            #[contract]
            pub struct BadContract;

            #[contractimpl]
            impl BadContract {
                pub fn bad_ttl(env: Env) {
                    // threshold (50_000) > extend_to (10_000) -> host trap!
                    env.storage().instance().extend_ttl(50_000, 10_000);
                }

                pub fn open_upgrade(env: Env, hash: BytesN<32>) {
                    env.deployer().update_current_contract_wasm(hash);
                }
            }
        "#;

        let ctx = parse_single_source("bad", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());

        assert!(diags.iter().any(|d| d.rule_id == "ARK-STOR-004"));
        assert!(diags.iter().any(|d| d.rule_id == "ARK-UPG-001"));
    }

    #[test]
    fn respects_inline_sorark_ignore_comments() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, BytesN, Env};

            #[contract]
            pub struct IgnoredContract;

            #[contractimpl]
            impl IgnoredContract {
                pub fn open_upgrade(env: Env, hash: BytesN<32>) {
                    // sorark-ignore: ARK-UPG-001
                    env.deployer().update_current_contract_wasm(hash);
                }
            }
        "#;

        let ctx = parse_single_source("ignored", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());
        assert!(!diags.iter().any(|d| d.rule_id == "ARK-UPG-001"));
    }
}
