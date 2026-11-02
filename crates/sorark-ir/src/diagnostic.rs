use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level of a SORARK diagnostic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Maps SORARK severity to SARIF v2.1.0 level string.
    #[must_use]
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Self::Info => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Confidence level of a static or binary analysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
        }
    }
}

/// High-level rule taxonomy for SORARK checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    StorageSafety,
    StateArchival,
    UpgradeAuth,
    StorageCompatibility,
    AbiCompatibility,
    ResourceBudget,
}

impl fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageSafety => f.write_str("storage-safety"),
            Self::StateArchival => f.write_str("state-archival"),
            Self::UpgradeAuth => f.write_str("upgrade-auth"),
            Self::StorageCompatibility => f.write_str("storage-compatibility"),
            Self::AbiCompatibility => f.write_str("abi-compatibility"),
            Self::ResourceBudget => f.write_str("resource-budget"),
        }
    }
}

/// Exact file and line/column location for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub snippet: Option<String>,
}

/// A structured diagnostic finding produced by any SORARK analysis engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: RuleCategory,
    pub message: String,
    pub help: String,
    pub span: Option<SourceSpan>,
    pub contract_item: Option<String>,
}

/// Static metadata describing a registered SORARK rule (used by `sorark rules` and SARIF `tool.driver.rules`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDescriptor {
    pub id: &'static str,
    pub title: &'static str,
    pub category: RuleCategory,
    pub default_severity: Severity,
    pub description: &'static str,
    pub remediation: &'static str,
}

/// Complete catalog of built-in SORARK rules across AST, WASM, and Upgrade Diff engines.
#[must_use]
pub fn builtin_rule_catalog() -> Vec<RuleDescriptor> {
    vec![
        RuleDescriptor {
            id: "ARK-STOR-001",
            title: "Unbounded Collection in Instance Storage",
            category: RuleCategory::StorageSafety,
            default_severity: Severity::Error,
            description: "Detects Map, Vec, Bytes, String, or structs transitively containing them stored inside env.storage().instance(), which shares a single 64 KiB ledger entry and can permanently brick the contract.",
            remediation: "Move dynamically growing collections to env.storage().persistent() with dedicated per-item DataKey variants.",
        },
        RuleDescriptor {
            id: "ARK-STOR-002",
            title: "Missing TTL Extension on Persistent/Instance Mutation",
            category: RuleCategory::StateArchival,
            default_severity: Severity::Warning,
            description: "Detects entrypoints that mutate persistent() or instance() storage without extending the entry's Time-To-Live (extend_ttl) directly or via a local helper function.",
            remediation: "Call env.storage().persistent().extend_ttl(&key, threshold, extend_to) or env.storage().instance().extend_ttl(threshold, extend_to) after state writes.",
        },
        RuleDescriptor {
            id: "ARK-STOR-003",
            title: "Critical State Stored in Ephemeral Temporary Storage",
            category: RuleCategory::StorageSafety,
            default_severity: Severity::Error,
            description: "Detects security-critical keys (Admin, Owner, Balance, Allowance, Nonce, Paused, Role) stored in env.storage().temporary(), where expiration permanently deletes the ledger entry without archival recovery.",
            remediation: "Store administrative, access-control, and financial state in env.storage().instance() or env.storage().persistent().",
        },
        RuleDescriptor {
            id: "ARK-STOR-004",
            title: "Invalid or Out-of-Bounds extend_ttl Parameters",
            category: RuleCategory::StateArchival,
            default_severity: Severity::Error,
            description: "Detects extend_ttl(threshold, extend_to) calls where threshold > extend_to (causes a host trap), extend_to == 0, or extend_to exceeds Stellar Mainnet max_entry_ttl (3,110,400 ledgers).",
            remediation: "Ensure 0 < threshold <= extend_to <= 3_110_400 ledgers (~180 days on Stellar Mainnet).",
        },
        RuleDescriptor {
            id: "ARK-UPG-001",
            title: "Unprotected Contract WASM Upgrade",
            category: RuleCategory::UpgradeAuth,
            default_severity: Severity::Error,
            description: "Detects calls to env.deployer().update_current_contract_wasm(...) without a dominating require_auth() check in the function or its helper call chain.",
            remediation: "Load the stored Admin address and invoke admin.require_auth() before calling update_current_contract_wasm.",
        },
        RuleDescriptor {
            id: "ARK-UPG-002",
            title: "Stateful Contract Missing Upgrade Mechanism",
            category: RuleCategory::UpgradeAuth,
            default_severity: Severity::Info,
            description: "Detects stateful Soroban contracts that initialize administrative state but expose no update_current_contract_wasm upgrade path.",
            remediation: "Add an admin-guarded upgrade(env: Env, new_wasm_hash: BytesN<32>) entrypoint or document immutability intentionally.",
        },
        RuleDescriptor {
            id: "ARK-WASM-001",
            title: "WASM Binary Ledger Size Budget & SEP-0048 Metadata Check",
            category: RuleCategory::ResourceBudget,
            default_severity: Severity::Warning,
            description: "Checks compiled .wasm contract size against Stellar ledger size thresholds (48 KiB warning / 64 KiB limit) and verifies presence of contractspecv0 and contractenvmetav0 sections.",
            remediation: "Enable release optimizations (opt-level = \"z\", lto = true, strip = \"symbols\") in Cargo.toml and compile with stellar contract build.",
        },
        RuleDescriptor {
            id: "ARK-DIFF-001",
            title: "Incompatible #[contracttype] Struct Storage Layout Mutation",
            category: RuleCategory::StorageCompatibility,
            default_severity: Severity::Error,
            description: "Detects removed fields, renamed ScMap field keys, changed field types, or reordered positional tuple struct fields between v1 and v2 that corrupt existing on-chain ledger entries.",
            remediation: "Keep existing #[contracttype] struct fields immutable across in-place upgrades, or introduce a versioned DataKey enum variant (e.g., StateV2) with an explicit migration routine.",
        },
        RuleDescriptor {
            id: "ARK-DIFF-002",
            title: "Incompatible #[contracttype] Enum or Tagged Union Mutation",
            category: RuleCategory::StorageCompatibility,
            default_severity: Severity::Error,
            description: "Detects removed enum/union variants, shifted u32 enum discriminants, or mutated union variant payload types between v1 and v2.",
            remediation: "Only append new variants at the end of enums/unions; never remove, rename, or alter existing variant payloads used as storage keys or values.",
        },
        RuleDescriptor {
            id: "ARK-DIFF-003",
            title: "Breaking Public Contract Entrypoint Signature Change",
            category: RuleCategory::AbiCompatibility,
            default_severity: Severity::Warning,
            description: "Detects removed public contract functions, changed parameter counts/types, or altered return types between v1 and v2.",
            remediation: "Preserve existing entrypoint signatures or introduce a new versioned entrypoint (e.g., deposit_v2) to avoid breaking cross-contract callers and indexers.",
        },
        RuleDescriptor {
            id: "ARK-DIFF-004",
            title: "Mutated #[contracterror] Error Code Mapping",
            category: RuleCategory::AbiCompatibility,
            default_severity: Severity::Warning,
            description: "Detects removed error enum variants or shifted integer error codes in #[contracterror] between v1 and v2.",
            remediation: "Keep existing #[contracterror] integer codes stable so cross-contract try_invoke_contract callers handle errors deterministically.",
        },
        RuleDescriptor {
            id: "ARK-DIFF-005",
            title: "Soroban Environment Protocol Version Mismatch",
            category: RuleCategory::AbiCompatibility,
            default_severity: Severity::Warning,
            description: "Detects protocol version regressions or major environment interface shifts in contractenvmetav0 between v1 and v2 WASM binaries.",
            remediation: "Verify that the target Stellar network supports the new Soroban environment protocol version before upgrading.",
        },
    ]
}
