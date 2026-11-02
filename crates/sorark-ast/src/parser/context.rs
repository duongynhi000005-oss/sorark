//! Pass-1 AST analysis context and intra-module call-graph queries.

use sorark_ir::{ContractModule, StorageTier, TypeRef};
use std::collections::{HashMap, HashSet};

/// Maximum call-graph recursion depth when resolving helper functions for TTL or auth checks.
const MAX_CALL_GRAPH_DEPTH: usize = 4;

/// Kind of operation performed on a Soroban storage tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOpKind {
    Set,
    Update,
    ExtendTtl,
    Get,
    Remove,
    Has,
}

impl StorageOpKind {
    /// Maps a Soroban storage method name (`set`, `update`, `extend_ttl`, ...) to an operation kind.
    #[must_use]
    pub fn from_method_name(method: &str) -> Option<Self> {
        match method {
            "set" => Some(Self::Set),
            "update" => Some(Self::Update),
            "extend_ttl" => Some(Self::ExtendTtl),
            "get" => Some(Self::Get),
            "remove" => Some(Self::Remove),
            "has" => Some(Self::Has),
            _ => None,
        }
    }

    /// Returns `true` if this operation mutates ledger state (`set` or `update`).
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        matches!(self, Self::Set | Self::Update)
    }
}

/// Recorded storage operation inside a contract function or helper.
#[derive(Debug, Clone)]
pub struct StorageOp {
    pub tier: StorageTier,
    pub kind: StorageOpKind,
    pub key_expr: Option<String>,
    pub value_expr: Option<String>,
    pub inferred_value_type: Option<TypeRef>,
    /// For `extend_ttl`, stores `(threshold, extend_to)` if resolvable to integer literals/constants.
    pub ttl_bounds: Option<(Option<u64>, Option<u64>)>,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
}

/// Recorded call to `update_current_contract_wasm`.
#[derive(Debug, Clone)]
pub struct WasmUpgradeCall {
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub auth_seen_before_call: bool,
}

/// Summary of a single parsed function (`#[contractimpl]` method or module helper function).
#[derive(Debug, Clone)]
pub struct ParsedFunction {
    pub name: String,
    pub is_contract_entrypoint: bool,
    pub is_pub: bool,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub storage_ops: Vec<StorageOp>,
    pub has_direct_require_auth: bool,
    pub wasm_upgrade_calls: Vec<WasmUpgradeCall>,
    pub called_functions: Vec<String>,
}

/// Complete Pass-1 AST analysis context across a Soroban crate/module.
#[derive(Debug, Clone)]
pub struct AstAnalysisContext {
    pub module: ContractModule,
    pub functions: Vec<ParsedFunction>,
    pub constants: HashMap<String, u64>,
    /// Map of `(file, line_number)` -> set of suppressed rule IDs (`// sorark-ignore: ARK-...`).
    pub inline_suppressions: HashMap<(String, usize), HashSet<String>>,
}

impl AstAnalysisContext {
    /// Checks whether `rule_id` is suppressed via `// sorark-ignore:` on `line` or `line - 1`.
    #[must_use]
    pub fn is_suppressed(&self, file: &str, line: usize, rule_id: &str) -> bool {
        let upper = rule_id.to_ascii_uppercase();
        for check_line in [line, line.saturating_sub(1)] {
            if let Some(set) = self
                .inline_suppressions
                .get(&(file.to_string(), check_line))
                && (set.contains(&upper) || set.contains("ALL"))
            {
                return true;
            }
        }
        false
    }

    /// Returns `true` if `func` or any helper function it calls (up to 4 hops) calls `extend_ttl`
    /// on the specified `tier`.
    #[must_use]
    pub fn function_extends_ttl(&self, func: &ParsedFunction, tier: StorageTier) -> bool {
        let mut visited = HashSet::new();
        self.check_extends_ttl_recursive(func, tier, 0, &mut visited)
    }

    /// Recursively walks the intra-module call graph to check if `extend_ttl` is invoked on `tier`.
    fn check_extends_ttl_recursive(
        &self,
        func: &ParsedFunction,
        tier: StorageTier,
        depth: usize,
        visited: &mut HashSet<String>,
    ) -> bool {
        if depth > MAX_CALL_GRAPH_DEPTH || !visited.insert(func.name.clone()) {
            return false;
        }
        if func
            .storage_ops
            .iter()
            .any(|op| op.kind == StorageOpKind::ExtendTtl && op.tier == tier)
        {
            return true;
        }
        func.called_functions.iter().any(|callee| {
            self.find_function(callee).is_some_and(|target| {
                self.check_extends_ttl_recursive(target, tier, depth + 1, visited)
            })
        })
    }

    /// Returns `true` if `func` or any helper function it invokes calls `.require_auth()`
    /// or `.require_auth_for_args(...)`.
    #[must_use]
    pub fn function_requires_auth(&self, func: &ParsedFunction) -> bool {
        let mut visited = HashSet::new();
        self.check_requires_auth_recursive(func, 0, &mut visited)
    }

    /// Recursively walks the intra-module call graph to check if `require_auth` is invoked.
    fn check_requires_auth_recursive(
        &self,
        func: &ParsedFunction,
        depth: usize,
        visited: &mut HashSet<String>,
    ) -> bool {
        if depth > MAX_CALL_GRAPH_DEPTH || !visited.insert(func.name.clone()) {
            return false;
        }
        if func.has_direct_require_auth {
            return true;
        }
        func.called_functions.iter().any(|callee| {
            self.find_function(callee).is_some_and(|target| {
                self.check_requires_auth_recursive(target, depth + 1, visited)
            })
        })
    }

    /// Finds a parsed function by name in the current analysis context.
    #[must_use]
    pub fn find_function(&self, name: &str) -> Option<&ParsedFunction> {
        self.functions.iter().find(|f| f.name == name)
    }
}
