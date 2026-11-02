//! Pass-2 Soroban AST static analysis rules.
//!
//! Each rule lives in its own module and implements [`AstRule`]:
//! - [`UnboundedInstanceStorageRule`] (`ARK-STOR-001`)
//! - [`MissingExtendTtlRule`] (`ARK-STOR-002`)
//! - [`CriticalStateInTempStorageRule`] (`ARK-STOR-003`)
//! - [`InvalidTtlBoundsRule`] (`ARK-STOR-004`)
//! - [`UnprotectedWasmUpgradeRule`] (`ARK-UPG-001`)
//! - [`MissingUpgradeMechanismRule`] (`ARK-UPG-002`)

mod invalid_ttl_bounds;
mod missing_ttl;
mod missing_upgrade;
mod temp_critical_state;
mod unbounded_instance;
mod unprotected_upgrade;

pub use invalid_ttl_bounds::InvalidTtlBoundsRule;
pub use missing_ttl::MissingExtendTtlRule;
pub use missing_upgrade::MissingUpgradeMechanismRule;
pub use temp_critical_state::CriticalStateInTempStorageRule;
pub use unbounded_instance::UnboundedInstanceStorageRule;
pub use unprotected_upgrade::UnprotectedWasmUpgradeRule;

use crate::parser::AstAnalysisContext;
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig};

/// Extensible trait for Pass-2 Soroban AST static analysis rules.
///
/// Contributors adding a new AST rule implement this trait in a dedicated file under
/// `crates/sorark-ast/src/rules/` and register it in [`default_ast_rules`].
pub trait AstRule: Send + Sync {
    /// Unique rule identifier, e.g. `"ARK-STOR-001"`.
    fn id(&self) -> &'static str;
    /// Short human-readable title.
    fn title(&self) -> &'static str;
    /// High-level rule taxonomy.
    fn category(&self) -> RuleCategory;
    /// Default severity level when not overridden in `sorark.toml`.
    fn default_severity(&self) -> Severity;
    /// Evaluates this rule against the Pass-1 [`AstAnalysisContext`].
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
