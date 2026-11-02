//! Core [`DiffRule`] trait and default rule registry for `sorark-diff`.

use crate::rules::{
    EnumAndUnionLayoutDiffRule, ErrorEnumDiffRule, FunctionAbiDiffRule, ProtocolVersionDiffRule,
    StructLayoutDiffRule,
};
use sorark_ir::{ContractModule, Diagnostic, RuleCategory, Severity, SorarkConfig};

/// Extensible trait for comparing two [`ContractModule`] versions (`old` vs `new`).
pub trait DiffRule: Send + Sync {
    /// Unique rule identifier (e.g. `"ARK-DIFF-001"`).
    fn id(&self) -> &'static str;

    /// Short human-readable title summarizing the compatibility check.
    fn title(&self) -> &'static str;

    /// Classification category for this rule.
    fn category(&self) -> RuleCategory;

    /// Default severity level emitted by this rule.
    fn default_severity(&self) -> Severity;

    /// Compares `old` (`v1`) and `new` (`v2`) [`ContractModule`] specifications and returns
    /// any upgrade-compatibility diagnostics.
    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        config: &SorarkConfig,
    ) -> Vec<Diagnostic>;
}

/// Returns the default suite of Soroban upgrade compatibility rules (`ARK-DIFF-001`..`ARK-DIFF-005`).
#[must_use]
pub fn default_diff_rules() -> Vec<Box<dyn DiffRule>> {
    vec![
        Box::new(StructLayoutDiffRule),
        Box::new(EnumAndUnionLayoutDiffRule),
        Box::new(FunctionAbiDiffRule),
        Box::new(ErrorEnumDiffRule),
        Box::new(ProtocolVersionDiffRule),
    ]
}
