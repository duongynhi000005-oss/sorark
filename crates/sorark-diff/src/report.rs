//! Diff report data structure and execution entrypoint (`compare_contract_modules`).

use crate::rule::default_diff_rules;
use serde::{Deserialize, Serialize};
use sorark_ir::{ContractModule, Diagnostic, Severity, SorarkConfig};

/// Summary report comparing an `old` (`v1`) and `new` (`v2`) contract module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// Name of the baseline (`v1`) contract module.
    pub old_name: String,
    /// Name of the candidate (`v2`) contract module.
    pub new_name: String,
    /// `true` if no blocking storage-layout or ABI compatibility errors were found.
    pub is_upgrade_safe: bool,
    /// All diagnostics emitted by enabled [`DiffRule`](crate::DiffRule)s.
    pub diagnostics: Vec<Diagnostic>,
}

/// Compares `old` and `new` [`ContractModule`] specifications using all enabled [`DiffRule`](crate::DiffRule)s.
#[must_use]
pub fn compare_contract_modules(
    old: &ContractModule,
    new: &ContractModule,
    config: &SorarkConfig,
) -> DiffReport {
    let rules = default_diff_rules();
    let mut diagnostics = Vec::new();
    for rule in &rules {
        if config.is_rule_enabled(rule.id()) {
            diagnostics.extend(rule.check_diff(old, new, config));
        }
    }

    let is_upgrade_safe = !diagnostics.iter().any(|d| {
        d.severity == Severity::Error
            || (config.fail_on_warnings && d.severity == Severity::Warning)
    });

    DiffReport {
        old_name: old.name.clone(),
        new_name: new.name.clone(),
        is_upgrade_safe,
        diagnostics,
    }
}
