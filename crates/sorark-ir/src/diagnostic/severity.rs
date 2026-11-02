//! Severity, confidence, and category taxonomies for SORARK findings.

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
    /// Returns the lowercase canonical label (`info`, `warning`, `error`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Maps SORARK severity to the SARIF v2.1.0 `level` string (`note`, `warning`, `error`).
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

impl Confidence {
    /// Returns the lowercase canonical label (`low`, `medium`, `high`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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

impl RuleCategory {
    /// Returns the kebab-case identifier for this rule category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StorageSafety => "storage-safety",
            Self::StateArchival => "state-archival",
            Self::UpgradeAuth => "upgrade-auth",
            Self::StorageCompatibility => "storage-compatibility",
            Self::AbiCompatibility => "abi-compatibility",
            Self::ResourceBudget => "resource-budget",
        }
    }
}

impl fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
