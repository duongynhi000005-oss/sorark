//! Fluent builder and data structure for SORARK [`Diagnostic`] findings.

use super::{Confidence, RuleCategory, Severity, SourceSpan};
use serde::{Deserialize, Serialize};

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

impl Diagnostic {
    /// Starts building a new [`Diagnostic`] with `High` default confidence.
    #[must_use]
    pub fn builder(
        rule_id: impl Into<String>,
        title: impl Into<String>,
        category: RuleCategory,
        severity: Severity,
    ) -> DiagnosticBuilder {
        DiagnosticBuilder {
            rule_id: rule_id.into(),
            title: title.into(),
            severity,
            confidence: Confidence::High,
            category,
            message: String::new(),
            help: String::new(),
            span: None,
            contract_item: None,
        }
    }
}

/// Ergonomic builder for constructing [`Diagnostic`] instances without repetitive struct literals.
#[derive(Debug, Clone)]
pub struct DiagnosticBuilder {
    rule_id: String,
    title: String,
    severity: Severity,
    confidence: Confidence,
    category: RuleCategory,
    message: String,
    help: String,
    span: Option<SourceSpan>,
    contract_item: Option<String>,
}

impl DiagnosticBuilder {
    /// Overrides the confidence level for this finding (defaults to [`Confidence::High`]).
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Sets the detailed explanation of what went wrong.
    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Sets the actionable remediation guidance for the developer.
    #[must_use]
    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = help.into();
        self
    }

    /// Attaches a [`SourceSpan`] to the diagnostic.
    #[must_use]
    pub fn span(mut self, span: SourceSpan) -> Self {
        self.span = Some(span);
        self
    }

    /// Attaches an optional [`SourceSpan`] to the diagnostic.
    #[must_use]
    pub fn maybe_span(mut self, span: Option<SourceSpan>) -> Self {
        self.span = span;
        self
    }

    /// Records the contract function, struct, or enum item associated with the finding.
    #[must_use]
    pub fn contract_item(mut self, item: impl Into<String>) -> Self {
        self.contract_item = Some(item.into());
        self
    }

    /// Finalizes and returns the constructed [`Diagnostic`].
    #[must_use]
    pub fn build(self) -> Diagnostic {
        Diagnostic {
            rule_id: self.rule_id,
            title: self.title,
            severity: self.severity,
            confidence: self.confidence,
            category: self.category,
            message: self.message,
            help: self.help,
            span: self.span,
            contract_item: self.contract_item,
        }
    }
}
