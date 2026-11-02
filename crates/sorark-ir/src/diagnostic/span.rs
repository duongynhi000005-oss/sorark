//! Source file location spans for SORARK diagnostics.

use serde::{Deserialize, Serialize};

/// Exact file, line, column, and code snippet location for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub snippet: Option<String>,
}

impl SourceSpan {
    /// Creates a new [`SourceSpan`] at the given file, 1-indexed line, and 1-indexed column.
    #[must_use]
    pub fn new(file: impl Into<String>, line: usize, column: usize) -> Self {
        Self {
            file: file.into(),
            line: line.max(1),
            column: column.max(1),
            end_line: None,
            snippet: None,
        }
    }

    /// Attaches a trimmed source line snippet to this span.
    #[must_use]
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        let s = snippet.into();
        if !s.is_empty() {
            self.snippet = Some(s);
        }
        self
    }

    /// Creates an optional span when a file path is available.
    #[must_use]
    pub fn from_optional_file(file: Option<&str>, line: Option<usize>) -> Option<Self> {
        file.map(|f| Self::new(f, line.unwrap_or(1), 1))
    }
}
