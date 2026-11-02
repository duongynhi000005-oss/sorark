//! Parser for inline `// sorark-ignore: ARK-STOR-001` suppression directives.

use std::collections::{HashMap, HashSet};

/// Directive prefix recognized in line comments.
const IGNORE_DIRECTIVE: &str = "sorark-ignore:";

/// Parses inline `// sorark-ignore: ARK-STOR-001, ARK-STOR-002` comments from raw source text.
///
/// Suppressed rule IDs are normalized to uppercase and indexed by `(file_label, 1_based_line)`.
pub fn parse_inline_suppressions(
    file_label: &str,
    source: &str,
    out: &mut HashMap<(String, usize), HashSet<String>>,
) {
    for (idx, line_str) in source.lines().enumerate() {
        let line_num = idx + 1;
        let ids = extract_rule_ids_from_line(line_str);
        if !ids.is_empty() {
            out.entry((file_label.to_string(), line_num))
                .or_default()
                .extend(ids);
        }
    }
}

/// Extracts uppercase rule IDs following `sorark-ignore:` on a single source line.
fn extract_rule_ids_from_line(line_str: &str) -> HashSet<String> {
    let Some(pos) = line_str.find(IGNORE_DIRECTIVE) else {
        return HashSet::new();
    };
    let after = &line_str[pos + IGNORE_DIRECTIVE.len()..];
    // Strip trailing explanatory comment (`-- reason` or `// reason`).
    let rules_part = after
        .split("//")
        .next()
        .unwrap_or(after)
        .split("--")
        .next()
        .unwrap_or(after);

    rules_part
        .split([',', ' ', '\t'])
        .map(str::trim)
        .filter(|tok| !tok.is_empty())
        .map(str::to_ascii_uppercase)
        .collect()
}
