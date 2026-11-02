//! Filesystem scanner and rule runner for Soroban Rust source code.
//!
//! Recursively discovers `.rs` files (respecting exclusion patterns), parses each file
//! into a shared [`AstAnalysisContext`], and executes enabled [`AstRule`](crate::AstRule)s.

use crate::error::AstEngineError;
use crate::parser::{AstAnalysisContext, parse_rust_source_into_context};
use crate::rules::default_ast_rules;
use sorark_ir::{ContractModule, Diagnostic, SorarkConfig, SourceOrigin};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Result of analyzing a Soroban Rust source file or directory.
#[derive(Debug, Clone)]
pub struct AstScanReport {
    /// Unified analysis context built across all scanned `.rs` files.
    pub context: AstAnalysisContext,
    /// Diagnostics emitted by all enabled [`AstRule`](crate::AstRule)s.
    pub diagnostics: Vec<Diagnostic>,
    /// Total number of `.rs` files parsed.
    pub files_scanned: usize,
}

/// Scans a single `.rs` file or recursively scans a directory of `.rs` files, building a unified
/// [`AstAnalysisContext`] and running all enabled [`AstRule`](crate::AstRule)s.
///
/// # Errors
///
/// Returns [`AstEngineError`] if the path does not exist, contains no `.rs` files, or
/// fails to parse due to a Rust syntax error.
pub fn scan_rust_path(
    target_path: impl AsRef<Path>,
    config: &SorarkConfig,
) -> Result<AstScanReport, AstEngineError> {
    let root = target_path.as_ref();
    ensure_path_exists(root)?;

    let rs_files = collect_rust_files(root, &config.exclude_paths)?;
    let ctx = parse_files_into_context(root, &rs_files)?;
    let diagnostics = run_rules_on_context(&ctx, config);

    Ok(AstScanReport {
        context: ctx,
        diagnostics,
        files_scanned: rs_files.len(),
    })
}

/// Runs all enabled default [`AstRule`](crate::AstRule)s against an already-constructed
/// [`AstAnalysisContext`].
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

/// Verifies that the target path exists on disk before walking it.
fn ensure_path_exists(root: &Path) -> Result<(), AstEngineError> {
    if !root.exists() {
        return Err(AstEngineError::Io {
            path: root.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "path does not exist"),
        });
    }
    Ok(())
}

/// Collects and deterministically sorts all `.rs` source files under `root`.
fn collect_rust_files(
    root: &Path,
    exclude_patterns: &[String],
) -> Result<Vec<PathBuf>, AstEngineError> {
    let mut rs_files = Vec::new();

    if root.is_file() {
        rs_files.push(root.to_path_buf());
    } else {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !is_excluded_entry(e.path(), exclude_patterns))
        {
            let entry = entry.map_err(|err| AstEngineError::Io {
                path: root.display().to_string(),
                source: err.into(),
            })?;
            if is_rust_source_file(&entry) {
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

    Ok(rs_files)
}

/// Parses every `.rs` file in `rs_files` into a single [`AstAnalysisContext`].
fn parse_files_into_context(
    root: &Path,
    rs_files: &[PathBuf],
) -> Result<AstAnalysisContext, AstEngineError> {
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

    for file_path in rs_files {
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

    Ok(ctx)
}

/// Returns `true` if a directory walk entry is a `.rs` file.
fn is_rust_source_file(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_file() && entry.path().extension().and_then(|s| s.to_str()) == Some("rs")
}

/// Returns `true` if `path` matches any configured directory/file name exclusion pattern.
fn is_excluded_entry(path: &Path, exclude_patterns: &[String]) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    exclude_patterns.iter().any(|pat| name == pat)
}
