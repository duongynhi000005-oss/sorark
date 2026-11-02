//! Pass-1 Rust AST parser for Soroban smart contracts.
//!
//! Splits parsing responsibilities across:
//! - [`context`]: [`AstAnalysisContext`], [`ParsedFunction`], and two-pass call-graph queries.
//! - [`suppression`]: inline `// sorark-ignore:` directive parsing.
//! - [`const_eval`]: compile-time integer constant propagation for TTL bounds.
//! - [`types`]: conversion from `syn::Type` to [`sorark_ir::TypeRef`].
//! - [`items`]: extraction of `#[contracttype]`, `#[contracterror]`, and `#[contractimpl]` items.
//! - [`body`]: intra-function statement and expression visitor.

mod body;
mod const_eval;
mod context;
mod items;
mod suppression;
mod types;

pub use context::{AstAnalysisContext, ParsedFunction, StorageOp, StorageOpKind, WasmUpgradeCall};
pub use suppression::parse_inline_suppressions;
pub use types::syn_type_to_typeref;

use const_eval::eval_u64_expr;
use items::{
    analyze_free_fn, has_soroban_attr, parse_contracterror_enum, parse_contracttype_enum,
    parse_contracttype_struct, parse_impl_block,
};
use sorark_ir::{ContractModule, SourceOrigin};
use std::collections::HashMap;
use syn::{File, Item};

/// Parses a single Rust source file into an existing [`AstAnalysisContext`].
pub fn parse_rust_source_into_context(
    file_label: &str,
    source: &str,
    ctx: &mut AstAnalysisContext,
) -> Result<(), syn::Error> {
    parse_inline_suppressions(file_label, source, &mut ctx.inline_suppressions);
    let syntax: File = syn::parse_file(source)?;
    let source_lines: Vec<&str> = source.lines().collect();

    collect_module_constants(&syntax.items, &mut ctx.constants);
    collect_module_items(file_label, &source_lines, &syntax.items, ctx);

    Ok(())
}

/// Convenience helper to parse a single source string into a standalone [`AstAnalysisContext`].
pub fn parse_single_source(
    module_name: &str,
    file_label: &str,
    source: &str,
) -> Result<AstAnalysisContext, syn::Error> {
    let mut ctx = AstAnalysisContext {
        module: ContractModule::new(
            module_name,
            SourceOrigin::RustSource {
                path: file_label.to_string(),
            },
        ),
        functions: Vec::new(),
        constants: HashMap::new(),
        inline_suppressions: HashMap::new(),
    };
    parse_rust_source_into_context(file_label, source, &mut ctx)?;
    Ok(ctx)
}

/// First pass over top-level `const` items so `extend_ttl` arguments can resolve named constants.
fn collect_module_constants(items: &[Item], constants: &mut HashMap<String, u64>) {
    for item in items {
        if let Item::Const(c) = item
            && let Some(val) = eval_u64_expr(&c.expr, constants)
        {
            constants.insert(c.ident.to_string(), val);
        }
    }
}

/// Second pass over top-level structs, enums, impl blocks, and free helper functions.
fn collect_module_items(
    file_label: &str,
    source_lines: &[&str],
    items: &[Item],
    ctx: &mut AstAnalysisContext,
) {
    for item in items {
        match item {
            Item::Struct(s) if has_soroban_attr(&s.attrs, "contracttype") => {
                parse_contracttype_struct(file_label, s, &mut ctx.module);
            }
            Item::Enum(e) => {
                if has_soroban_attr(&e.attrs, "contracttype") {
                    parse_contracttype_enum(file_label, e, &mut ctx.module);
                } else if has_soroban_attr(&e.attrs, "contracterror") {
                    parse_contracterror_enum(file_label, e, &mut ctx.module);
                }
            }
            Item::Impl(imp) => {
                let is_contractimpl = has_soroban_attr(&imp.attrs, "contractimpl");
                parse_impl_block(
                    file_label,
                    source_lines,
                    imp,
                    is_contractimpl,
                    &ctx.constants,
                    &mut ctx.module,
                    &mut ctx.functions,
                );
            }
            Item::Fn(func) => {
                let parsed = analyze_free_fn(file_label, source_lines, func, &ctx.constants);
                ctx.functions.push(parsed);
            }
            _ => {}
        }
    }
}
