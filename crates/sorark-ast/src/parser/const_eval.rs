//! Constant integer expression evaluation and compact AST node formatting helpers.

use std::collections::HashMap;
use syn::{BinOp, Expr, Lit, Pat};

/// Evaluates a constant integer expression (such as `DAY_IN_LEDGERS * 30`) using known
/// module constants.
///
/// Returns `None` if the expression depends on runtime variables or unsupported operators.
#[must_use]
pub fn eval_u64_expr(expr: &Expr, constants: &HashMap<String, u64>) -> Option<u64> {
    match expr {
        Expr::Lit(lit) => eval_int_literal(&lit.lit),
        Expr::Path(p) => {
            let ident = p.path.segments.last()?.ident.to_string();
            constants.get(&ident).copied()
        }
        Expr::Paren(p) => eval_u64_expr(&p.expr, constants),
        Expr::Binary(bin) => {
            let lhs = eval_u64_expr(&bin.left, constants)?;
            let rhs = eval_u64_expr(&bin.right, constants)?;
            eval_binary_op(&bin.op, lhs, rhs)
        }
        _ => None,
    }
}

/// Parses a `syn::Lit` integer literal as `u64`.
fn eval_int_literal(lit: &Lit) -> Option<u64> {
    if let Lit::Int(int_lit) = lit {
        int_lit.base10_parse::<u64>().ok()
    } else {
        None
    }
}

/// Evaluates checked arithmetic (`+`, `-`, `*`, `/`) on two `u64` operands.
fn eval_binary_op(op: &BinOp, lhs: u64, rhs: u64) -> Option<u64> {
    match op {
        BinOp::Add(_) => lhs.checked_add(rhs),
        BinOp::Sub(_) => lhs.checked_sub(rhs),
        BinOp::Mul(_) => lhs.checked_mul(rhs),
        BinOp::Div(_) => lhs.checked_div(rhs),
        _ => None,
    }
}

/// Extracts the variable identifier name from a `syn::Pat` (handling `ident` and `&ident`).
#[must_use]
pub fn pat_to_ident_string(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Reference(pr) => pat_to_ident_string(&pr.pat),
        _ => None,
    }
}

/// Renders an AST expression (`&DataKey::Admin`, `DataKey::Balance(user)`) into a concise
/// human-readable string for diagnostic messages and key-pattern matching.
#[must_use]
pub fn expr_to_compact_string(expr: &Expr) -> String {
    match expr {
        Expr::Reference(r) => expr_to_compact_string(&r.expr),
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::Call(c) => {
            let func = expr_to_compact_string(&c.func);
            let args: Vec<String> = c.args.iter().map(expr_to_compact_string).collect();
            format!("{func}({})", args.join(", "))
        }
        Expr::Lit(lit) => match &lit.lit {
            Lit::Str(s) => s.value(),
            Lit::Int(i) => i.base10_digits().to_string(),
            _ => "literal".to_string(),
        },
        _ => "expr".to_string(),
    }
}
