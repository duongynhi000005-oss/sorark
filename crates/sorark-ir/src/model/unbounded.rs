//! Transitive "is this type unbounded?" analysis over a [`ContractModule`].
//!
//! A `#[contracttype]` struct is unbounded if any of its fields is, which can be several
//! user-defined types deep. This walker follows those references with cycle protection
//! and records the path it took so diagnostics can explain *why* a value is unbounded.

use super::{ContractModule, TypeRef};
use std::collections::HashSet;

/// Depth-first walker that searches for an unbounded type reachable from a root type.
pub(super) struct UnboundedAnalyzer<'m> {
    module: &'m ContractModule,
    /// User-defined type names already expanded, to terminate on recursive types.
    visited: HashSet<String>,
}

impl<'m> UnboundedAnalyzer<'m> {
    /// Creates a walker scoped to the user-defined types of `module`.
    pub(super) fn new(module: &'m ContractModule) -> Self {
        Self {
            module,
            visited: HashSet::new(),
        }
    }

    /// Returns a human-readable path to the first unbounded type reachable from `ty`.
    pub(super) fn explain(&mut self, ty: &TypeRef) -> Option<String> {
        if ty.is_directly_unbounded() {
            return Some(format!("`{ty}` is dynamically sized"));
        }

        let mut custom_names = Vec::new();
        ty.referenced_custom_types(&mut custom_names);
        custom_names
            .into_iter()
            .find_map(|name| self.explain_custom(name))
    }

    /// Expands one user-defined type name (struct, tuple struct, or union) once.
    fn explain_custom(&mut self, name: &str) -> Option<String> {
        if !self.visited.insert(name.to_string()) {
            return None;
        }
        self.explain_struct(name)
            .or_else(|| self.explain_tuple_struct(name))
            .or_else(|| self.explain_union(name))
    }

    /// Checks each named field of struct `name`.
    fn explain_struct(&mut self, name: &str) -> Option<String> {
        let spec = self.module.find_struct(name)?;
        spec.fields.iter().find_map(|field| {
            self.explain(&field.ty)
                .map(|inner| format!("`{}` -> field `{}` ({inner})", spec.name, field.name))
        })
    }

    /// Checks each positional element of tuple struct `name`.
    fn explain_tuple_struct(&mut self, name: &str) -> Option<String> {
        let spec = self.module.find_tuple_struct(name)?;
        spec.fields.iter().enumerate().find_map(|(idx, field_ty)| {
            self.explain(field_ty)
                .map(|inner| format!("`{}` -> tuple element .{idx} ({inner})", spec.name))
        })
    }

    /// Checks each payload type of every case of union `name`.
    fn explain_union(&mut self, name: &str) -> Option<String> {
        let spec = self.module.find_union(name)?;
        spec.cases.iter().find_map(|case| {
            case.payload.iter().find_map(|payload_ty| {
                self.explain(payload_ty)
                    .map(|inner| format!("`{}::{}` payload ({inner})", spec.name, case.name))
            })
        })
    }
}
