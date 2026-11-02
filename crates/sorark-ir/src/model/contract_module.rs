//! The [`ContractModule`] aggregate: one normalized view of a Soroban contract.

use super::{
    EnumSpec, ErrorEnumSpec, FunctionSpec, SourceOrigin, StructSpec, TupleStructSpec, TypeRef,
    UnionSpec, unbounded::UnboundedAnalyzer,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unified, source-agnostic Soroban contract specification model.
///
/// Populated either from Rust source (`sorark-ast`) or from compiled `.wasm` XDR
/// (`sorark-wasm`), so the diff engine can compare any combination of the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractModule {
    pub name: String,
    pub origin: SourceOrigin,
    pub structs: Vec<StructSpec>,
    pub tuple_structs: Vec<TupleStructSpec>,
    pub enums: Vec<EnumSpec>,
    pub unions: Vec<UnionSpec>,
    pub error_enums: Vec<ErrorEnumSpec>,
    pub functions: Vec<FunctionSpec>,
}

impl ContractModule {
    /// Creates an empty module with the given name and origin.
    #[must_use]
    pub fn new(name: impl Into<String>, origin: SourceOrigin) -> Self {
        Self {
            name: name.into(),
            origin,
            structs: Vec::new(),
            tuple_structs: Vec::new(),
            enums: Vec::new(),
            unions: Vec::new(),
            error_enums: Vec::new(),
            functions: Vec::new(),
        }
    }

    /// Finds a named-field struct by name.
    #[must_use]
    pub fn find_struct(&self, name: &str) -> Option<&StructSpec> {
        self.structs.iter().find(|s| s.name == name)
    }

    /// Finds a tuple struct by name.
    #[must_use]
    pub fn find_tuple_struct(&self, name: &str) -> Option<&TupleStructSpec> {
        self.tuple_structs.iter().find(|s| s.name == name)
    }

    /// Finds a C-style integer enum by name.
    #[must_use]
    pub fn find_enum(&self, name: &str) -> Option<&EnumSpec> {
        self.enums.iter().find(|e| e.name == name)
    }

    /// Finds a tagged union (data enum) by name.
    #[must_use]
    pub fn find_union(&self, name: &str) -> Option<&UnionSpec> {
        self.unions.iter().find(|u| u.name == name)
    }

    /// Finds a `#[contracterror]` enum by name.
    #[must_use]
    pub fn find_error_enum(&self, name: &str) -> Option<&ErrorEnumSpec> {
        self.error_enums.iter().find(|e| e.name == name)
    }

    /// Finds an exported entrypoint by name.
    #[must_use]
    pub fn find_function(&self, name: &str) -> Option<&FunctionSpec> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Returns `true` if `ty` is unbounded directly or through any `#[contracttype]`
    /// struct, tuple struct, or union defined in this module.
    #[must_use]
    pub fn is_type_transitively_unbounded(&self, ty: &TypeRef) -> bool {
        self.unbounded_reason_chain(ty).is_some()
    }

    /// Explains why `ty` is unbounded as a chain of fields,
    /// e.g. ``"`VaultConfig` -> field `users` (`Map<Address, i128>` is dynamically sized)"``.
    ///
    /// Returns `None` when the type is bounded.
    #[must_use]
    pub fn unbounded_reason_chain(&self, ty: &TypeRef) -> Option<String> {
        UnboundedAnalyzer::new(self).explain(ty)
    }

    /// Builds a lookup map of struct names to their definitions.
    #[must_use]
    pub fn struct_map(&self) -> HashMap<&str, &StructSpec> {
        self.structs.iter().map(|s| (s.name.as_str(), s)).collect()
    }
}
