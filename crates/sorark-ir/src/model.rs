use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Origin metadata for a normalized Soroban [`ContractModule`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceOrigin {
    /// Parsed from one or more Rust source files (`.rs`).
    RustSource { path: String },
    /// Decoded from a compiled WebAssembly binary (`.wasm`) SEP-0048 custom sections.
    WasmBinary {
        path: String,
        byte_size: usize,
        protocol_version: Option<u32>,
        pre_release_version: Option<u32>,
        rs_soroban_env_version: Option<String>,
        rustc_version: Option<String>,
    },
}

/// Normalized representation of a Soroban contract type (`ScSpecTypeDef` / Rust AST type).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TypeRef {
    Void,
    Bool,
    U32,
    I32,
    U64,
    I64,
    Timepoint,
    Duration,
    U128,
    I128,
    U256,
    I256,
    Bytes,
    BytesN(u32),
    String,
    Symbol,
    Address,
    Val,
    Error,
    Option(Box<TypeRef>),
    Result {
        ok: Box<TypeRef>,
        err: Box<TypeRef>,
    },
    Vec(Box<TypeRef>),
    Map {
        key: Box<TypeRef>,
        value: Box<TypeRef>,
    },
    Tuple(Vec<TypeRef>),
    /// User-defined `#[contracttype]` or `#[contracterror]` identifier.
    Custom(String),
}

impl TypeRef {
    /// Returns `true` if this type is directly dynamically sized / unbounded on the ledger
    /// (`Vec<T>`, `Map<K, V>`, `Bytes`, `String`), or wraps an unbounded type inside
    /// `Option`, `Result`, or `Tuple`.
    #[must_use]
    pub fn is_directly_unbounded(&self) -> bool {
        match self {
            Self::Vec(_) | Self::Map { .. } | Self::Bytes | Self::String => true,
            Self::Option(inner) => inner.is_directly_unbounded(),
            Self::Result { ok, err } => ok.is_directly_unbounded() || err.is_directly_unbounded(),
            Self::Tuple(items) => items.iter().any(Self::is_directly_unbounded),
            _ => false,
        }
    }

    /// Collects all custom user-defined type identifiers referenced within this type.
    pub fn referenced_custom_types<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Self::Custom(name) => out.push(name.as_str()),
            Self::Option(inner) | Self::Vec(inner) => inner.referenced_custom_types(out),
            Self::Result { ok, err } => {
                ok.referenced_custom_types(out);
                err.referenced_custom_types(out);
            }
            Self::Map { key, value } => {
                key.referenced_custom_types(out);
                value.referenced_custom_types(out);
            }
            Self::Tuple(items) => {
                for item in items {
                    item.referenced_custom_types(out);
                }
            }
            _ => {}
        }
    }

    /// Canonical, human-readable Soroban type signature used for cross-engine (AST vs WASM) diffing.
    #[must_use]
    pub fn canonical_signature(&self) -> String {
        match self {
            Self::Void => "()".to_string(),
            Self::Bool => "bool".to_string(),
            Self::U32 => "u32".to_string(),
            Self::I32 => "i32".to_string(),
            Self::U64 => "u64".to_string(),
            Self::I64 => "i64".to_string(),
            Self::Timepoint => "Timepoint".to_string(),
            Self::Duration => "Duration".to_string(),
            Self::U128 => "u128".to_string(),
            Self::I128 => "i128".to_string(),
            Self::U256 => "U256".to_string(),
            Self::I256 => "I256".to_string(),
            Self::Bytes => "Bytes".to_string(),
            Self::BytesN(n) => format!("BytesN<{n}>"),
            Self::String => "String".to_string(),
            Self::Symbol => "Symbol".to_string(),
            Self::Address => "Address".to_string(),
            Self::Val => "Val".to_string(),
            Self::Error => "Error".to_string(),
            Self::Option(inner) => format!("Option<{}>", inner.canonical_signature()),
            Self::Result { ok, err } => {
                format!(
                    "Result<{}, {}>",
                    ok.canonical_signature(),
                    err.canonical_signature()
                )
            }
            Self::Vec(inner) => format!("Vec<{}>", inner.canonical_signature()),
            Self::Map { key, value } => format!(
                "Map<{}, {}>",
                key.canonical_signature(),
                value.canonical_signature()
            ),
            Self::Tuple(items) => {
                let joined: Vec<String> = items.iter().map(Self::canonical_signature).collect();
                format!("({})", joined.join(", "))
            }
            Self::Custom(name) => name.clone(),
        }
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical_signature())
    }
}

/// A named field inside a `#[contracttype]` struct (`ScSpecUdtStructFieldV0`).
/// On-chain, named structs serialize as an `ScMap` keyed by `ScSymbol(name)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructFieldSpec {
    pub name: String,
    pub ty: TypeRef,
    pub line: Option<usize>,
}

/// A `#[contracttype]` struct with named fields (`ScSpecUdtStructV0` serialized as `ScMap`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructSpec {
    pub name: String,
    pub fields: Vec<StructFieldSpec>,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// A `#[contracttype]` tuple struct (`struct Pair(u64, Address)`), serialized on-chain as
/// a positional `ScVec` where element order determines deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleStructSpec {
    pub name: String,
    pub fields: Vec<TypeRef>,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// A single case inside a C-style unit `#[contracttype]` enum (`ScSpecUdtEnumCaseV0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumVariantSpec {
    pub name: String,
    pub discriminant: u32,
    pub line: Option<usize>,
}

/// A C-style integer `#[contracttype]` enum (`ScSpecUdtEnumV0`), serialized on-chain as `ScVal::U32`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumSpec {
    pub name: String,
    pub variants: Vec<EnumVariantSpec>,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// A single case in a Soroban tagged union / data enum (`ScSpecUdtUnionCaseV0`).
/// On-chain, serialized as `ScVec([ScSymbol(name), ...payload])`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnionCaseSpec {
    pub name: String,
    /// Empty for void variants (`DataKey::Admin`), non-empty for tuple variants (`DataKey::Balance(Address)`).
    pub payload: Vec<TypeRef>,
    pub line: Option<usize>,
}

/// A `#[contracttype]` tagged union / enum with data payloads (`ScSpecUdtUnionV0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnionSpec {
    pub name: String,
    pub cases: Vec<UnionCaseSpec>,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// A `#[contracterror]` enum (`ScSpecUdtErrorEnumV0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnumSpec {
    pub name: String,
    pub variants: Vec<EnumVariantSpec>,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// Parameter in an exported Soroban contract entrypoint (`ScSpecFunctionInputV0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionParamSpec {
    pub name: String,
    pub ty: TypeRef,
}

/// Exported Soroban contract function (`ScSpecFunctionV0` / `#[contractimpl] pub fn`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSpec {
    pub name: String,
    pub params: Vec<FunctionParamSpec>,
    pub return_type: TypeRef,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// Soroban storage tier (`env.storage().instance()`, `.persistent()`, `.temporary()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTier {
    Instance,
    Persistent,
    Temporary,
}

impl fmt::Display for StorageTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Instance => f.write_str("instance"),
            Self::Persistent => f.write_str("persistent"),
            Self::Temporary => f.write_str("temporary"),
        }
    }
}

/// Unified, source-agnostic Soroban contract specification model.
/// Populated from either Rust AST (`sorark-ast`) or compiled `.wasm` XDR (`sorark-wasm`).
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

    /// Computes whether `ty` is directly or transitively unbounded by walking `#[contracttype]`
    /// structs, tuple structs, and unions defined in this module.
    #[must_use]
    pub fn is_type_transitively_unbounded(&self, ty: &TypeRef) -> bool {
        let mut visited = HashSet::new();
        self.check_unbounded_recursive(ty, &mut visited)
    }

    /// Returns the human-readable chain of fields/types explaining why a type is unbounded
    /// (e.g. `VaultConfig -> field 'users' (Map<Address, i128>)`).
    #[must_use]
    pub fn unbounded_reason_chain(&self, ty: &TypeRef) -> Option<String> {
        let mut visited = HashSet::new();
        self.find_unbounded_chain(ty, &mut visited)
    }

    fn check_unbounded_recursive(&self, ty: &TypeRef, visited: &mut HashSet<String>) -> bool {
        if ty.is_directly_unbounded() {
            return true;
        }
        let mut custom_names = Vec::new();
        ty.referenced_custom_types(&mut custom_names);
        for name in custom_names {
            if !visited.insert(name.to_string()) {
                continue;
            }
            if let Some(s) = self.structs.iter().find(|s| s.name == name)
                && s.fields
                    .iter()
                    .any(|f| self.check_unbounded_recursive(&f.ty, visited))
            {
                return true;
            }
            if let Some(ts) = self.tuple_structs.iter().find(|ts| ts.name == name)
                && ts
                    .fields
                    .iter()
                    .any(|f| self.check_unbounded_recursive(f, visited))
            {
                return true;
            }
            if let Some(u) = self.unions.iter().find(|u| u.name == name)
                && u.cases.iter().any(|c| {
                    c.payload
                        .iter()
                        .any(|p| self.check_unbounded_recursive(p, visited))
                })
            {
                return true;
            }
        }
        false
    }

    fn find_unbounded_chain(&self, ty: &TypeRef, visited: &mut HashSet<String>) -> Option<String> {
        if ty.is_directly_unbounded() {
            return Some(format!("`{ty}` is dynamically sized"));
        }
        let mut custom_names = Vec::new();
        ty.referenced_custom_types(&mut custom_names);
        for name in custom_names {
            if !visited.insert(name.to_string()) {
                continue;
            }
            if let Some(s) = self.structs.iter().find(|s| s.name == name) {
                for field in &s.fields {
                    if let Some(inner) = self.find_unbounded_chain(&field.ty, visited) {
                        return Some(format!(
                            "`{}` -> field `{}` ({})",
                            s.name, field.name, inner
                        ));
                    }
                }
            }
            if let Some(ts) = self.tuple_structs.iter().find(|ts| ts.name == name) {
                for (idx, field_ty) in ts.fields.iter().enumerate() {
                    if let Some(inner) = self.find_unbounded_chain(field_ty, visited) {
                        return Some(format!("`{}` -> tuple element .{idx} ({inner})", ts.name));
                    }
                }
            }
            if let Some(u) = self.unions.iter().find(|u| u.name == name) {
                for case in &u.cases {
                    for payload_ty in &case.payload {
                        if let Some(inner) = self.find_unbounded_chain(payload_ty, visited) {
                            return Some(format!(
                                "`{}::{}` payload ({inner})",
                                u.name, case.name
                            ));
                        }
                    }
                }
            }
        }
        None
    }

    /// Builds a lookup map of struct names to their definitions.
    #[must_use]
    pub fn struct_map(&self) -> HashMap<&str, &StructSpec> {
        self.structs.iter().map(|s| (s.name.as_str(), s)).collect()
    }
}
