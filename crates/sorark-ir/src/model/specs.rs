//! User-defined type and entrypoint specifications.
//!
//! Each struct mirrors one `ScSpecEntry` variant and documents how Soroban serializes it
//! on-chain, because that serialization determines which upgrades are safe.

use super::TypeRef;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A named field inside a `#[contracttype]` struct (`ScSpecUdtStructFieldV0`).
///
/// On-chain, named structs serialize as an `ScMap` keyed by `ScSymbol(name)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructFieldSpec {
    pub name: String,
    pub ty: TypeRef,
    pub line: Option<usize>,
}

/// A `#[contracttype]` struct with named fields (`ScSpecUdtStructV0`, serialized as `ScMap`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructSpec {
    pub name: String,
    pub fields: Vec<StructFieldSpec>,
    pub file: Option<String>,
    pub line: Option<usize>,
}

impl StructSpec {
    /// Looks up a field by its exact name (the `ScSymbol` map key).
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&StructFieldSpec> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// A `#[contracttype]` tuple struct (`struct Pair(u64, Address)`).
///
/// Serialized on-chain as a positional `ScVec`, so element order determines deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleStructSpec {
    pub name: String,
    pub fields: Vec<TypeRef>,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// A single case inside a C-style enum (`ScSpecUdtEnumCaseV0`) or `#[contracterror]` enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumVariantSpec {
    pub name: String,
    pub discriminant: u32,
    pub line: Option<usize>,
}

/// A C-style integer `#[contracttype]` enum (`ScSpecUdtEnumV0`), serialized as `ScVal::U32`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumSpec {
    pub name: String,
    pub variants: Vec<EnumVariantSpec>,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// A single case in a Soroban tagged union / data enum (`ScSpecUdtUnionCaseV0`).
///
/// Serialized on-chain as `ScVec([ScSymbol(name), ...payload])`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnionCaseSpec {
    pub name: String,
    /// Empty for void variants (`DataKey::Admin`), non-empty for tuple variants
    /// (`DataKey::Balance(Address)`).
    pub payload: Vec<TypeRef>,
    pub line: Option<usize>,
}

impl UnionCaseSpec {
    /// Renders the case as Rust-like source, e.g. `Balance(Address)` or `Admin`.
    #[must_use]
    pub fn signature(&self) -> String {
        if self.payload.is_empty() {
            self.name.clone()
        } else {
            format!("{}({})", self.name, self.payload_signature())
        }
    }

    /// Renders only the payload types, e.g. `Address, u32`.
    #[must_use]
    pub fn payload_signature(&self) -> String {
        self.payload
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
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

/// Parameter of an exported Soroban contract entrypoint (`ScSpecFunctionInputV0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionParamSpec {
    pub name: String,
    pub ty: TypeRef,
}

impl fmt::Display for FunctionParamSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.ty)
    }
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

impl FunctionSpec {
    /// Renders the parameter list as `name: Type, ...`.
    #[must_use]
    pub fn params_signature(&self) -> String {
        self.params
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Returns the parameter types in order; names are ignored because they do not affect
    /// the on-chain calling convention.
    #[must_use]
    pub fn param_types(&self) -> Vec<&TypeRef> {
        self.params.iter().map(|p| &p.ty).collect()
    }
}

/// Soroban storage tier (`env.storage().instance()`, `.persistent()`, `.temporary()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTier {
    Instance,
    Persistent,
    Temporary,
}

impl StorageTier {
    /// Maps the SDK accessor method name (`instance`, `persistent`, `temporary`) to a tier.
    #[must_use]
    pub fn from_accessor(method: &str) -> Option<Self> {
        match method {
            "instance" => Some(Self::Instance),
            "persistent" => Some(Self::Persistent),
            "temporary" => Some(Self::Temporary),
            _ => None,
        }
    }

    /// Returns the SDK accessor method name for this tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Persistent => "persistent",
            Self::Temporary => "temporary",
        }
    }
}

impl fmt::Display for StorageTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
