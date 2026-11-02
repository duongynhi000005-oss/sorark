//! Normalized Soroban type representation shared by every SORARK engine.
//!
//! [`TypeRef`] mirrors the XDR `ScSpecTypeDef` union so that a type parsed from Rust
//! source (`syn`) and a type decoded from a compiled `.wasm` spec compare as equal.

use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// Returns `true` if this type is dynamically sized on the ledger.
    ///
    /// `Vec<T>`, `Map<K, V>`, `Bytes`, and `String` are unbounded by themselves; `Option`,
    /// `Result`, and tuples are unbounded when any of their inner types is.
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

    /// Pushes every user-defined type name referenced (at any depth) by this type into `out`.
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

    /// Returns the canonical, human-readable signature used when comparing AST and WASM types
    /// (for example `Map<Address, i128>` or `Option<BytesN<32>>`).
    #[must_use]
    pub fn canonical_signature(&self) -> String {
        if let Some(name) = self.primitive_name() {
            return name.to_string();
        }
        self.composite_signature()
    }

    /// Returns the fixed spelling of primitive (non-generic) types, or `None` for composites.
    fn primitive_name(&self) -> Option<&'static str> {
        let name = match self {
            Self::Void => "()",
            Self::Bool => "bool",
            Self::U32 => "u32",
            Self::I32 => "i32",
            Self::U64 => "u64",
            Self::I64 => "i64",
            Self::Timepoint => "Timepoint",
            Self::Duration => "Duration",
            Self::U128 => "u128",
            Self::I128 => "i128",
            Self::U256 => "U256",
            Self::I256 => "I256",
            Self::Bytes => "Bytes",
            Self::String => "String",
            Self::Symbol => "Symbol",
            Self::Address => "Address",
            Self::Val => "Val",
            Self::Error => "Error",
            _ => return None,
        };
        Some(name)
    }

    /// Formats generic and user-defined types by recursing into their inner types.
    fn composite_signature(&self) -> String {
        match self {
            Self::BytesN(n) => format!("BytesN<{n}>"),
            Self::Option(inner) => format!("Option<{inner}>"),
            Self::Result { ok, err } => format!("Result<{ok}, {err}>"),
            Self::Vec(inner) => format!("Vec<{inner}>"),
            Self::Map { key, value } => format!("Map<{key}, {value}>"),
            Self::Tuple(items) => format!("({})", join_signatures(items)),
            Self::Custom(name) => name.clone(),
            // Primitives are handled by `primitive_name`; this arm keeps the match exhaustive.
            other => other.primitive_name().unwrap_or("?").to_string(),
        }
    }
}

/// Joins a list of types into a comma-separated signature string.
fn join_signatures(items: &[TypeRef]) -> String {
    items
        .iter()
        .map(TypeRef::canonical_signature)
        .collect::<Vec<_>>()
        .join(", ")
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical_signature())
    }
}
