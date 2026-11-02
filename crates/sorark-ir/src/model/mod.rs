//! Source-agnostic Soroban contract model.
//!
//! - [`type_ref`]: normalized `ScSpecTypeDef` equivalent ([`TypeRef`]).
//! - [`specs`]: struct / enum / union / error / function specifications.
//! - [`origin`]: where a module was loaded from ([`SourceOrigin`]).
//! - [`contract_module`]: the [`ContractModule`] aggregate and its queries.

mod contract_module;
mod origin;
mod specs;
mod type_ref;
mod unbounded;

pub use contract_module::ContractModule;
pub use origin::SourceOrigin;
pub use specs::{
    EnumSpec, EnumVariantSpec, ErrorEnumSpec, FunctionParamSpec, FunctionSpec, StorageTier,
    StructFieldSpec, StructSpec, TupleStructSpec, UnionCaseSpec, UnionSpec,
};
pub use type_ref::TypeRef;
