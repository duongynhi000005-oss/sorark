//! Soroban storage-layout and ABI upgrade compatibility rules (`ARK-DIFF-001`..`ARK-DIFF-005`).

mod enum_union;
mod error_enum;
mod function_abi;
mod protocol;
mod struct_layout;

pub use enum_union::EnumAndUnionLayoutDiffRule;
pub use error_enum::ErrorEnumDiffRule;
pub use function_abi::FunctionAbiDiffRule;
pub use protocol::ProtocolVersionDiffRule;
pub use struct_layout::StructLayoutDiffRule;
