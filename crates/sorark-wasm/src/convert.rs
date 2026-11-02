//! Conversion from Stellar XDR [`ScSpecEntry`] definitions into [`sorark_ir`] specifications.

use sorark_ir::{
    ContractModule, EnumSpec, EnumVariantSpec, ErrorEnumSpec, FunctionParamSpec, FunctionSpec,
    StructFieldSpec, StructSpec, TupleStructSpec, TypeRef, UnionCaseSpec, UnionSpec,
};
use stellar_xdr::{
    ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0,
    ScSpecUdtStructV0, ScSpecUdtUnionCaseV0, ScSpecUdtUnionV0,
};

/// Translates a single decoded [`ScSpecEntry`] and appends it to `module`.
pub(crate) fn populate_module_from_spec_entry(
    path_label: &str,
    entry: &ScSpecEntry,
    module: &mut ContractModule,
) {
    match entry {
        ScSpecEntry::FunctionV0(f) => {
            module.functions.push(convert_spec_function(path_label, f));
        }
        ScSpecEntry::UdtStructV0(s) => {
            convert_spec_struct(path_label, s, module);
        }
        ScSpecEntry::UdtEnumV0(e) => {
            module.enums.push(convert_spec_enum(path_label, e));
        }
        ScSpecEntry::UdtUnionV0(u) => {
            module.unions.push(convert_spec_union(path_label, u));
        }
        ScSpecEntry::UdtErrorEnumV0(err) => {
            module
                .error_enums
                .push(convert_spec_error_enum(path_label, err));
        }
        ScSpecEntry::EventV0(_) => {}
    }
}

/// Converts an [`ScSpecFunctionV0`] entry into a normalized [`FunctionSpec`].
fn convert_spec_function(path_label: &str, f: &ScSpecFunctionV0) -> FunctionSpec {
    let name = f.name.to_utf8_string_lossy();
    let params = f
        .inputs
        .iter()
        .map(|inp| FunctionParamSpec {
            name: inp.name.to_utf8_string_lossy(),
            ty: xdr_typedef_to_typeref(&inp.type_),
        })
        .collect();
    let return_type = match f.outputs.as_slice() {
        [] => TypeRef::Void,
        [single] => xdr_typedef_to_typeref(single),
        many => TypeRef::Tuple(many.iter().map(xdr_typedef_to_typeref).collect()),
    };
    FunctionSpec {
        name,
        params,
        return_type,
        file: Some(path_label.to_string()),
        line: None,
    }
}

/// Converts an [`ScSpecUdtStructV0`] into either a [`TupleStructSpec`] (when fields are
/// sequential 0-indexed numbers `"0"`, `"1"`, ...) or a named [`StructSpec`].
fn convert_spec_struct(path_label: &str, s: &ScSpecUdtStructV0, module: &mut ContractModule) {
    let name = s.name.to_utf8_string_lossy();
    let is_tuple_struct = !s.fields.is_empty()
        && s.fields
            .iter()
            .enumerate()
            .all(|(idx, f)| f.name.to_utf8_string_lossy() == idx.to_string());

    if is_tuple_struct {
        let fields = s
            .fields
            .iter()
            .map(|f| xdr_typedef_to_typeref(&f.type_))
            .collect();
        module.tuple_structs.push(TupleStructSpec {
            name,
            fields,
            file: Some(path_label.to_string()),
            line: None,
        });
    } else {
        let fields = s
            .fields
            .iter()
            .map(|f| StructFieldSpec {
                name: f.name.to_utf8_string_lossy(),
                ty: xdr_typedef_to_typeref(&f.type_),
                line: None,
            })
            .collect();
        module.structs.push(StructSpec {
            name,
            fields,
            file: Some(path_label.to_string()),
            line: None,
        });
    }
}

/// Converts an [`ScSpecUdtEnumV0`] entry into a normalized [`EnumSpec`].
fn convert_spec_enum(path_label: &str, e: &ScSpecUdtEnumV0) -> EnumSpec {
    let name = e.name.to_utf8_string_lossy();
    let variants = e
        .cases
        .iter()
        .map(|c| EnumVariantSpec {
            name: c.name.to_utf8_string_lossy(),
            discriminant: c.value,
            line: None,
        })
        .collect();
    EnumSpec {
        name,
        variants,
        file: Some(path_label.to_string()),
        line: None,
    }
}

/// Converts an [`ScSpecUdtUnionV0`] entry into a normalized [`UnionSpec`].
fn convert_spec_union(path_label: &str, u: &ScSpecUdtUnionV0) -> UnionSpec {
    let name = u.name.to_utf8_string_lossy();
    let cases = u
        .cases
        .iter()
        .map(|c| match c {
            ScSpecUdtUnionCaseV0::VoidV0(v) => UnionCaseSpec {
                name: v.name.to_utf8_string_lossy(),
                payload: Vec::new(),
                line: None,
            },
            ScSpecUdtUnionCaseV0::TupleV0(t) => UnionCaseSpec {
                name: t.name.to_utf8_string_lossy(),
                payload: t.type_.iter().map(xdr_typedef_to_typeref).collect(),
                line: None,
            },
        })
        .collect();
    UnionSpec {
        name,
        cases,
        file: Some(path_label.to_string()),
        line: None,
    }
}

/// Converts an [`ScSpecUdtErrorEnumV0`] entry into a normalized [`ErrorEnumSpec`].
fn convert_spec_error_enum(path_label: &str, e: &ScSpecUdtErrorEnumV0) -> ErrorEnumSpec {
    let name = e.name.to_utf8_string_lossy();
    let variants = e
        .cases
        .iter()
        .map(|c| EnumVariantSpec {
            name: c.name.to_utf8_string_lossy(),
            discriminant: c.value,
            line: None,
        })
        .collect();
    ErrorEnumSpec {
        name,
        variants,
        file: Some(path_label.to_string()),
        line: None,
    }
}

/// Converts a Stellar XDR [`ScSpecTypeDef`] into a normalized [`TypeRef`].
#[must_use]
pub fn xdr_typedef_to_typeref(td: &ScSpecTypeDef) -> TypeRef {
    match td {
        ScSpecTypeDef::Val => TypeRef::Val,
        ScSpecTypeDef::Bool => TypeRef::Bool,
        ScSpecTypeDef::Void => TypeRef::Void,
        ScSpecTypeDef::Error => TypeRef::Error,
        ScSpecTypeDef::U32 => TypeRef::U32,
        ScSpecTypeDef::I32 => TypeRef::I32,
        ScSpecTypeDef::U64 => TypeRef::U64,
        ScSpecTypeDef::I64 => TypeRef::I64,
        ScSpecTypeDef::Timepoint => TypeRef::Timepoint,
        ScSpecTypeDef::Duration => TypeRef::Duration,
        ScSpecTypeDef::U128 => TypeRef::U128,
        ScSpecTypeDef::I128 => TypeRef::I128,
        ScSpecTypeDef::U256 => TypeRef::U256,
        ScSpecTypeDef::I256 => TypeRef::I256,
        ScSpecTypeDef::Bytes => TypeRef::Bytes,
        ScSpecTypeDef::String => TypeRef::String,
        ScSpecTypeDef::Symbol => TypeRef::Symbol,
        ScSpecTypeDef::Address | ScSpecTypeDef::MuxedAddress => TypeRef::Address,
        ScSpecTypeDef::Option(opt) => {
            TypeRef::Option(Box::new(xdr_typedef_to_typeref(&opt.value_type)))
        }
        ScSpecTypeDef::Result(res) => TypeRef::Result {
            ok: Box::new(xdr_typedef_to_typeref(&res.ok_type)),
            err: Box::new(xdr_typedef_to_typeref(&res.error_type)),
        },
        ScSpecTypeDef::Vec(v) => TypeRef::Vec(Box::new(xdr_typedef_to_typeref(&v.element_type))),
        ScSpecTypeDef::Map(m) => TypeRef::Map {
            key: Box::new(xdr_typedef_to_typeref(&m.key_type)),
            value: Box::new(xdr_typedef_to_typeref(&m.value_type)),
        },
        ScSpecTypeDef::Tuple(t) => {
            TypeRef::Tuple(t.value_types.iter().map(xdr_typedef_to_typeref).collect())
        }
        ScSpecTypeDef::BytesN(b) => TypeRef::BytesN(b.n),
        ScSpecTypeDef::Udt(udt) => TypeRef::Custom(udt.name.to_utf8_string_lossy()),
    }
}
