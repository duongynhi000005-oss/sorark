//! Conversion from `syn::Type` AST nodes to normalized [`TypeRef`] values.

use sorark_ir::TypeRef;
use syn::{Expr, GenericArgument, Lit, PathArguments, Type};

/// Converts a `syn::Type` from a Soroban Rust file into a normalized [`TypeRef`].
#[must_use]
pub fn syn_type_to_typeref(ty: &Type) -> TypeRef {
    match ty {
        Type::Reference(r) => syn_type_to_typeref(&r.elem),
        Type::Paren(p) => syn_type_to_typeref(&p.elem),
        Type::Tuple(t) => convert_tuple_type(t),
        Type::Path(tp) => convert_path_type(tp),
        _ => TypeRef::Val,
    }
}

/// Converts a Rust tuple type (`()` or `(A, B)`) into [`TypeRef::Void`] or [`TypeRef::Tuple`].
fn convert_tuple_type(tuple: &syn::TypeTuple) -> TypeRef {
    if tuple.elems.is_empty() {
        TypeRef::Void
    } else {
        TypeRef::Tuple(tuple.elems.iter().map(syn_type_to_typeref).collect())
    }
}

/// Converts a path type (`u64`, `soroban_sdk::Address`, `Map<K, V>`) into a [`TypeRef`].
fn convert_path_type(tp: &syn::TypePath) -> TypeRef {
    let Some(seg) = tp.path.segments.last() else {
        return TypeRef::Val;
    };
    let ident = seg.ident.to_string();

    if let Some(prim) = map_primitive_ident(&ident) {
        return prim;
    }

    match ident.as_str() {
        "BytesN" => {
            let len = extract_const_generic_u32(&seg.arguments).unwrap_or(32);
            TypeRef::BytesN(len)
        }
        "Option" => {
            let inner = extract_type_generics(&seg.arguments)
                .into_iter()
                .next()
                .unwrap_or(TypeRef::Val);
            TypeRef::Option(Box::new(inner))
        }
        "Result" => {
            let mut generics = extract_type_generics(&seg.arguments).into_iter();
            let ok = generics.next().unwrap_or(TypeRef::Void);
            let err = generics.next().unwrap_or(TypeRef::Error);
            TypeRef::Result {
                ok: Box::new(ok),
                err: Box::new(err),
            }
        }
        "Vec" => {
            let inner = extract_type_generics(&seg.arguments)
                .into_iter()
                .next()
                .unwrap_or(TypeRef::Val);
            TypeRef::Vec(Box::new(inner))
        }
        "Map" => {
            let mut generics = extract_type_generics(&seg.arguments).into_iter();
            let key = generics.next().unwrap_or(TypeRef::Val);
            let value = generics.next().unwrap_or(TypeRef::Val);
            TypeRef::Map {
                key: Box::new(key),
                value: Box::new(value),
            }
        }
        other => TypeRef::Custom(other.to_string()),
    }
}

/// Maps non-generic Soroban/Rust type identifiers to their corresponding [`TypeRef`] variant.
fn map_primitive_ident(ident: &str) -> Option<TypeRef> {
    let ty = match ident {
        "bool" => TypeRef::Bool,
        "u32" => TypeRef::U32,
        "i32" => TypeRef::I32,
        "u64" => TypeRef::U64,
        "i64" => TypeRef::I64,
        "u128" => TypeRef::U128,
        "i128" => TypeRef::I128,
        "U256" => TypeRef::U256,
        "I256" => TypeRef::I256,
        "Timepoint" => TypeRef::Timepoint,
        "Duration" => TypeRef::Duration,
        "Bytes" => TypeRef::Bytes,
        "String" => TypeRef::String,
        "Symbol" => TypeRef::Symbol,
        "Address" | "MuxedAddress" => TypeRef::Address,
        "Val" | "RawVal" => TypeRef::Val,
        "Error" => TypeRef::Error,
        _ => return None,
    };
    Some(ty)
}

/// Extracts all type generic arguments (`<T, U>`) from an angle-bracketed path segment.
fn extract_type_generics(args: &PathArguments) -> Vec<TypeRef> {
    let PathArguments::AngleBracketed(ab) = args else {
        return Vec::new();
    };
    ab.args
        .iter()
        .filter_map(|arg| {
            if let GenericArgument::Type(t) = arg {
                Some(syn_type_to_typeref(t))
            } else {
                None
            }
        })
        .collect()
}

/// Extracts a `u32` const generic argument (such as `32` in `BytesN<32>`).
fn extract_const_generic_u32(args: &PathArguments) -> Option<u32> {
    let PathArguments::AngleBracketed(ab) = args else {
        return None;
    };
    for arg in &ab.args {
        match arg {
            GenericArgument::Const(Expr::Lit(lit)) => {
                if let Lit::Int(int_lit) = &lit.lit {
                    return int_lit.base10_parse::<u32>().ok();
                }
            }
            GenericArgument::Type(Type::Path(tp)) => {
                if let Some(seg) = tp.path.segments.last()
                    && let Ok(n) = seg.ident.to_string().parse::<u32>()
                {
                    return Some(n);
                }
            }
            _ => {}
        }
    }
    None
}
