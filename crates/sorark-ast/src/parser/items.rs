//! Top-level Soroban item extractors (`#[contracttype]`, `#[contracterror]`, `#[contractimpl]`).

use super::body::FnBodyAnalyzer;
use super::const_eval::{eval_u64_expr, pat_to_ident_string};
use super::context::ParsedFunction;
use super::types::syn_type_to_typeref;
use sorark_ir::{
    ContractModule, EnumSpec, EnumVariantSpec, ErrorEnumSpec, FunctionParamSpec, FunctionSpec,
    StructFieldSpec, StructSpec, TupleStructSpec, TypeRef, UnionCaseSpec, UnionSpec,
};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{
    Attribute, Fields, FnArg, ImplItem, ImplItemFn, ItemEnum, ItemFn, ItemImpl, ItemStruct,
    ReturnType, Visibility,
};

/// Returns `true` if `attrs` contains a Soroban attribute whose final path segment equals `target`
/// (e.g., `#[contracttype]` or `#[soroban_sdk::contracttype]`).
#[must_use]
pub fn has_soroban_attr(attrs: &[Attribute], target: &str) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|seg| seg.ident == target)
    })
}

/// Extracts a `#[contracttype]` struct into [`ContractModule::structs`] (if named fields)
/// or [`ContractModule::tuple_structs`] (if unnamed tuple fields).
pub fn parse_contracttype_struct(file_label: &str, s: &ItemStruct, module: &mut ContractModule) {
    let name = s.ident.to_string();
    let line = Some(s.ident.span().start().line);
    match &s.fields {
        Fields::Named(named) => {
            let fields = named
                .named
                .iter()
                .filter_map(|f| {
                    let field_name = f.ident.as_ref()?.to_string();
                    Some(StructFieldSpec {
                        name: field_name,
                        ty: syn_type_to_typeref(&f.ty),
                        line: Some(f.span().start().line),
                    })
                })
                .collect();
            module.structs.push(StructSpec {
                name,
                fields,
                file: Some(file_label.to_string()),
                line,
            });
        }
        Fields::Unnamed(unnamed) => {
            let fields = unnamed
                .unnamed
                .iter()
                .map(|f| syn_type_to_typeref(&f.ty))
                .collect();
            module.tuple_structs.push(TupleStructSpec {
                name,
                fields,
                file: Some(file_label.to_string()),
                line,
            });
        }
        Fields::Unit => {}
    }
}

/// Extracts a `#[contracttype]` enum into either [`ContractModule::enums`] (for integer unit enums)
/// or [`ContractModule::unions`] (for tagged unions / `DataKey` enums).
pub fn parse_contracttype_enum(file_label: &str, e: &ItemEnum, module: &mut ContractModule) {
    let name = e.ident.to_string();
    let line = Some(e.ident.span().start().line);
    let all_unit = e.variants.iter().all(|v| matches!(v.fields, Fields::Unit));
    let any_explicit_discriminant = e.variants.iter().any(|v| v.discriminant.is_some());

    if all_unit && any_explicit_discriminant {
        module.enums.push(EnumSpec {
            name,
            variants: extract_discriminant_variants(e, 0),
            file: Some(file_label.to_string()),
            line,
        });
    } else {
        module.unions.push(UnionSpec {
            name,
            cases: extract_union_cases(e),
            file: Some(file_label.to_string()),
            line,
        });
    }
}

/// Extracts a `#[contracterror]` enum into [`ContractModule::error_enums`].
pub fn parse_contracterror_enum(file_label: &str, e: &ItemEnum, module: &mut ContractModule) {
    let name = e.ident.to_string();
    let line = Some(e.ident.span().start().line);
    module.error_enums.push(ErrorEnumSpec {
        name,
        variants: extract_discriminant_variants(e, 1),
        file: Some(file_label.to_string()),
        line,
    });
}

/// Computes `u32` discriminant values for each variant of a unit or error enum.
fn extract_discriminant_variants(e: &ItemEnum, start_disc: u32) -> Vec<EnumVariantSpec> {
    let mut next_disc = start_disc;
    let empty_consts = HashMap::new();
    let mut variants = Vec::with_capacity(e.variants.len());

    for v in &e.variants {
        if let Some((_, expr)) = &v.discriminant
            && let Some(val) = eval_u64_expr(expr, &empty_consts)
        {
            next_disc = u32::try_from(val).unwrap_or(next_disc);
        }
        variants.push(EnumVariantSpec {
            name: v.ident.to_string(),
            discriminant: next_disc,
            line: Some(v.ident.span().start().line),
        });
        next_disc = next_disc.saturating_add(1);
    }
    variants
}

/// Converts each variant of a tagged `#[contracttype]` enum into a [`UnionCaseSpec`].
fn extract_union_cases(e: &ItemEnum) -> Vec<UnionCaseSpec> {
    e.variants
        .iter()
        .map(|v| {
            let payload = match &v.fields {
                Fields::Unit => Vec::new(),
                Fields::Unnamed(u) => u
                    .unnamed
                    .iter()
                    .map(|f| syn_type_to_typeref(&f.ty))
                    .collect(),
                Fields::Named(n) => n.named.iter().map(|f| syn_type_to_typeref(&f.ty)).collect(),
            };
            UnionCaseSpec {
                name: v.ident.to_string(),
                payload,
                line: Some(v.ident.span().start().line),
            }
        })
        .collect()
}

/// Extracts methods from an `impl` block, recording public `#[contractimpl]` entrypoints in
/// `module.functions` and analyzing every method body into `functions`.
pub fn parse_impl_block(
    file_label: &str,
    source_lines: &[&str],
    imp: &ItemImpl,
    is_contractimpl: bool,
    constants: &HashMap<String, u64>,
    module: &mut ContractModule,
    functions: &mut Vec<ParsedFunction>,
) {
    for item in &imp.items {
        if let ImplItem::Fn(method) = item {
            let is_pub = matches!(method.vis, Visibility::Public(_)) || imp.trait_.is_some();
            let is_entrypoint = is_contractimpl && is_pub;
            if is_entrypoint {
                module
                    .functions
                    .push(extract_function_spec(file_label, method));
            }
            let parsed = analyze_impl_fn(
                file_label,
                source_lines,
                method,
                is_entrypoint,
                is_pub,
                constants,
            );
            functions.push(parsed);
        }
    }
}

/// Builds a normalized [`FunctionSpec`] from a public `#[contractimpl]` method signature.
fn extract_function_spec(file_label: &str, method: &ImplItemFn) -> FunctionSpec {
    let name = method.sig.ident.to_string();
    let params = extract_exported_params(&method.sig.inputs);
    let return_type = extract_exported_return_type(&method.sig.output);

    FunctionSpec {
        name,
        params,
        return_type,
        file: Some(file_label.to_string()),
        line: Some(method.sig.ident.span().start().line),
    }
}

/// Extracts exported parameter specs, omitting the leading Soroban `Env` parameter.
fn extract_exported_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::Token![,]>,
) -> Vec<FunctionParamSpec> {
    let mut params = Vec::new();
    for input in inputs {
        if let FnArg::Typed(pat_ty) = input {
            let param_name = pat_to_ident_string(&pat_ty.pat).unwrap_or_else(|| "_".to_string());
            let ty_ref = syn_type_to_typeref(&pat_ty.ty);
            if matches!(&ty_ref, TypeRef::Custom(c) if c == "Env") {
                continue;
            }
            params.push(FunctionParamSpec {
                name: param_name,
                ty: ty_ref,
            });
        }
    }
    params
}

/// Extracts the normalized return type of an entrypoint, unwrapping `Result<T, E>` to `T`
/// to match `ScSpecFunctionV0` conventions.
fn extract_exported_return_type(output: &ReturnType) -> TypeRef {
    match output {
        ReturnType::Default => TypeRef::Void,
        ReturnType::Type(_, ty) => {
            let converted = syn_type_to_typeref(ty);
            if let TypeRef::Result { ok, .. } = converted {
                *ok
            } else {
                converted
            }
        }
    }
}

/// Analyzes the body of an `impl` method into a [`ParsedFunction`].
fn analyze_impl_fn(
    file_label: &str,
    source_lines: &[&str],
    method: &ImplItemFn,
    is_contract_entrypoint: bool,
    is_pub: bool,
    constants: &HashMap<String, u64>,
) -> ParsedFunction {
    let mut visitor = FnBodyAnalyzer::new(source_lines, constants);
    visitor.seed_fn_inputs(&method.sig.inputs);
    visitor.visit_block(&method.block);
    let span = method.sig.ident.span().start();
    visitor.into_parsed_function(
        method.sig.ident.to_string(),
        is_contract_entrypoint,
        is_pub,
        file_label,
        span.line,
        span.column + 1,
    )
}

/// Analyzes the body of a free module function into a [`ParsedFunction`].
pub fn analyze_free_fn(
    file_label: &str,
    source_lines: &[&str],
    func: &ItemFn,
    constants: &HashMap<String, u64>,
) -> ParsedFunction {
    let mut visitor = FnBodyAnalyzer::new(source_lines, constants);
    visitor.seed_fn_inputs(&func.sig.inputs);
    visitor.visit_block(&func.block);
    let span = func.sig.ident.span().start();
    let is_pub = matches!(func.vis, Visibility::Public(_));
    visitor.into_parsed_function(
        func.sig.ident.to_string(),
        false,
        is_pub,
        file_label,
        span.line,
        span.column + 1,
    )
}
