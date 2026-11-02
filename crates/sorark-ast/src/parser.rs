use proc_macro2::Span;
use sorark_ir::{
    ContractModule, EnumSpec, EnumVariantSpec, ErrorEnumSpec, FunctionParamSpec, FunctionSpec,
    SourceOrigin, StorageTier, StructFieldSpec, StructSpec, TupleStructSpec, TypeRef,
    UnionCaseSpec, UnionSpec,
};
use std::collections::{HashMap, HashSet};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprCall, ExprMethodCall, ExprPath, Fields, File, FnArg, GenericArgument,
    ImplItem, ImplItemFn, Item, ItemEnum, ItemFn, ItemImpl, ItemStruct, Lit, Pat, PathArguments,
    ReturnType, Stmt, Type,
};

/// Kind of operation performed on a Soroban storage tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOpKind {
    Set,
    Update,
    ExtendTtl,
    Get,
    Remove,
    Has,
}

/// Recorded storage operation inside a contract function or helper.
#[derive(Debug, Clone)]
pub struct StorageOp {
    pub tier: StorageTier,
    pub kind: StorageOpKind,
    pub key_expr: Option<String>,
    pub value_expr: Option<String>,
    pub inferred_value_type: Option<TypeRef>,
    /// For `extend_ttl`, stores `(threshold, extend_to)` if resolvable to integer literals/constants.
    pub ttl_bounds: Option<(Option<u64>, Option<u64>)>,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
}

/// Recorded call to `update_current_contract_wasm`.
#[derive(Debug, Clone)]
pub struct WasmUpgradeCall {
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub auth_seen_before_call: bool,
}

/// Summary of a single parsed function (`#[contractimpl]` method or module helper function).
#[derive(Debug, Clone)]
pub struct ParsedFunction {
    pub name: String,
    pub is_contract_entrypoint: bool,
    pub is_pub: bool,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub storage_ops: Vec<StorageOp>,
    pub has_direct_require_auth: bool,
    pub wasm_upgrade_calls: Vec<WasmUpgradeCall>,
    pub called_functions: Vec<String>,
}

/// Complete Pass-1 AST analysis context across a Soroban crate/module.
#[derive(Debug, Clone)]
pub struct AstAnalysisContext {
    pub module: ContractModule,
    pub functions: Vec<ParsedFunction>,
    pub constants: HashMap<String, u64>,
    /// Map of `(file, line_number)` -> set of suppressed rule IDs (`// sorark-ignore: ARK-...`).
    pub inline_suppressions: HashMap<(String, usize), HashSet<String>>,
}

impl AstAnalysisContext {
    /// Checks whether `rule_id` is suppressed via `// sorark-ignore:` on `line` or `line - 1`.
    #[must_use]
    pub fn is_suppressed(&self, file: &str, line: usize, rule_id: &str) -> bool {
        let upper = rule_id.to_ascii_uppercase();
        for check_line in [line, line.saturating_sub(1)] {
            if let Some(set) = self
                .inline_suppressions
                .get(&(file.to_string(), check_line))
                && (set.contains(&upper) || set.contains("ALL"))
            {
                return true;
            }
        }
        false
    }

    /// Returns `true` if `func` or any helper function it calls (up to 4 hops) calls `extend_ttl`
    /// on the specified `tier`.
    #[must_use]
    pub fn function_extends_ttl(&self, func: &ParsedFunction, tier: StorageTier) -> bool {
        let mut visited = HashSet::new();
        self.check_extends_ttl_recursive(func, tier, 0, &mut visited)
    }

    fn check_extends_ttl_recursive(
        &self,
        func: &ParsedFunction,
        tier: StorageTier,
        depth: usize,
        visited: &mut HashSet<String>,
    ) -> bool {
        if depth > 4 || !visited.insert(func.name.clone()) {
            return false;
        }
        if func
            .storage_ops
            .iter()
            .any(|op| op.kind == StorageOpKind::ExtendTtl && op.tier == tier)
        {
            return true;
        }
        for callee in &func.called_functions {
            if let Some(target) = self.functions.iter().find(|f| &f.name == callee)
                && self.check_extends_ttl_recursive(target, tier, depth + 1, visited)
            {
                return true;
            }
        }
        false
    }

    /// Returns `true` if `func` or any helper function it invokes calls `.require_auth()`
    /// or `.require_auth_for_args(...)`.
    #[must_use]
    pub fn function_requires_auth(&self, func: &ParsedFunction) -> bool {
        let mut visited = HashSet::new();
        self.check_requires_auth_recursive(func, 0, &mut visited)
    }

    fn check_requires_auth_recursive(
        &self,
        func: &ParsedFunction,
        depth: usize,
        visited: &mut HashSet<String>,
    ) -> bool {
        if depth > 4 || !visited.insert(func.name.clone()) {
            return false;
        }
        if func.has_direct_require_auth {
            return true;
        }
        for callee in &func.called_functions {
            if let Some(target) = self.functions.iter().find(|f| &f.name == callee)
                && self.check_requires_auth_recursive(target, depth + 1, visited)
            {
                return true;
            }
        }
        false
    }
}

/// Parses inline `// sorark-ignore: ARK-STOR-001, ARK-STOR-002` comments from raw source text.
pub fn parse_inline_suppressions(
    file_label: &str,
    source: &str,
    out: &mut HashMap<(String, usize), HashSet<String>>,
) {
    for (idx, line_str) in source.lines().enumerate() {
        let line_num = idx + 1;
        if let Some(pos) = line_str.find("sorark-ignore:") {
            let after = &line_str[pos + "sorark-ignore:".len()..];
            let rules_part = after.split("//").next().unwrap_or(after);
            let mut set = HashSet::new();
            for token in rules_part.split([',', ' ', '\t']) {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    set.insert(trimmed.to_ascii_uppercase());
                }
            }
            if !set.is_empty() {
                out.entry((file_label.to_string(), line_num))
                    .or_default()
                    .extend(set);
            }
        }
    }
}

/// Parses a single Rust source file into an existing [`AstAnalysisContext`].
pub fn parse_rust_source_into_context(
    file_label: &str,
    source: &str,
    ctx: &mut AstAnalysisContext,
) -> Result<(), syn::Error> {
    parse_inline_suppressions(file_label, source, &mut ctx.inline_suppressions);
    let syntax: File = syn::parse_file(source)?;
    let source_lines: Vec<&str> = source.lines().collect();

    // First collect constants so TTL bounds can resolve named constants like `DAY_IN_LEDGERS`.
    for item in &syntax.items {
        if let Item::Const(c) = item
            && let Some(val) = eval_u64_expr(&c.expr, &ctx.constants)
        {
            ctx.constants.insert(c.ident.to_string(), val);
        }
    }

    for item in &syntax.items {
        match item {
            Item::Struct(s) if has_soroban_attr(&s.attrs, "contracttype") => {
                parse_contracttype_struct(file_label, s, &mut ctx.module);
            }
            Item::Enum(e) => {
                if has_soroban_attr(&e.attrs, "contracttype") {
                    parse_contracttype_enum(file_label, e, &mut ctx.module);
                } else if has_soroban_attr(&e.attrs, "contracterror") {
                    parse_contracterror_enum(file_label, e, &mut ctx.module);
                }
            }
            Item::Impl(imp) => {
                let is_contractimpl = has_soroban_attr(&imp.attrs, "contractimpl");
                parse_impl_block(
                    file_label,
                    &source_lines,
                    imp,
                    is_contractimpl,
                    &ctx.constants,
                    &mut ctx.module,
                    &mut ctx.functions,
                );
            }
            Item::Fn(func) => {
                let parsed = analyze_free_fn(file_label, &source_lines, func, &ctx.constants);
                ctx.functions.push(parsed);
            }
            _ => {}
        }
    }

    Ok(())
}

/// Convenience helper to parse a single source string into a standalone [`AstAnalysisContext`].
pub fn parse_single_source(
    module_name: &str,
    file_label: &str,
    source: &str,
) -> Result<AstAnalysisContext, syn::Error> {
    let mut ctx = AstAnalysisContext {
        module: ContractModule::new(
            module_name,
            SourceOrigin::RustSource {
                path: file_label.to_string(),
            },
        ),
        functions: Vec::new(),
        constants: HashMap::new(),
        inline_suppressions: HashMap::new(),
    };
    parse_rust_source_into_context(file_label, source, &mut ctx)?;
    Ok(ctx)
}

fn has_soroban_attr(attrs: &[Attribute], target: &str) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|seg| seg.ident == target)
    })
}

fn parse_contracttype_struct(file_label: &str, s: &ItemStruct, module: &mut ContractModule) {
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

fn parse_contracttype_enum(file_label: &str, e: &ItemEnum, module: &mut ContractModule) {
    let name = e.ident.to_string();
    let line = Some(e.ident.span().start().line);
    let all_unit = e.variants.iter().all(|v| matches!(v.fields, Fields::Unit));
    let any_explicit_discriminant = e.variants.iter().any(|v| v.discriminant.is_some());

    // In Soroban, unit enums with explicit discriminants or #[repr(u32)] map to ScSpecUdtEnumV0,
    // while enums with tuple payloads (or standard DataKey enums) map to ScSpecUdtUnionV0.
    if all_unit && any_explicit_discriminant {
        let mut next_disc: u32 = 0;
        let mut variants = Vec::new();
        for v in &e.variants {
            if let Some((_, expr)) = &v.discriminant
                && let Some(val) = eval_u64_expr(expr, &HashMap::new())
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
        module.enums.push(EnumSpec {
            name,
            variants,
            file: Some(file_label.to_string()),
            line,
        });
    } else {
        let cases = e
            .variants
            .iter()
            .map(|v| {
                let payload = match &v.fields {
                    Fields::Unit => Vec::new(),
                    Fields::Unnamed(u) => u
                        .unnamed
                        .iter()
                        .map(|f| syn_type_to_typeref(&f.ty))
                        .collect(),
                    Fields::Named(n) => {
                        n.named.iter().map(|f| syn_type_to_typeref(&f.ty)).collect()
                    }
                };
                UnionCaseSpec {
                    name: v.ident.to_string(),
                    payload,
                    line: Some(v.ident.span().start().line),
                }
            })
            .collect();
        module.unions.push(UnionSpec {
            name,
            cases,
            file: Some(file_label.to_string()),
            line,
        });
    }
}

fn parse_contracterror_enum(file_label: &str, e: &ItemEnum, module: &mut ContractModule) {
    let name = e.ident.to_string();
    let line = Some(e.ident.span().start().line);
    let mut next_disc: u32 = 1;
    let mut variants = Vec::new();
    for v in &e.variants {
        if let Some((_, expr)) = &v.discriminant
            && let Some(val) = eval_u64_expr(expr, &HashMap::new())
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
    module.error_enums.push(ErrorEnumSpec {
        name,
        variants,
        file: Some(file_label.to_string()),
        line,
    });
}

fn parse_impl_block(
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
            let is_pub = matches!(method.vis, syn::Visibility::Public(_)) || imp.trait_.is_some();
            if is_contractimpl && is_pub {
                module
                    .functions
                    .push(extract_function_spec(file_label, method));
            }
            let parsed = analyze_impl_fn(
                file_label,
                source_lines,
                method,
                is_contractimpl && is_pub,
                is_pub,
                constants,
            );
            functions.push(parsed);
        }
    }
}

fn extract_function_spec(file_label: &str, method: &ImplItemFn) -> FunctionSpec {
    let name = method.sig.ident.to_string();
    let mut params = Vec::new();
    for input in &method.sig.inputs {
        if let FnArg::Typed(pat_ty) = input {
            let param_name = pat_to_ident_string(&pat_ty.pat).unwrap_or_else(|| "_".to_string());
            let ty_ref = syn_type_to_typeref(&pat_ty.ty);
            // Skip Soroban `Env` first parameter in exported contract specs (matches ScSpecFunctionV0)
            if matches!(&ty_ref, TypeRef::Custom(c) if c == "Env") {
                continue;
            }
            params.push(FunctionParamSpec {
                name: param_name,
                ty: ty_ref,
            });
        }
    }
    let return_type = match &method.sig.output {
        ReturnType::Default => TypeRef::Void,
        ReturnType::Type(_, ty) => {
            let converted = syn_type_to_typeref(ty);
            // In Soroban ScSpecFunctionV0, `Result<T, ContractError>` unwraps to `T` in the return spec
            if let TypeRef::Result { ok, .. } = converted {
                *ok
            } else {
                converted
            }
        }
    };
    FunctionSpec {
        name,
        params,
        return_type,
        file: Some(file_label.to_string()),
        line: Some(method.sig.ident.span().start().line),
    }
}

fn analyze_impl_fn(
    file_label: &str,
    source_lines: &[&str],
    method: &ImplItemFn,
    is_contract_entrypoint: bool,
    is_pub: bool,
    constants: &HashMap<String, u64>,
) -> ParsedFunction {
    let mut visitor = FnBodyAnalyzer::new(file_label, source_lines, constants);
    visitor.seed_fn_inputs(&method.sig.inputs);
    visitor.visit_block(&method.block);
    let span = method.sig.ident.span().start();
    ParsedFunction {
        name: method.sig.ident.to_string(),
        is_contract_entrypoint,
        is_pub,
        file: file_label.to_string(),
        line: span.line,
        column: span.column + 1,
        storage_ops: visitor.storage_ops,
        has_direct_require_auth: visitor.has_require_auth,
        wasm_upgrade_calls: visitor.wasm_upgrade_calls,
        called_functions: visitor.called_functions,
    }
}

fn analyze_free_fn(
    file_label: &str,
    source_lines: &[&str],
    func: &ItemFn,
    constants: &HashMap<String, u64>,
) -> ParsedFunction {
    let mut visitor = FnBodyAnalyzer::new(file_label, source_lines, constants);
    visitor.seed_fn_inputs(&func.sig.inputs);
    visitor.visit_block(&func.block);
    let span = func.sig.ident.span().start();
    let is_pub = matches!(func.vis, syn::Visibility::Public(_));
    ParsedFunction {
        name: func.sig.ident.to_string(),
        is_contract_entrypoint: false,
        is_pub,
        file: file_label.to_string(),
        line: span.line,
        column: span.column + 1,
        storage_ops: visitor.storage_ops,
        has_direct_require_auth: visitor.has_require_auth,
        wasm_upgrade_calls: visitor.wasm_upgrade_calls,
        called_functions: visitor.called_functions,
    }
}

struct FnBodyAnalyzer<'a> {
    source_lines: &'a [&'a str],
    constants: &'a HashMap<String, u64>,
    local_var_types: HashMap<String, TypeRef>,
    storage_ops: Vec<StorageOp>,
    has_require_auth: bool,
    wasm_upgrade_calls: Vec<WasmUpgradeCall>,
    called_functions: Vec<String>,
}

impl<'a> FnBodyAnalyzer<'a> {
    fn new(
        _file_label: &'a str,
        source_lines: &'a [&'a str],
        constants: &'a HashMap<String, u64>,
    ) -> Self {
        Self {
            source_lines,
            constants,
            local_var_types: HashMap::new(),
            storage_ops: Vec::new(),
            has_require_auth: false,
            wasm_upgrade_calls: Vec::new(),
            called_functions: Vec::new(),
        }
    }

    fn seed_fn_inputs(&mut self, inputs: &syn::punctuated::Punctuated<FnArg, syn::Token![,]>) {
        for arg in inputs {
            if let FnArg::Typed(pat_ty) = arg
                && let Some(ident) = pat_to_ident_string(&pat_ty.pat)
            {
                self.local_var_types
                    .insert(ident, syn_type_to_typeref(&pat_ty.ty));
            }
        }
    }

    fn line_snippet(&self, span: Span) -> (usize, usize, String) {
        let start = span.start();
        let line = start.line.max(1);
        let col = start.column + 1;
        let snippet = self
            .source_lines
            .get(line - 1)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        (line, col, snippet)
    }

    fn infer_expr_type(&self, expr: &Expr) -> Option<TypeRef> {
        match expr {
            Expr::Reference(r) => self.infer_expr_type(&r.expr),
            Expr::Paren(p) => self.infer_expr_type(&p.expr),
            Expr::Path(ep) => {
                if ep.path.segments.len() == 1 {
                    let var_name = ep.path.segments[0].ident.to_string();
                    self.local_var_types.get(&var_name).cloned()
                } else {
                    None
                }
            }
            Expr::Struct(es) => es
                .path
                .segments
                .last()
                .map(|seg| TypeRef::Custom(seg.ident.to_string())),
            Expr::Call(call) => infer_constructor_call_type(call),
            Expr::MethodCall(mc) => {
                let method = mc.method.to_string();
                if method == "clone" {
                    self.infer_expr_type(&mc.receiver)
                } else {
                    None
                }
            }
            Expr::Macro(mac) => {
                let name = mac
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                match name.as_str() {
                    "vec" => Some(TypeRef::Vec(Box::new(TypeRef::Val))),
                    "map" => Some(TypeRef::Map {
                        key: Box::new(TypeRef::Val),
                        value: Box::new(TypeRef::Val),
                    }),
                    "bytes" => Some(TypeRef::Bytes),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for FnBodyAnalyzer<'_> {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if let Stmt::Local(local) = stmt {
            match &local.pat {
                Pat::Type(pat_ty) => {
                    if let Some(var_name) = pat_to_ident_string(&pat_ty.pat) {
                        self.local_var_types
                            .insert(var_name, syn_type_to_typeref(&pat_ty.ty));
                    }
                }
                Pat::Ident(pat_ident) => {
                    if let Some(init) = &local.init
                        && let Some(inferred) = self.infer_expr_type(&init.expr)
                    {
                        self.local_var_types
                            .insert(pat_ident.ident.to_string(), inferred);
                    }
                }
                _ => {}
            }
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        // Visit receiver & arguments first so execution order (e.g. require_auth before update_wasm) is preserved!
        visit::visit_expr_method_call(self, node);

        let method_name = node.method.to_string();

        if method_name == "require_auth" || method_name == "require_auth_for_args" {
            self.has_require_auth = true;
            return;
        }

        if method_name == "update_current_contract_wasm" {
            let (line, column, snippet) = self.line_snippet(node.method.span());
            self.wasm_upgrade_calls.push(WasmUpgradeCall {
                line,
                column,
                snippet,
                auth_seen_before_call: self.has_require_auth,
            });
            return;
        }

        if let Some(tier) = detect_storage_tier_on_receiver(&node.receiver) {
            let op_kind = match method_name.as_str() {
                "set" => Some(StorageOpKind::Set),
                "update" => Some(StorageOpKind::Update),
                "extend_ttl" => Some(StorageOpKind::ExtendTtl),
                "get" => Some(StorageOpKind::Get),
                "remove" => Some(StorageOpKind::Remove),
                "has" => Some(StorageOpKind::Has),
                _ => None,
            };

            if let Some(kind) = op_kind {
                let (line, column, snippet) = self.line_snippet(node.method.span());
                let key_expr = node.args.first().map(expr_to_compact_string);
                let value_expr = node.args.get(1).map(expr_to_compact_string);
                let inferred_value_type =
                    node.args.get(1).and_then(|arg| self.infer_expr_type(arg));

                let ttl_bounds = if kind == StorageOpKind::ExtendTtl {
                    match tier {
                        StorageTier::Instance => {
                            let threshold = node
                                .args
                                .first()
                                .and_then(|e| eval_u64_expr(e, self.constants));
                            let extend_to = node
                                .args
                                .get(1)
                                .and_then(|e| eval_u64_expr(e, self.constants));
                            Some((threshold, extend_to))
                        }
                        StorageTier::Persistent | StorageTier::Temporary => {
                            let threshold = node
                                .args
                                .get(1)
                                .and_then(|e| eval_u64_expr(e, self.constants));
                            let extend_to = node
                                .args
                                .get(2)
                                .and_then(|e| eval_u64_expr(e, self.constants));
                            Some((threshold, extend_to))
                        }
                    }
                } else {
                    None
                };

                self.storage_ops.push(StorageOp {
                    tier,
                    kind,
                    key_expr,
                    value_expr,
                    inferred_value_type,
                    ttl_bounds,
                    line,
                    column,
                    snippet,
                });
            }
        } else {
            // Record helper method calls like `self.bump_ttl(&env)`
            self.called_functions.push(method_name);
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        visit::visit_expr_call(self, node);
        if let Expr::Path(ExprPath { path, .. }) = &*node.func
            && let Some(last) = path.segments.last()
        {
            self.called_functions.push(last.ident.to_string());
        }
    }
}

fn detect_storage_tier_on_receiver(receiver: &Expr) -> Option<StorageTier> {
    if let Expr::MethodCall(mc) = receiver {
        match mc.method.to_string().as_str() {
            "instance" => Some(StorageTier::Instance),
            "persistent" => Some(StorageTier::Persistent),
            "temporary" => Some(StorageTier::Temporary),
            _ => detect_storage_tier_on_receiver(&mc.receiver),
        }
    } else {
        None
    }
}

fn infer_constructor_call_type(call: &ExprCall) -> Option<TypeRef> {
    if let Expr::Path(ExprPath { path, .. }) = &*call.func {
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if segs.len() >= 2 {
            let type_seg = &segs[segs.len() - 2];
            match type_seg.as_str() {
                "Map" => {
                    return Some(TypeRef::Map {
                        key: Box::new(TypeRef::Val),
                        value: Box::new(TypeRef::Val),
                    });
                }
                "Vec" => return Some(TypeRef::Vec(Box::new(TypeRef::Val))),
                "Bytes" => return Some(TypeRef::Bytes),
                "String" => return Some(TypeRef::String),
                _ => {}
            }
        }
    }
    None
}

fn pat_to_ident_string(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Reference(pr) => pat_to_ident_string(&pr.pat),
        _ => None,
    }
}

fn expr_to_compact_string(expr: &Expr) -> String {
    match expr {
        Expr::Reference(r) => expr_to_compact_string(&r.expr),
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::Call(c) => {
            let func = expr_to_compact_string(&c.func);
            let args: Vec<String> = c.args.iter().map(expr_to_compact_string).collect();
            format!("{func}({})", args.join(", "))
        }
        Expr::Lit(lit) => match &lit.lit {
            Lit::Str(s) => s.value(),
            Lit::Int(i) => i.base10_digits().to_string(),
            _ => "literal".to_string(),
        },
        _ => "expr".to_string(),
    }
}

fn eval_u64_expr(expr: &Expr, constants: &HashMap<String, u64>) -> Option<u64> {
    match expr {
        Expr::Lit(lit) => {
            if let Lit::Int(int_lit) = &lit.lit {
                int_lit.base10_parse::<u64>().ok()
            } else {
                None
            }
        }
        Expr::Path(p) => {
            let ident = p.path.segments.last()?.ident.to_string();
            constants.get(&ident).copied()
        }
        Expr::Paren(p) => eval_u64_expr(&p.expr, constants),
        Expr::Binary(bin) => {
            let lhs = eval_u64_expr(&bin.left, constants)?;
            let rhs = eval_u64_expr(&bin.right, constants)?;
            match bin.op {
                syn::BinOp::Add(_) => lhs.checked_add(rhs),
                syn::BinOp::Sub(_) => lhs.checked_sub(rhs),
                syn::BinOp::Mul(_) => lhs.checked_mul(rhs),
                syn::BinOp::Div(_) => lhs.checked_div(rhs),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Converts a `syn::Type` from a Soroban Rust file into a normalized [`TypeRef`].
pub fn syn_type_to_typeref(ty: &Type) -> TypeRef {
    match ty {
        Type::Reference(r) => syn_type_to_typeref(&r.elem),
        Type::Paren(p) => syn_type_to_typeref(&p.elem),
        Type::Tuple(t) => {
            if t.elems.is_empty() {
                TypeRef::Void
            } else {
                TypeRef::Tuple(t.elems.iter().map(syn_type_to_typeref).collect())
            }
        }
        Type::Path(tp) => {
            let Some(seg) = tp.path.segments.last() else {
                return TypeRef::Val;
            };
            let ident = seg.ident.to_string();
            match ident.as_str() {
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
                "BytesN" => {
                    let len = extract_const_generic_u32(&seg.arguments).unwrap_or(32);
                    TypeRef::BytesN(len)
                }
                "String" => TypeRef::String,
                "Symbol" => TypeRef::Symbol,
                "Address" => TypeRef::Address,
                "Val" | "RawVal" => TypeRef::Val,
                "Error" => TypeRef::Error,
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
        _ => TypeRef::Val,
    }
}

fn extract_type_generics(args: &PathArguments) -> Vec<TypeRef> {
    if let PathArguments::AngleBracketed(ab) = args {
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
    } else {
        Vec::new()
    }
}

fn extract_const_generic_u32(args: &PathArguments) -> Option<u32> {
    if let PathArguments::AngleBracketed(ab) = args {
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
    }
    None
}
