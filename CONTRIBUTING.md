# Contributing to SORARK (`sorark`)

Thank you for contributing to **SORARK**! Whether you are joining us through a **Drips Stellar Wave** sprint or contributing independently to improve Stellar Soroban security and upgrade tooling, this guide covers everything you need to get productive quickly.

---

## 1. Development Environment Setup

### Requirements
* **Rust:** `1.87+` (Rust **2024 Edition**). Verify via `rustc --version`.
* **Clippy & Rustfmt:** `rustup component add clippy rustfmt`
* **Optional WASM Target (for compiling `examples/` contracts to `.wasm`):**
  ```bash
  rustup target add wasm32-unknown-unknown
  ```

### Verification Commands (Run Before Opening Any PR)
All three commands are enforced by GitHub Actions CI and **must pass with zero warnings**:

```bash
# 1. Check formatting across all workspace crates
cargo fmt --all -- --check

# 2. Run strict Clippy lints across all workspace crates and tests
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 3. Run all unit, integration, and doc tests
cargo test --workspace
```

---

## 2. How to Add a New Rule (Zero Merge-Conflict Design)

`sorark` is architected so each contributor can implement a new rule in its own single-responsibility module without colliding with other contributors:

### Adding an AST Storage / TTL / Security Rule (`sorark-ast`)
1. Create a new file under [`crates/sorark-ast/src/rules/`](./crates/sorark-ast/src/rules/) (for example, `crates/sorark-ast/src/rules/redundant_has.rs`).
2. Implement the [`AstRule`](./crates/sorark-ast/src/rules/mod.rs) trait (`id()`, `title()`, `category()`, `default_severity()`, `check()`) and construct findings using [`Diagnostic::builder`](./crates/sorark-ir/src/diagnostic/builder.rs).
3. Respect inline suppressions by checking `ctx.is_suppressed(&func.file, line, self.id())`.
4. Export and register your rule in `default_ast_rules()` inside [`crates/sorark-ast/src/rules/mod.rs`](./crates/sorark-ast/src/rules/mod.rs), and add its descriptor to `builtin_rule_catalog()` in [`crates/sorark-ir/src/diagnostic/catalog.rs`](./crates/sorark-ir/src/diagnostic/catalog.rs).
5. Add unit tests in [`crates/sorark-ast/src/lib.rs`](./crates/sorark-ast/src/lib.rs) covering both positive detection and safe/negative cases.

### Adding an Upgrade Compatibility Diff Rule (`sorark-diff`)
1. Create a new file under [`crates/sorark-diff/src/rules/`](./crates/sorark-diff/src/rules/) (for example, `crates/sorark-diff/src/rules/constructor_migration.rs`).
2. Implement the [`DiffRule`](./crates/sorark-diff/src/rule.rs) trait (`check_diff(&self, old: &ContractModule, new: &ContractModule, config: &SorarkConfig) -> Vec<Diagnostic>`).
3. Because [`ContractModule`](./crates/sorark-ir/src/model/contract_module.rs) is normalized across both Rust AST and `.wasm` `contractspecv0` XDR sections, your rule automatically works on both `.rs` and `.wasm` inputs!
4. Export the rule in [`crates/sorark-diff/src/rules/mod.rs`](./crates/sorark-diff/src/rules/mod.rs), register it in `default_diff_rules()` in [`crates/sorark-diff/src/rule.rs`](./crates/sorark-diff/src/rule.rs) and `builtin_rule_catalog()` in [`crates/sorark-ir/src/diagnostic/catalog.rs`](./crates/sorark-ir/src/diagnostic/catalog.rs), and add unit tests in [`crates/sorark-diff/src/lib.rs`](./crates/sorark-diff/src/lib.rs).

---

## 3. Coding Standards (Rust 2024 Best Practices)

* **`unsafe_code = "forbid"`**: No `unsafe` blocks are permitted anywhere in the workspace.
* **Single Responsibility & Small Functions**: Keep modules focused on a single concern and decompose complex passes or checks into small, well-named helper functions.
* **Documentation Comments**: Every module (`//!`), public struct/enum/trait, and function (`///`) should include clear Rustdoc comments explaining its role.
* **Error Handling**:
  * Library crates (`sorark-ir`, `sorark-ast`, `sorark-wasm`, `sorark-diff`) must return structured `Result<T, E>` using `thiserror` (`ConfigError`, `AstEngineError`, `WasmEngineError`). Never call `.unwrap()` or `.expect()` in non-test library code.
  * Only `sorark-cli` (`crates/sorark-cli`) uses `anyhow::Result` for top-level command execution.
* **Commit Messages**: Use Conventional Commits (`feat(ast): add ARK-STOR-005 ...`, `fix(diff): handle optional fields ...`, `refactor(wasm): ...`, `test(cli): ...`).

---

## 4. Drips Stellar Wave Guidelines

During active **Stellar Wave** sprints on [drips.network/wave/stellar](https://www.drips.network/wave/stellar):
1. Apply to the issue on Drips Wave and comment on the GitHub issue with your implementation plan.
2. Reference the issue number (`Closes #<id>`) in your Pull Request description.
3. Ensure every new feature or rule includes unit tests and updates `sorark rules` catalog metadata if applicable.
4. Keep PRs focused on the single assigned issue so maintainers can review and merge within 24 hours.
