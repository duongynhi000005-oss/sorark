# SORARK — Drips Stellar Wave Maintainer & Contributor Blueprint

This document tracks **SORARK's** compliance with the **[Drips Stellar Wave Program](https://www.drips.network/wave/stellar)** maintainer standards and provides our curated queue of **18 pre-scoped Wave tasks** mapped to Drips point tiers (**Trivial = 100 pts**, **Medium = 150 pts**, **High = 200 pts**).

---

## 1. Repository Quality & Onboarding Checklist

- [x] **GitHub Organization Ownership:** Hosted under the dedicated GitHub Organization [`sorark-labs/sorark`](https://github.com/sorark-labs/sorark).
- [x] **Open-Source License:** Dual-licensed under MIT / Apache-2.0 ([`LICENSE`](./LICENSE)).
- [x] **Genuine Stellar / Soroban Integration:**
  - Directly decodes Stellar SEP-0048 XDR (`stellar-xdr` v30 `ScSpecEntry`, `ScEnvMetaEntry`, `ScMetaEntry`) from compiled `.wasm` contracts ([`crates/sorark-wasm`](./crates/sorark-wasm)).
  - Models Soroban's three-tier State Archival (`Instance`, `Persistent`, `Temporary`), 64 KiB ledger entry limits, and `ScMap`/`ScVec` upgrade compatibility ([`crates/sorark-ast`](./crates/sorark-ast), [`crates/sorark-diff`](./crates/sorark-diff)).
  - Bundles 3 real `#![no_std]` Soroban smart contracts ([`examples/vulnerable-vault`](./examples/vulnerable-vault), [`examples/upgrade-v1`](./examples/upgrade-v1), [`examples/upgrade-v2-broken`](./examples/upgrade-v2-broken)) built with `soroban-sdk`.
- [x] **Repository Hygiene Files:** [`README.md`](./README.md), [`CONTRIBUTING.md`](./CONTRIBUTING.md), [`SECURITY.md`](./SECURITY.md), [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md), [`CHANGELOG.md`](./CHANGELOG.md), and `.github/` templates.
- [x] **Green Automated CI Gates:** [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) enforcing `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test --workspace`.

---

## 2. Pre-Scoped Drips Stellar Wave Issue Backlog (18 Ready-to-Open Tasks)

Each task below is designed to be self-contained, testable within a 7-day Wave sprint, and isolated to specific modules so multiple contributors can work in parallel without merge conflicts.

### Tier 1: Trivial Complexity (100 Points)

#### Issue 1: Add `--min-severity <info|warning|error>` filter flag to `sorark lint` and `sorark diff`
* **Complexity:** Trivial (100 pts)
* **Target Files:** `crates/sorark-cli/src/cli.rs`, `crates/sorark-cli/src/commands.rs`, `crates/sorark-cli/tests/cli_integration.rs`
* **Scope:** Add a `--min-severity` CLI flag so users can filter out `info` or `warning` findings from terminal/JSON/SARIF output.
* **Acceptance Criteria:** `sorark lint examples/vulnerable-vault --min-severity error` outputs only `Error`-level diagnostics and passes new CLI integration tests.

#### Issue 2: Add `--explain <RULE_ID>` flag to `sorark rules` with vulnerable vs. fixed code examples
* **Complexity:** Trivial (100 pts)
* **Target Files:** `crates/sorark-ir/src/diagnostic/catalog.rs`, `crates/sorark-cli/src/cli.rs`, `crates/sorark-cli/src/commands.rs`
* **Scope:** Extend `RuleDescriptor` with `bad_example` and `good_example` Rust snippets and add `sorark rules --explain ARK-STOR-001`.
* **Acceptance Criteria:** Running `sorark rules --explain ARK-STOR-001` prints a detailed explanation and side-by-side code examples.

#### Issue 3: Add `ARK-WASM-002` to detect excessive exported function count or oversized WASM memory pages
* **Complexity:** Trivial (100 pts)
* **Target Files:** `crates/sorark-wasm/src/budget.rs`, `crates/sorark-ir/src/config/mod.rs`
* **Scope:** Check `WasmMetrics.initial_memory_pages` (> 16 pages / 1 MiB) and `export_count` against configurable thresholds in `sorark.toml`.
* **Acceptance Criteria:** Unit test in `sorark-wasm` verifies warning diagnostic when a synthetic WASM binary declares > 16 initial linear memory pages.

#### Issue 4: Support `[rules.<RULE_ID>] severity = "..."` per-rule severity overrides in `sorark.toml`
* **Complexity:** Trivial (100 pts)
* **Target Files:** `crates/sorark-ir/src/config/mod.rs`, `crates/sorark-ast/src/scanner.rs`, `crates/sorark-diff/src/report.rs`
* **Scope:** Allow users to promote a `Warning` rule (like `ARK-STOR-002`) to `Error` or demote it to `Info` via `sorark.toml`.
* **Acceptance Criteria:** Unit test verifies custom severity mapping from TOML configuration.

#### Issue 5: Add GitHub Actions annotation output format (`--format github`)
* **Complexity:** Trivial (100 pts)
* **Target Files:** `crates/sorark-cli/src/format/mod.rs`, `crates/sorark-cli/src/format/github.rs`, `crates/sorark-cli/tests/cli_integration.rs`
* **Scope:** Implement `OutputFormat::Github` emitting `::error file={file},line={line},col={col},title={rule_id}::{message}` workflow commands.
* **Acceptance Criteria:** Integration test verifies exact GitHub Actions workflow command syntax.

#### Issue 6: Add summary statistics table (`structs`, `enums`, `unions`, `entrypoints`) to `sorark inspect --format markdown`
* **Complexity:** Trivial (100 pts)
* **Target Files:** `crates/sorark-cli/src/format/inspect.rs`, `crates/sorark-cli/src/format/mod.rs`
* **Scope:** Format `sorark inspect <file.wasm> --format markdown` with clean GitHub Flavored Markdown tables instead of plain text lists.
* **Acceptance Criteria:** Unit test verifies Markdown table headers for structs, unions, and functions.

---

### Tier 2: Medium Complexity (150 Points)

#### Issue 7: Implement `ARK-STOR-005`: Detect Redundant Ledger Read-Before-Write (`has` followed by `get` on identical key)
* **Complexity:** Medium (150 pts)
* **Target Files:** `crates/sorark-ast/src/rules/redundant_has.rs`, `crates/sorark-ast/src/rules/mod.rs`, `crates/sorark-ir/src/diagnostic/catalog.rs`
* **Scope:** Calling `env.storage().persistent().has(&key)` immediately followed by `env.storage().persistent().get(&key)` performs redundant host map lookups compared to matching on `get(&key)`.
* **Acceptance Criteria:** New `RedundantHasBeforeGetRule` (`ARK-STOR-005`) detects `has(&k)` + `get(&k)` on the same key expression within a function body.

#### Issue 8: Implement `ARK-STOR-006`: Detect Unbounded Loop Over Storage Reads/Writes (`for` / `while` containing `env.storage()`)
* **Complexity:** Medium (150 pts)
* **Target Files:** `crates/sorark-ast/src/parser/body.rs`, `crates/sorark-ast/src/rules/loop_storage.rs`, `crates/sorark-ast/src/rules/mod.rs`
* **Scope:** Track loop nesting depth in `FnBodyAnalyzer`. Flag `persistent()` or `temporary()` reads/writes inside loops, which quickly exceed Soroban's per-transaction ledger footprint entry limits.
* **Acceptance Criteria:** `ARK-STOR-006` triggers when `env.storage().persistent().set(...)` or `.get(...)` occurs inside `ExprForLoop` or `ExprWhile`.

#### Issue 9: Implement `ARK-SEP-041`: SEP-41 Token Interface Conformance Checker
* **Complexity:** Medium (150 pts)
* **Target Files:** `crates/sorark-ir/src/model/sep41.rs`, `crates/sorark-cli/src/commands.rs`
* **Scope:** Add a checker verifying whether a `ContractModule` (from `.rs` or `.wasm`) implements the standard Stellar SEP-41 token interface (`allowance`, `approve`, `balance`, `transfer`, `transfer_from`, `burn`, `burn_from`, `decimals`, `name`, `symbol`) with exact parameter and return types.
* **Acceptance Criteria:** Detects missing or mistyped SEP-41 functions (e.g., `balance(id: Address) -> i128`).

#### Issue 10: Implement `ARK-STOR-007`: Detect Symbol Key Length > 32 Characters in `symbol_short!` / `Symbol::new`
* **Complexity:** Medium (150 pts)
* **Target Files:** `crates/sorark-ast/src/parser/body.rs`, `crates/sorark-ast/src/rules/symbol_length.rs`
* **Scope:** `symbol_short!` only supports up to 9 characters (`[a-zA-Z0-9_]`), and `Symbol::new` traps at runtime if the string exceeds 32 characters.
* **Acceptance Criteria:** Static rule flags invalid characters or lengths in `symbol_short!` and `Symbol::new(&env, "...")` literals.

#### Issue 11: Implement `ARK-UPG-003`: Detect `__constructor` Re-Initialization Logic Assumed During WASM Upgrades
* **Complexity:** Medium (150 pts)
* **Target Files:** `crates/sorark-diff/src/rules/constructor_migration.rs`, `crates/sorark-diff/src/rules/mod.rs`, `crates/sorark-diff/src/rule.rs`
* **Scope:** Soroban does not re-run `__constructor` when `update_current_contract_wasm` upgrades a live contract. Flag when `v2` modifies `__constructor` parameters or adds new `__constructor` arguments without a `migrate` entrypoint.
* **Acceptance Criteria:** Diffing `v1` and `v2` where `__constructor` signature changes without a `migrate` function emits `ARK-UPG-003`.

#### Issue 12: Add `examples/sep41-token` Real `#![no_std]` Soroban Token Contract Example
* **Complexity:** Medium (150 pts)
* **Target Files:** `examples/sep41-token/Cargo.toml`, `examples/sep41-token/src/lib.rs`
* **Scope:** Create a complete, `sorark`-clean SEP-41 compliant Soroban token contract under `examples/sep41-token` with unit tests and integration tests in `sorark-cli`.
* **Acceptance Criteria:** `sorark --deny-warnings lint examples/sep41-token` passes with 0 errors and 0 warnings.

---

### Tier 3: High Complexity (200 Points)

#### Issue 13: Implement Git Revision Diffing (`sorark diff --old-rev <git-ref> --new-rev <git-ref>`)
* **Complexity:** High (200 pts)
* **Target Files:** `crates/sorark-cli/src/cli.rs`, `crates/sorark-cli/src/commands.rs`
* **Scope:** Allow `sorark diff --old-rev main --new-rev HEAD --path ./contracts/vault` to extract Rust source files from two git revisions without requiring manual directory copies.
* **Acceptance Criteria:** Integration test creates a temporary git repo with 2 commits and verifies `sorark diff --old-rev HEAD~1 --new-rev HEAD` catches breaking storage mutations.

#### Issue 14: Implement Cross-File Workspace Call-Graph Resolution in `sorark-ast`
* **Complexity:** High (200 pts)
* **Target Files:** `crates/sorark-ast/src/parser/context.rs`, `crates/sorark-ast/src/parser/body.rs`, `crates/sorark-ast/src/lib.rs`
* **Scope:** Extend `AstAnalysisContext` so module-qualified calls (`storage_utils::bump_instance(&env)`, `auth::require_admin(&env)`) across multiple `.rs` files in a multi-file contract resolve accurately in Pass 2.
* **Acceptance Criteria:** Multi-file contract test (`lib.rs` + `storage.rs` + `auth.rs`) resolves helper TTL and auth checks across module paths with zero false positives.

#### Issue 15: Implement On-Chain Ledger Entry Byte Size Estimator (`ARK-FOOT-001`) for `#[contracttype]` Structs & Keys
* **Complexity:** High (200 pts)
* **Target Files:** `crates/sorark-ir/src/model/`, `crates/sorark-ast/src/rules/`
* **Scope:** Calculate the exact XDR serialized byte overhead of fixed-size `#[contracttype]` structs (`ScMap` header + `ScSymbol` field key lengths + `ScVal` field payloads) and warn when large fixed arrays/structs approach the 64 KiB ledger entry ceiling.
* **Acceptance Criteria:** Unit test verifies exact XDR byte size estimation for nested `#[contracttype]` structs and `BytesN<N>` fields.

#### Issue 16: Decode `ScSpecEntry::EventV0` (`#[contractevent]`) and Add `ARK-DIFF-006` Event Schema Compatibility Rule
* **Complexity:** High (200 pts)
* **Target Files:** `crates/sorark-ir/src/model/specs.rs`, `crates/sorark-wasm/src/convert.rs`, `crates/sorark-diff/src/rules/`
* **Scope:** Parse Soroban contract events (`#[contractevent]` and `ScSpecEntry::EventV0`) into `ContractModule` and detect breaking event topic/data schema changes between `v1` and `v2` that break off-chain indexers.
* **Acceptance Criteria:** Changing an event's topic count or payload struct between `v1` and `v2` triggers `ARK-DIFF-006`.

#### Issue 17: Implement `sorark lint --suggest-patch` Auto-Remediation Suggestions for Missing `extend_ttl`
* **Complexity:** High (200 pts)
* **Target Files:** `crates/sorark-ast/src/rules/missing_ttl.rs`, `crates/sorark-cli/src/commands.rs`
* **Scope:** Generate unified diff patches inserting standard `extend_ttl` calls after unextended `instance().set(...)` or `persistent().set(...)` statements.
* **Acceptance Criteria:** Running `sorark lint examples/vulnerable-vault --suggest-patch` outputs a valid unified diff patch for `ARK-STOR-002` findings.

#### Issue 18: Build Reusable Composite GitHub Action (`action.yml`) for CI Pull Request Upgrade Diffing
* **Complexity:** High (200 pts)
* **Target Files:** `action.yml`, `README.md`, `.github/workflows/ci.yml`
* **Scope:** Create a turnkey root `action.yml` so any Stellar Soroban repository can add `uses: sorark-labs/sorark@v0.1` in their GitHub Actions workflow to run `sorark lint` and upload SARIF results automatically.
* **Acceptance Criteria:** `action.yml` is self-tested inside `.github/workflows/ci.yml`.
