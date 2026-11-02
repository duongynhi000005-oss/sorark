# SORARK Technical Design Specification

- **Project Name:** SORARK (`sorark`)
- **Tagline:** State Archival, Storage-Tier Safety, and Upgrade-Compatibility Analyzer for Stellar Soroban Smart Contracts
- **Rust Edition:** `2024` (`rustc >= 1.85`)
- **License:** MIT OR Apache-2.0

---

## 1. Problem Statement & Motivation

Stellar's Soroban smart contract platform introduces two protocol-level mechanics that differ fundamentally from EVM and other smart contract runtimes:

1. **Three-Tier State Archival & 64 KiB Ledger Entry Limits:**
   - Every Soroban ledger entry (`LedgerEntry`) is capped at **64 KiB (`65,536` bytes)**.
   - **Instance Storage (`env.storage().instance()`)** shares a single ledger entry with the contract instance itself and is loaded on *every* invocation. Storing unbounded collections (`Map`, `Vec`, `Bytes`, `String`) or structs transitively containing them inside `instance()` causes the contract to hit the 64 KiB ceiling and permanently brick.
   - **Persistent Storage (`env.storage().persistent()`)** and **Instance Storage** require explicit `extend_ttl(threshold, extend_to)` calls (`min_persistent_entry_ttl = 4,096` ledgers, `max_entry_ttl = 3,110,400` ledgers). Forgetting to extend TTL causes unexpected archival.
   - **Temporary Storage (`env.storage().temporary()`)** (`min_temp_entry_ttl = 16` ledgers) is **permanently deleted** upon expiration and cannot be restored via `RestoreFootprintOp`. Storing access-control keys (`Admin`, `Owner`, `Role`, `Paused`), balances, or nonces in `temporary()` creates critical state-reset vulnerabilities.

2. **In-Place WASM Bytecode Upgrades (`update_current_contract_wasm`) & `ScVal` Serialization:**
   - Soroban serializes `#[contracttype]` named structs as key-sorted `ScMap`s (keyed by field name `ScSymbol`), tuple structs as positional `ScVec`s, data enums as `ScSpecUdtUnionV0` tagged vectors, and unit enums as `u32` discriminants (`ScSpecUdtEnumV0`).
   - Mutating field names, field types, tuple ordering, or enum variants between `v1` and `v2` without an explicit state migration causes host deserialization traps on live on-chain ledger state.

---

## 2. Workspace Architecture

`sorark` is structured as a modular 5-crate Rust 2024 workspace plus 3 real `#![no_std]` Soroban smart contract packages under `examples/`:

```text
sorark/
├── Cargo.toml                     # Workspace root (Rust 2024, strict workspace lints)
├── crates/
│   ├── sorark-ir/                 # Normalized Soroban Contract IR, Diagnostics, & Config
│   ├── sorark-ast/                # Two-Pass `syn` v2 AST Semantic Analyzer & Storage/TTL Rules
│   ├── sorark-wasm/               # `wasmparser` + `stellar-xdr` SEP-0048 Spec Decoder & Budget Checks
│   ├── sorark-diff/               # Ledger Storage-Layout & ABI Upgrade Diff Engine (`v1` vs `v2`)
│   └── sorark-cli/                # `sorark` CLI binary + Text/JSON/SARIF/Markdown Formatters
└── examples/
    ├── vulnerable-vault/          # Real `soroban-sdk` contract triggering storage/TTL/auth rules
    ├── upgrade-v1/                # Baseline `soroban-sdk` vault contract (v1)
    └── upgrade-v2-broken/         # Mutated `soroban-sdk` vault contract (v2) with breaking storage/ABI
```

---

## 3. Core Components & Data Flow

### 3.1 `sorark-ir` (Normalized Contract Representation)
Provides a source-agnostic intermediate representation (`ContractModule`) populated identically from either Rust source files (`sorark-ast`) or compiled `.wasm` SEP-0048 custom sections (`sorark-wasm`):
- `StructSpec` (named fields mapped to `ScMap` `ScSymbol` keys)
- `TupleStructSpec` (positional fields mapped to `ScVec` indices)
- `EnumSpec` (`u32` discriminant cases mapped to `ScSpecUdtEnumV0`)
- `UnionSpec` (tagged union cases mapped to `ScSpecUdtUnionV0`)
- `ErrorEnumSpec` (`#[contracterror]` codes mapped to `ScSpecUdtErrorEnumV0`)
- `FunctionSpec` (exported contract entrypoints, parameter names/types, return type)
- `Diagnostic`, `Severity` (`Error`, `Warning`, `Info`), `Confidence` (`High`, `Medium`, `Low`), `SourceSpan`, and `SorarkConfig` (`sorark.toml`).

### 3.2 `sorark-ast` (Two-Pass Semantic AST Engine)
Uses `syn` (v2, `visit` + `full` + `extra-traits`) and `proc-macro2` (`span-locations`):
- **Pass 1 (Symbol & Call-Graph Discovery):**
  - Collects all `#[contracttype]` structs and enums across scanned files.
  - Computes **transitive unboundedness** (e.g., if `struct UserRecord` contains `Vec<u64>`, and `struct GlobalState` contains `UserRecord`, both are marked as transitively unbounded).
  - Builds an intra-module helper function summary recording which functions invoke `.extend_ttl(...)` (and on which storage tier) and which invoke `.require_auth()`.
  - Parses inline suppression comments (`// sorark-ignore: ARK-STOR-002`).
- **Pass 2 (Rule Execution via `AstRule` Trait):**
  - `ARK-STOR-001`: Unbounded type (`Map`, `Vec`, `Bytes`, `String`, or transitive unbounded struct/enum) stored in `env.storage().instance()`.
  - `ARK-STOR-002`: Mutation (`.set()`, `.update()`) on `persistent()` or `instance()` storage without a direct or helper-delegated `.extend_ttl()` call in the same execution flow.
  - `ARK-STOR-003`: Critical state key (`Admin`, `Owner`, `Balance`, `Allowance`, `Nonce`, `Paused`, `Role`, `Supply`, `Config`) written to `.temporary()` storage.
  - `ARK-STOR-004`: Invalid `extend_ttl(threshold, extend_to)` arguments (`threshold > extend_to`, `extend_to == 0`, or literal `extend_to > 3_110_400` Mainnet `max_entry_ttl`).
  - `ARK-UPG-001`: `update_current_contract_wasm` invoked without a dominating `require_auth()` check (direct or via helper).
  - `ARK-UPG-002`: Contract writes persistent/instance state and defines an admin/init flow but provides no `update_current_contract_wasm` upgrade mechanism.

### 3.3 `sorark-wasm` (Binary WASM & `stellar-xdr` SEP-0048 Decoder)
Uses `wasmparser` and `stellar-xdr` (`curr` channel):
- Extracts `contractspecv0`, `contractenvmetav0`, and `contractmetav0` custom sections.
- Decodes `ScSpecEntry` streams into `sorark_ir::ContractModule` and extracts `ScEnvMetaEntry` protocol version metadata.
- Evaluates `ARK-WASM-001` (WASM byte size budget warnings/errors against ledger limits and missing SEP-0048 sections).

### 3.4 `sorark-diff` (Upgrade & Storage-Layout Compatibility Engine)
Compares `old: &ContractModule` and `new: &ContractModule` via the `DiffRule` trait:
- `ARK-DIFF-001`: `#[contracttype]` struct layout incompatibly mutated (field removed, field renamed, field type changed, or positional tuple struct field reordered).
- `ARK-DIFF-002`: `#[contracttype]` enum/union incompatibly mutated (variant removed, unit enum discriminant shifted, or union payload arity/type changed).
- `ARK-DIFF-003`: Public contract function removed, parameter arity/type changed, or return type changed.
- `ARK-DIFF-004`: `#[contracterror]` variant removed or integer error code mutated.
- `ARK-DIFF-005`: Soroban environment protocol version regression or incompatible jump in `contractenvmetav0`.

### 3.5 `sorark-cli` (`sorark`)
Provides 5 subcommands (`lint`, `diff`, `inspect`, `rules`, `init`) and 4 output formats (`text`, `json`, `sarif`, `markdown`) with deterministic CI exit codes (`0` = pass, `1` = error findings, `2` = CLI/IO failure).

