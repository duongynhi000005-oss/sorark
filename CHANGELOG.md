# Changelog

All notable changes to **SORARK** (`sorark`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-02

### Added
- **`sorark-ir`:** Source-agnostic Soroban contract intermediate representation (`ContractModule`, `StructSpec`, `TupleStructSpec`, `EnumSpec`, `UnionSpec`, `ErrorEnumSpec`, `FunctionSpec`, `TypeRef`), transitive unbounded type graph resolver, diagnostic types, and `sorark.toml` configuration loader.
- **`sorark-ast`:** Two-pass `syn` v2 static analyzer with helper call-graph resolution (`extend_ttl`, `require_auth`), inline `// sorark-ignore:` comment support, and 6 built-in rules (`ARK-STOR-001` through `ARK-STOR-004`, `ARK-UPG-001`, `ARK-UPG-002`).
- **`sorark-wasm`:** Binary WebAssembly inspector using `wasmparser` and `stellar-xdr` to decode `contractspecv0` (`ScSpecEntry`), `contractenvmetav0` (`ScEnvMetaEntry`), and `contractmetav0` (`ScMetaEntry`) custom sections, plus `ARK-WASM-001` ledger byte budget verification.
- **`sorark-diff`:** Storage-layout (`ScMap`/`ScVec`/`ScSpecUdtUnionV0`) and ABI upgrade compatibility engine (`ARK-DIFF-001` through `ARK-DIFF-005`) comparing `v1` and `v2` contracts across `.rs` and `.wasm` targets.
- **`sorark-cli` (`sorark`):** Command-line binary supporting `lint`, `diff`, `inspect`, `rules`, and `init` with `text`, `json`, `sarif` (v2.1.0), and `markdown` output formats.
- **`examples/`:** Three real `#![no_std]` Soroban smart contracts (`vulnerable-vault`, `upgrade-v1`, `upgrade-v2-broken`) using `soroban-sdk`.
