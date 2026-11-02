# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | :white_check_mark: Active |

## Threat Model & Scope

**SORARK** (`sorark`) processes untrusted inputs during static and binary analysis:
1. **Untrusted Rust Source Files (`.rs`):** Parsed purely as abstract syntax trees via `syn` (`proc-macro2`). `sorark` **never executes**, compiles, or expands arbitrary procedural macros or `build.rs` scripts from target repositories during `sorark lint` or `sorark diff`.
2. **Untrusted WebAssembly Binaries (`.wasm`):** Parsed via `wasmparser` and `stellar-xdr` with bounded XDR decoding (`stellar_xdr::curr::Limited`). `sorark` **never executes** untrusted WASM bytecode in a host runtime during `inspect` or `diff`.
3. **Memory Safety:** `#![forbid(unsafe_code)]` is enforced across all workspace crates via `[workspace.lints.rust]`.

### Known Security Boundaries
* Static AST analysis (`sorark-ast`) operates on intra-module syntax and two-pass symbol tables; it is not a replacement for formal verification or manual smart contract security audits prior to Stellar Mainnet deployment.

## Reporting a Vulnerability

If you discover a security vulnerability in `sorark` (such as an XDR parser denial-of-service, path traversal, or a critical false-negative bypass in a core storage/upgrade rule):

1. **Do NOT open a public GitHub issue.**
2. Use GitHub's **[Private Vulnerability Reporting](https://github.com/sorark-labs/sorark/security/advisories/new)** tab on the repository.
3. Include a minimal reproduction `.rs` snippet or `.wasm` fixture and the `sorark` version.
4. Maintainers will acknowledge receipt within **48 hours** and coordinate a patch release and advisory.
