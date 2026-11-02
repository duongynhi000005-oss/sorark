//! Synthetic Soroban WebAssembly binary encoder for unit and integration testing.
//!
//! Produces valid `.wasm` modules containing XDR-encoded `contractenvmetav0` and
//! `contractspecv0` custom sections without requiring an external `wasm32` toolchain.

use stellar_xdr::{Limits, ScEnvMetaEntry, ScSpecEntry, WriteXdr};

/// Builds a valid WebAssembly binary containing encoded `contractenvmetav0` and `contractspecv0`
/// custom sections from `ScSpecEntry` items.
///
/// # Errors
///
/// Returns [`stellar_xdr::Error`] if serializing any XDR entry fails.
pub fn encode_soroban_wasm_with_specs(
    protocol_version: u32,
    entries: &[ScSpecEntry],
) -> Result<Vec<u8>, stellar_xdr::Error> {
    // Standard 8-byte WebAssembly magic header + version 1 (`\0asm\x01\0\0\0`).
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    let env_entry = ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(
        stellar_xdr::ScEnvMetaEntryInterfaceVersion {
            protocol: protocol_version,
            pre_release: 0,
        },
    );
    let env_xdr = env_entry.to_xdr(Limits::none())?;
    append_wasm_custom_section(&mut wasm, "contractenvmetav0", &env_xdr);

    let mut spec_xdr = Vec::new();
    for entry in entries {
        spec_xdr.extend_from_slice(&entry.to_xdr(Limits::none())?);
    }
    append_wasm_custom_section(&mut wasm, "contractspecv0", &spec_xdr);

    Ok(wasm)
}

/// Appends a custom section (`id = 0`) with the given `name` and raw `payload` to `wasm`.
fn append_wasm_custom_section(wasm: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let name_bytes = name.as_bytes();
    let mut section_body = Vec::new();
    write_leb128_u32(&mut section_body, name_bytes.len() as u32);
    section_body.extend_from_slice(name_bytes);
    section_body.extend_from_slice(payload);

    wasm.push(0x00); // Custom section ID = 0
    write_leb128_u32(wasm, section_body.len() as u32);
    wasm.extend_from_slice(&section_body);
}

/// Encodes an unsigned 32-bit integer using unsigned LEB128 variable-length encoding.
fn write_leb128_u32(out: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
}
