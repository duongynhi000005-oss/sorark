//! WebAssembly section walker and SEP-0048 custom section XDR stream decoders.
//!
//! Iterates over WebAssembly payloads via `wasmparser` and decodes the three standard
//! Soroban custom sections (`contractspecv0`, `contractenvmetav0`, and `contractmetav0`).

use crate::error::WasmEngineError;
use crate::metrics::WasmMetrics;
use std::io::Cursor;
use stellar_xdr::{Limited, Limits, ReadXdr, ScEnvMetaEntry, ScMetaEntry, ScSpecEntry};
use wasmparser::{
    CustomSectionReader, ExportSectionReader, ExternalKind, ImportSectionReader,
    MemorySectionReader, Parser, Payload,
};

/// Walks all WebAssembly sections in `bytes`, populating `metrics` and returning
/// every [`ScSpecEntry`] decoded from the `contractspecv0` custom section.
pub(crate) fn parse_wasm_sections(
    path_label: &str,
    bytes: &[u8],
    metrics: &mut WasmMetrics,
) -> Result<Vec<ScSpecEntry>, WasmEngineError> {
    let mut spec_entries = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|err| WasmEngineError::WasmParse {
            path: path_label.to_string(),
            message: err.to_string(),
        })?;

        match payload {
            Payload::ImportSection(reader) => record_imports(path_label, reader, metrics)?,
            Payload::ExportSection(reader) => record_exports(path_label, reader, metrics)?,
            Payload::MemorySection(reader) => record_memory(path_label, reader, metrics)?,
            Payload::CustomSection(section) => {
                decode_custom_section(path_label, &section, metrics, &mut spec_entries)?;
            }
            _ => {}
        }
    }

    Ok(spec_entries)
}

/// Counts host imports declared in the WebAssembly Import section.
fn record_imports(
    path_label: &str,
    reader: ImportSectionReader<'_>,
    metrics: &mut WasmMetrics,
) -> Result<(), WasmEngineError> {
    for import in reader {
        let _ = import.map_err(|err| WasmEngineError::WasmParse {
            path: path_label.to_string(),
            message: err.to_string(),
        })?;
        metrics.import_count += 1;
    }
    Ok(())
}

/// Counts exports and records exported function names from the WebAssembly Export section.
fn record_exports(
    path_label: &str,
    reader: ExportSectionReader<'_>,
    metrics: &mut WasmMetrics,
) -> Result<(), WasmEngineError> {
    for export in reader {
        let export = export.map_err(|err| WasmEngineError::WasmParse {
            path: path_label.to_string(),
            message: err.to_string(),
        })?;
        metrics.export_count += 1;
        if export.kind == ExternalKind::Func {
            metrics.exported_functions.push(export.name.to_string());
        }
    }
    Ok(())
}

/// Extracts initial and maximum linear memory page bounds from the WebAssembly Memory section.
fn record_memory(
    path_label: &str,
    reader: MemorySectionReader<'_>,
    metrics: &mut WasmMetrics,
) -> Result<(), WasmEngineError> {
    for mem in reader {
        let mem = mem.map_err(|err| WasmEngineError::WasmParse {
            path: path_label.to_string(),
            message: err.to_string(),
        })?;
        metrics.initial_memory_pages = Some(mem.initial);
        metrics.max_memory_pages = mem.maximum;
    }
    Ok(())
}

/// Dispatches SEP-0048 custom sections (`contractspecv0`, `contractenvmetav0`, `contractmetav0`)
/// to their respective XDR stream decoders.
fn decode_custom_section(
    path_label: &str,
    section: &CustomSectionReader<'_>,
    metrics: &mut WasmMetrics,
    spec_entries: &mut Vec<ScSpecEntry>,
) -> Result<(), WasmEngineError> {
    match section.name() {
        "contractspecv0" => {
            metrics.has_contractspecv0 = true;
            decode_contractspecv0(path_label, section.data(), spec_entries)?;
        }
        "contractenvmetav0" => {
            metrics.has_contractenvmetav0 = true;
            decode_contractenvmetav0(path_label, section.data(), metrics)?;
        }
        "contractmetav0" => {
            metrics.has_contractmetav0 = true;
            decode_contractmetav0(path_label, section.data(), metrics)?;
        }
        _ => {}
    }
    Ok(())
}

/// Decodes a stream of [`ScSpecEntry`] records from `contractspecv0`.
fn decode_contractspecv0(
    path_label: &str,
    data: &[u8],
    spec_entries: &mut Vec<ScSpecEntry>,
) -> Result<(), WasmEngineError> {
    let mut limited = Limited::new(Cursor::new(data), Limits::none());
    for entry_res in ScSpecEntry::read_xdr_iter(&mut limited) {
        let entry = entry_res.map_err(|source| WasmEngineError::XdrDecode {
            path: path_label.to_string(),
            section: "contractspecv0",
            source,
        })?;
        spec_entries.push(entry);
    }
    Ok(())
}

/// Decodes [`ScEnvMetaEntry`] records from `contractenvmetav0` to extract the target Stellar
/// protocol version and pre-release number.
fn decode_contractenvmetav0(
    path_label: &str,
    data: &[u8],
    metrics: &mut WasmMetrics,
) -> Result<(), WasmEngineError> {
    let mut limited = Limited::new(Cursor::new(data), Limits::none());
    for entry_res in ScEnvMetaEntry::read_xdr_iter(&mut limited) {
        let entry = entry_res.map_err(|source| WasmEngineError::XdrDecode {
            path: path_label.to_string(),
            section: "contractenvmetav0",
            source,
        })?;
        match entry {
            ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(iv) => {
                metrics.protocol_version = Some(iv.protocol);
                metrics.pre_release_version = Some(iv.pre_release);
            }
        }
    }
    Ok(())
}

/// Decodes key-value [`ScMetaEntry`] records from `contractmetav0` (`rsver`, `rssdkver`).
fn decode_contractmetav0(
    path_label: &str,
    data: &[u8],
    metrics: &mut WasmMetrics,
) -> Result<(), WasmEngineError> {
    let mut limited = Limited::new(Cursor::new(data), Limits::none());
    for entry_res in ScMetaEntry::read_xdr_iter(&mut limited) {
        let entry = entry_res.map_err(|source| WasmEngineError::XdrDecode {
            path: path_label.to_string(),
            section: "contractmetav0",
            source,
        })?;
        match entry {
            ScMetaEntry::ScMetaV0(meta) => {
                let key = meta.key.to_utf8_string_lossy();
                let val = meta.val.to_utf8_string_lossy();
                if key == "rsver" {
                    metrics.rustc_version = Some(val);
                } else if key == "rssdkver" {
                    metrics.rs_soroban_env_version = Some(val);
                }
            }
        }
    }
    Ok(())
}
