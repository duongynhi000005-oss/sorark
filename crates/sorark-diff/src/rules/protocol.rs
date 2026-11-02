//! `ARK-DIFF-005`: Soroban environment protocol version mismatch in `contractenvmetav0`.

use crate::rule::DiffRule;
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, RuleCategory, Severity, SorarkConfig, SourceOrigin,
    SourceSpan,
};

/// Compares the `contractenvmetav0` Stellar protocol version between two compiled `.wasm`
/// binaries, flagging protocol downgrades as errors and protocol advances as informational notes.
pub struct ProtocolVersionDiffRule;

impl DiffRule for ProtocolVersionDiffRule {
    fn id(&self) -> &'static str {
        "ARK-DIFF-005"
    }

    fn title(&self) -> &'static str {
        "Soroban Environment Protocol Version Mismatch"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::AbiCompatibility
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        _config: &SorarkConfig,
    ) -> Vec<Diagnostic> {
        let (
            SourceOrigin::WasmBinary {
                protocol_version: Some(old_proto),
                ..
            },
            SourceOrigin::WasmBinary {
                path: new_path,
                protocol_version: Some(new_proto),
                ..
            },
        ) = (&old.origin, &new.origin)
        else {
            return Vec::new();
        };

        if new_proto < old_proto {
            vec![
                Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Error)
                    .confidence(Confidence::High)
                    .message(format!(
                        "WASM upgrade downgrades Soroban environment protocol version from Protocol {old_proto} (v1) to Protocol {new_proto} (v2)."
                    ))
                    .help("Compile the v2 contract with a `soroban-sdk` version targeting at least the v1 protocol version.")
                    .span(SourceSpan::new(new_path, 1, 1))
                    .build(),
            ]
        } else if new_proto > old_proto {
            vec![
                Diagnostic::builder(self.id(), self.title(), self.category(), Severity::Info)
                    .confidence(Confidence::High)
                    .message(format!(
                        "WASM upgrade advances Soroban environment protocol requirement from Protocol {old_proto} (v1) to Protocol {new_proto} (v2)."
                    ))
                    .help(format!(
                        "Verify that the target Stellar network has upgraded to Protocol {new_proto} before executing `update_current_contract_wasm`."
                    ))
                    .span(SourceSpan::new(new_path, 1, 1))
                    .build(),
            ]
        } else {
            Vec::new()
        }
    }
}
