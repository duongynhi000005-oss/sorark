use sorark_wasm::encode_soroban_wasm_with_specs;
use std::path::PathBuf;
use std::process::Command;
use stellar_xdr::{
    ScSpecEntry, ScSpecTypeDef, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM, VecM,
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn sorark_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sorark"))
}

#[test]
fn cli_lint_catches_all_hazards_in_vulnerable_vault_example() {
    let example_dir = workspace_root().join("examples/vulnerable-vault");
    let output = Command::new(sorark_bin())
        .args(["lint", example_dir.to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ARK-STOR-001"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-STOR-002"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-STOR-003"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-STOR-004"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-UPG-001"), "stdout: {stdout}");
}

#[test]
fn cli_lint_suggest_patch_emits_unified_diff_for_missing_extend_ttl() {
    let example_dir = workspace_root().join("examples/vulnerable-vault");
    let output = Command::new(sorark_bin())
        .args([
            "lint",
            example_dir.to_str().unwrap(),
            "--suggest-patch",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--- a/"), "Expected unified diff header in stdout: {stdout}");
    assert!(stdout.contains("+++ b/"), "Expected unified diff header in stdout: {stdout}");
    assert!(
        stdout.contains("+        env.storage().persistent().extend_ttl(&key, 4096, 16384);"),
        "Expected synthesized extend_ttl patch line in stdout: {stdout}"
    );
}

#[test]
fn cli_lint_passes_cleanly_on_upgrade_v1_example() {
    let example_dir = workspace_root().join("examples/upgrade-v1");
    let output = Command::new(sorark_bin())
        .args(["--deny-warnings", "lint", example_dir.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("0 error(s), 0 warning(s)"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_diff_catches_storage_and_abi_breakages_between_v1_and_v2_examples() {
    let v1_dir = workspace_root().join("examples/upgrade-v1");
    let v2_dir = workspace_root().join("examples/upgrade-v2-broken");

    let output = Command::new(sorark_bin())
        .args([
            "diff",
            "--old",
            v1_dir.to_str().unwrap(),
            "--new",
            v2_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-001"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-002"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-003"), "stdout: {stdout}");
    assert!(stdout.contains("ARK-DIFF-004"), "stdout: {stdout}");
}

#[test]
fn cli_sarif_and_wasm_binary_diff_work_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let v1_wasm_path = tmp.path().join("v1.wasm");
    let v2_wasm_path = tmp.path().join("v2.wasm");

    let v1_struct = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: StringM::try_from("Position").unwrap(),
        fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: StringM::try_from("shares").unwrap(),
            type_: ScSpecTypeDef::I128,
        }])
        .unwrap(),
    });

    let v2_struct = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: StringM::try_from("Position").unwrap(),
        fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: StringM::try_from("shares").unwrap(),
            type_: ScSpecTypeDef::U64,
        }])
        .unwrap(),
    });

    std::fs::write(
        &v1_wasm_path,
        encode_soroban_wasm_with_specs(22, &[v1_struct]).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &v2_wasm_path,
        encode_soroban_wasm_with_specs(22, &[v2_struct]).unwrap(),
    )
    .unwrap();

    // 1. Inspect v1.wasm
    let inspect_out = Command::new(sorark_bin())
        .args(["inspect", v1_wasm_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(inspect_out.status.code(), Some(0));
    let inspect_text = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(
        inspect_text.contains("Protocol 22"),
        "inspect: {inspect_text}"
    );
    assert!(
        inspect_text.contains("struct Position"),
        "inspect: {inspect_text}"
    );

    // 2. Diff v1.wasm vs v2.wasm in SARIF format
    let diff_out = Command::new(sorark_bin())
        .args([
            "diff",
            "--old",
            v1_wasm_path.to_str().unwrap(),
            "--new",
            v2_wasm_path.to_str().unwrap(),
            "--format",
            "sarif",
        ])
        .output()
        .unwrap();
    assert_eq!(diff_out.status.code(), Some(1));
    let sarif_json: serde_json::Value = serde_json::from_slice(&diff_out.stdout).unwrap();
    assert_eq!(sarif_json["version"], "2.1.0");
    assert_eq!(
        sarif_json["runs"][0]["results"][0]["ruleId"],
        "ARK-DIFF-001"
    );
}
