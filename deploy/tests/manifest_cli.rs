use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_snapshot_manifest"))
}

#[test]
fn export_preserves_exact_archived_manifest_bytes_without_a_newline() {
    let result = command()
        .arg("build")
        .arg(root().join("fixtures/tn10-snapshot.json"))
        .output()
        .unwrap();
    assert!(result.status.success());
    let evidence: Value =
        serde_json::from_str(include_str!("../../evidence/tn10-2026-08-26.json")).unwrap();
    assert_eq!(
        result.stdout,
        evidence["manifest_json"].as_str().unwrap().as_bytes()
    );
    assert!(!result.stdout.ends_with(b"\n"));
}

#[test]
fn initial_proof_is_explicitly_scoped_and_bound_to_the_fixture() {
    let result = command()
        .arg("proof")
        .arg(root().join("fixtures/tn10-snapshot.json"))
        .arg("0")
        .output()
        .unwrap();
    assert!(result.status.success());
    let proof: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(proof["scope"]
        .as_str()
        .unwrap()
        .contains("initial snapshot root"));
    assert_eq!(proof["holder"]["index"], 0);
    assert_eq!(proof["proof"]["siblings"].as_array().unwrap().len(), 1);
}

#[test]
fn invalid_input_or_index_never_emits_a_manifest_or_proof() {
    for args in [
        vec!["build", "Cargo.toml"],
        vec!["proof", "fixtures/tn10-snapshot.json", "1"],
        vec!["proof", "fixtures/tn10-snapshot.json", "-1"],
    ] {
        let result = command().current_dir(root()).args(args).output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!result.stderr.is_empty());
    }
}
