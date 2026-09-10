//! Rebuild the public TN10 program commitments without private keys or RPC.
use kasmelt_harness::snapshot::{Snapshot, SnapshotNetworkPlan, SnapshotSource};
use kaspa_addresses::Address;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn standalone_compiler_reproduces_the_tn10_manifest_and_programs() {
    let evidence: Value =
        serde_json::from_str(include_str!("../../evidence/tn10-2026-08-26.json")).unwrap();
    let source: SnapshotSource = serde_json::from_value(evidence["source"].clone()).unwrap();
    for (name, bytes) in [
        (
            "token_contract",
            include_bytes!("../../contracts/kasmelt-snapshot-token.sil").as_slice(),
        ),
        (
            "controller_contract",
            include_bytes!("../../contracts/kasmelt-snapshot-controller.sil").as_slice(),
        ),
    ] {
        assert_eq!(
            hex::encode(Sha256::digest(bytes)),
            evidence["source_hashes"][name].as_str().unwrap()
        );
    }
    let snapshot = Snapshot::from_source(source).unwrap();
    assert_eq!(
        snapshot.manifest_json,
        evidence["manifest_json"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(snapshot.manifest_commitment),
        evidence["manifest_commitment"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(snapshot.initial_root),
        evidence["initial_root"].as_str().unwrap()
    );

    let authority = Address::try_from(evidence["authority_address"].as_str().unwrap()).unwrap();
    let owner: [u8; 32] = authority.payload.as_slice().try_into().unwrap();
    let root = snapshot.initial_root;
    let plan = SnapshotNetworkPlan::new(snapshot, owner).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(plan.token_program())),
        evidence["token_program_sha256"].as_str().unwrap()
    );

    let token_id: [u8; 32] = hex::decode(evidence["token_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let controller = plan.controller_program(token_id, root).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(controller)),
        evidence["controller_program_sha256"].as_str().unwrap()
    );
}
