//! Executable proof for the one-time snapshot migration path.
//!
//! Claims and adversarial transactions execute against the pinned Kaspa script engine.

use kasmelt_harness::snapshot::{
    demo_source, ClaimTamper, LiveUtxo, Snapshot, SnapshotLab, SnapshotNetworkPlan, SourceHolder,
    LIVE_TN10_FEE,
};
use kaspa_addresses::{Address, Prefix, Version as AddressVersion};
use kaspa_consensus_core::{
    hashing::tx::id as transaction_id,
    tx::{MutableTransaction, Transaction, TransactionOutpoint, UtxoEntry},
};
use kaspa_txscript::pay_to_address_script;
use secp256k1::{Keypair, SECP256K1};

fn lab() -> SnapshotLab {
    SnapshotLab::new(Snapshot::from_source(demo_source()).expect("demo snapshot validates"))
        .expect("contracts compile and templates resolve")
}

fn demo_owner_key(owner: [u8; 32]) -> Keypair {
    (10u8..14)
        .map(|seed| {
            let mut secret = [0u8; 32];
            secret[31] = seed;
            Keypair::from_seckey_slice(SECP256K1, &secret).unwrap()
        })
        .find(|key| key.x_only_public_key().0.serialize() == owner)
        .expect("demo holder key is known")
}

fn test_key(seed: u8) -> Keypair {
    let mut secret = [0u8; 32];
    secret[31] = seed;
    Keypair::from_seckey_slice(SECP256K1, &secret).unwrap()
}

fn plain_live(key: &Keypair, byte: u8, amount: u64) -> LiveUtxo {
    let owner = key.x_only_public_key().0.serialize();
    LiveUtxo {
        outpoint: TransactionOutpoint::new([byte; 32].into(), 0),
        entry: UtxoEntry::new(
            amount,
            pay_to_address_script(&Address::new(
                Prefix::Testnet,
                AddressVersion::PubKey,
                &owner,
            )),
            100,
            false,
            None,
        ),
    }
}

fn live_output(tx: &MutableTransaction<Transaction>, index: usize) -> LiveUtxo {
    let output = &tx.tx.outputs[index];
    LiveUtxo {
        outpoint: TransactionOutpoint::new(transaction_id(&tx.tx), index as u32),
        entry: UtxoEntry::new(
            output.value,
            output.script_public_key.clone(),
            101 + index as u64,
            false,
            output.covenant.map(|binding| binding.covenant_id),
        ),
    }
}

fn script_hash_source(count: u32) -> kasmelt_harness::snapshot::SnapshotSource {
    let mut source = demo_source();
    source.holders = (0..count)
        .map(|index| {
            let mut owner = [0u8; 32];
            owner[..4].copy_from_slice(&index.to_le_bytes());
            owner[31] = 0xa5;
            SourceHolder {
                address: Address::new(Prefix::Testnet, AddressVersion::ScriptHash, &owner)
                    .to_string(),
                amount: "1".to_string(),
            }
        })
        .collect();
    source
}

#[test]
fn snapshot_is_deterministic_under_input_reordering() {
    let source = demo_source();
    let a = Snapshot::from_source(source.clone()).unwrap();
    let mut reversed = source;
    reversed.holders.reverse();
    let b = Snapshot::from_source(reversed).unwrap();
    assert_eq!(a.initial_root, b.initial_root);
    assert_eq!(a.manifest_commitment, b.manifest_commitment);
    assert_eq!(a.manifest_json, b.manifest_json);
}

#[test]
fn demo_snapshot_has_pinned_golden_commitments() {
    let snapshot = Snapshot::from_source(demo_source()).unwrap();
    assert_eq!(
        hex::encode(snapshot.initial_root),
        "2bd10ce7e683ae276b00f5fb744ce867925d09781c908592ef4fd028039ed91a"
    );
    assert_eq!(
        hex::encode(snapshot.manifest_commitment),
        "efc1a6cb806f1d471b92f03857883f33c4bb9eb14b0d2cac9ed85b3b5f7070f2"
    );
}

#[test]
fn genesis_controller_and_signed_reserve_handoff_pass_and_are_block_legal() {
    let lab = lab();
    assert!(lab.setup.all_pass());
    for stage in [
        &lab.setup.token_genesis,
        &lab.setup.controller_genesis,
        &lab.setup.reserve_handoff,
    ] {
        assert!(stage.pass, "{}: {}", stage.label, stage.verdict);
        assert!(stage.mass.block_legal, "{} exceeds mass", stage.label);
        assert!(
            stage.mass.lab_fee_estimate_covered,
            "{} underfunds the conservative lab fee estimate",
            stage.label
        );
        assert!(!stage.transaction_id.chars().all(|ch| ch == '0'));
    }
    assert_eq!(lab.setup.reserve_handoff.input_script_units.len(), 2);
}

#[test]
fn live_builder_prepares_the_exact_five_stage_chain_from_confirmed_inputs() {
    let funding_key = test_key(200);
    let authority_key = test_key(201);
    let claimant_key = test_key(202);
    let claimant_owner = claimant_key.x_only_public_key().0.serialize();
    let mut source = demo_source();
    source.ticker = "TN10POC".to_string();
    source.checkpoint.indexer = "synthetic-test-vector/no-krc-indexer".to_string();
    source.holders = vec![SourceHolder {
        address: Address::new(Prefix::Testnet, AddressVersion::PubKey, &claimant_owner).to_string(),
        amount: "1000000".to_string(),
    }];
    let snapshot = Snapshot::from_source(source).unwrap();
    let plan = SnapshotNetworkPlan::new(snapshot, authority_key.x_only_public_key().0.serialize())
        .unwrap();

    let stage1 = plan
        .prepare_token_genesis(
            plain_live(&funding_key, 0xa1, 100_000_000_000),
            &funding_key,
            LIVE_TN10_FEE,
        )
        .unwrap();
    assert!(stage1.prepared.evidence.pass);
    let token_cell = live_output(&stage1.prepared.transaction, 0);
    let change1 = live_output(&stage1.prepared.transaction, 1);

    let stage2 = plan
        .prepare_controller_genesis(stage1.token_id, change1, &funding_key, LIVE_TN10_FEE)
        .unwrap();
    assert!(stage2.prepared.evidence.pass);
    let controller_cell = live_output(&stage2.prepared.transaction, 0);
    let change2 = live_output(&stage2.prepared.transaction, 1);

    let stage3 = plan
        .prepare_reserve_handoff(
            stage1.token_id,
            stage2.controller_id,
            token_cell,
            change2,
            &authority_key,
            &funding_key,
            LIVE_TN10_FEE,
        )
        .unwrap();
    assert!(stage3.prepared.evidence.pass);
    let reserve_cell = live_output(&stage3.prepared.transaction, 0);
    let change3 = live_output(&stage3.prepared.transaction, 1);

    let stage4 = plan
        .prepare_claim(
            stage1.token_id,
            stage2.controller_id,
            0,
            controller_cell,
            reserve_cell,
            change3,
            &funding_key,
            LIVE_TN10_FEE,
        )
        .unwrap();
    assert!(stage4.prepared.evidence.pass);
    assert_eq!(stage4.reserve_amount_after, 0);
    let recipient_cell = live_output(&stage4.prepared.transaction, 1);
    let change4 = live_output(&stage4.prepared.transaction, 3);

    let stage5 = plan
        .prepare_recipient_split(
            stage1.token_id,
            0,
            recipient_cell,
            change4,
            &claimant_key,
            funding_key.x_only_public_key().0.serialize(),
            &funding_key,
            LIVE_TN10_FEE,
        )
        .unwrap();
    assert!(stage5.prepared.evidence.pass);
    assert_eq!(stage5.prepared.transaction.tx.outputs.len(), 3);
}

#[test]
fn live_builder_refuses_public_fixture_authority() {
    let snapshot = Snapshot::from_source(demo_source()).unwrap();
    assert!(
        SnapshotNetworkPlan::new(snapshot, test_key(1).x_only_public_key().0.serialize()).is_err()
    );
}

#[test]
fn two_sequential_full_claims_pass_the_real_engine_and_conserve_supply() {
    let mut lab = lab();
    let total = lab.snapshot.total;

    let first_amount = lab.snapshot.holders[0].amount;
    let first = lab.claim(0).expect("first claim executes");
    assert!(first.pass, "{}", first.verdict);
    assert_ne!(first.root_before, first.root_after);
    assert_eq!(lab.reserve_amount + first_amount, total);

    let second_amount = lab.snapshot.holders[1].amount;
    let second = lab
        .claim(1)
        .expect("second claim executes against new root");
    assert!(second.pass, "{}", second.verdict);
    assert_eq!(second.root_before, first.root_after);
    assert_eq!(lab.reserve_amount + first_amount + second_amount, total);
    assert_eq!(lab.claimed_count(), 2);
}

#[test]
fn every_entitlement_can_be_claimed_and_the_reserve_reaches_zero() {
    let mut lab = lab();
    for index in [2, 0, 3, 1] {
        let attempt = lab.claim(index).expect("claim executes in sequence");
        assert!(attempt.pass, "{}", attempt.verdict);
        assert!(attempt.mass.block_legal);
    }
    assert_eq!(lab.reserve_amount, 0);
    assert_eq!(lab.claimed_count(), lab.snapshot.holders.len());
}

#[test]
fn a_claimed_p2pk_recipient_can_authorize_and_split_its_token() {
    let mut lab = lab();
    let owner_key = demo_owner_key(lab.snapshot.holders[0].owner);
    let claim = lab.claim(0).expect("recipient is created by a real claim");
    let split = lab
        .simulate_p2pk_recipient_split(0, &claim.transaction_id, &owner_key)
        .expect("downstream split is constructed");
    assert!(split.pass, "{}", split.verdict);
    assert!(split.mass.block_legal);
    assert!(split.mass.lab_fee_estimate_covered);

    let wrong_key = demo_owner_key(lab.snapshot.holders[1].owner);
    assert!(lab
        .simulate_p2pk_recipient_split(0, &claim.transaction_id, &wrong_key)
        .is_err());
}

#[test]
fn maximum_poc_tree_depth_executes_within_committed_budget_and_block_mass() {
    let lab = SnapshotLab::new(Snapshot::from_source(script_hash_source(1_024)).unwrap()).unwrap();
    let attempt = lab
        .simulate_with_proof(1_023, lab.proof(1_023).unwrap(), ClaimTamper::None)
        .unwrap();
    assert!(attempt.pass, "{}", attempt.verdict);
    assert_eq!(attempt.proof_depth, 10);
    assert!(attempt.mass.block_legal);
    assert!(attempt.mass.lab_fee_estimate_covered);
    assert!(attempt.mass.compute < attempt.mass.compute_limit);
    assert!(attempt.mass.transient < attempt.mass.transient_limit);
    assert!(attempt
        .mass
        .storage
        .is_some_and(|mass| mass < attempt.mass.storage_limit));
}

#[test]
fn merkle_codec_has_pinned_vectors_across_odd_padding_and_max_depth() {
    for count in [1u32, 3, 5, 1_024] {
        let snapshot = Snapshot::from_source(script_hash_source(count)).unwrap();
        let vector = snapshot.merkle_vector(count as usize - 1).unwrap();
        let expected = match count {
            1 => {
                r#"{"index":0,"context":"c5e299421dfb5045d07e5431e6d4265a26dd1d2ea03aa04d7230c55277cc8a50","entitlement_leaf":"0d3b562d26caf5247789e4993cbe0f463f10781ac3b97497be83d67844b23dea","claimed_leaf":"8d589c90dbd33d97487a2aa5597df32507fffea10665f99883122cda56510379","first_padding_leaf":"7864e75a1a5bcdbb3f18046512e2332fab45550fda66f2a63dad395306d8c662","siblings":["7864e75a1a5bcdbb3f18046512e2332fab45550fda66f2a63dad395306d8c662"],"root_before":"91f8c6bc0dc67bd13a4204744cc5a5cf5ae4c7cee618346af289e8f0c4409292","root_after":"8648d014afe62bdd2678ff6020cb29a781f101c53792118782e781b202940d48"}"#
            }
            3 => {
                r#"{"index":2,"context":"c5e299421dfb5045d07e5431e6d4265a26dd1d2ea03aa04d7230c55277cc8a50","entitlement_leaf":"3790d9ab50dda73e2c44175c67cbd354d3c6c76a7afd4542f42e45d813b2b4b0","claimed_leaf":"c1e6272422f51223e75a35faa1c657e9f3df51576524ff506f1f39544a5b685e","first_padding_leaf":"d780a28ff23d0a33e599f15d7b75a55b961ce5814ddcccd9e37c257319d28ba4","siblings":["d780a28ff23d0a33e599f15d7b75a55b961ce5814ddcccd9e37c257319d28ba4","7828dab8e6b3983503de4dbcd0ef9eaa2d827c60c491efef3f947ed04458511c"],"root_before":"eced5cd86fa1c487f39385dfafcd1282ba2fd02f36e62fd48d652c066e1cc0cf","root_after":"d499bc46138d6143e93bec8e9e57069ae7d8684b54094138877f732a301e552e"}"#
            }
            5 => {
                r#"{"index":4,"context":"c5e299421dfb5045d07e5431e6d4265a26dd1d2ea03aa04d7230c55277cc8a50","entitlement_leaf":"6c274e89535644769c011c5d29c99f86c0c1cf14123016f7cbc2b2974285d435","claimed_leaf":"5de2efc55cda2115f47cb3d8e3268f0b4c327d8b32c090e7b9b326f5c3596ffc","first_padding_leaf":"b5f34860cac291f5856282eb3060c49548888775638dd6c9f8033de3325c635d","siblings":["b5f34860cac291f5856282eb3060c49548888775638dd6c9f8033de3325c635d","2517396d4b0e1d6ee5537613462424e21aeccca9afc8ab787a89ba72b1d1aa71","05ef343a4217a8072eaa2d9ad717dd0a4ef054491a1f21cdf419166eea1154c8"],"root_before":"3f88b174ebd9a225d784a76a9cb1acb7a362cd1f60044c6234f40addcbafc262","root_after":"b31b2b7db13e248b45ab838cecffec07dbf12a72999fff4022732449f5083005"}"#
            }
            1_024 => {
                r#"{"index":1023,"context":"c5e299421dfb5045d07e5431e6d4265a26dd1d2ea03aa04d7230c55277cc8a50","entitlement_leaf":"1982c793ade5e55feabb78ec6a5025af4cd019725524e348d4b2ff3b93d92d98","claimed_leaf":"5b956e12392f65d22783aae4119b84009abdd12ec88ccaae547245816039acdf","first_padding_leaf":null,"siblings":["d525e85dfa15d277c30121b315b890bd6381e3efedd3f500feba62dd10af1c8c","36615dd7c1ef00242207aa879facc4f2931bdb78b6e7809ee80b258b378f6681","3126fc8df1f8c29151e1447f4b4153d3e21b4e284e839a0b8bcc410ec8ef5f1a","75ebaf84fd3962338c667ab156fd66c8a363d718b5c77455e793890981136db2","4ad9b18820061a5cf3e3581dc9eefdd768e6cb420b34d4c5a69f426291358c41","a448b2b11e846834fe77074ac8e7d6d9e686c20c796f72d04d3aef09da9df68f","6f2257d743dbd8b754b7839c5b8948ff7a8540b156b3742f3bf37413962db1d0","a7f51e885174a906bf2635390ef020c9d9c697d8383fe99266b5f920c90fcb5d","deef305c0e9ef093ab82c2d196ea9d3a7fa88836f4e651648b9a9d72140b8ede","4a55a281790b860d81cd6a4a4dc8dea1a4e3ea4599c112c8bc997f4597c5ead7"],"root_before":"2874c1b9d5b1f95aa2a228b505921db922484cccb0e507338b4f4870bb78922d","root_after":"0e110a533d62a864a26153974d8b3a54f111fe6171f39af5ed5f9ee3d960e85e"}"#
            }
            _ => unreachable!(),
        };
        assert_eq!(serde_json::to_string(&vector).unwrap(), expected);
    }
}

#[test]
fn stale_and_duplicate_proofs_fail_after_the_root_moves() {
    let mut lab = lab();
    let stale_for_zero = lab.proof(0).unwrap();
    let stale_for_one = lab.proof(1).unwrap();

    assert!(lab.claim(0).unwrap().pass);

    let replay = lab
        .simulate_with_proof(0, stale_for_zero, ClaimTamper::None)
        .expect("replay reaches the engine");
    assert!(
        !replay.pass,
        "a retired leaf proof must fail against the new root"
    );

    let competing = lab
        .simulate_with_proof(1, stale_for_one, ClaimTamper::None)
        .expect("competing claim reaches the engine");
    assert!(
        !competing.pass,
        "a proof built before another claim must refresh"
    );
}

#[test]
fn proof_amount_destination_conservation_and_kas_drain_tampering_fail_closed() {
    let lab = lab();
    for tamper in [
        ClaimTamper::Proof,
        ClaimTamper::Amount,
        ClaimTamper::Destination,
        ClaimTamper::ReserveAmount,
        ClaimTamper::ControllerKas,
        ClaimTamper::ReserveKas,
        ClaimTamper::RecipientKas,
        ClaimTamper::ExtraTokenOutput,
        ClaimTamper::DropController,
    ] {
        let attempt = lab
            .simulate_with_proof(0, lab.proof(0).unwrap(), tamper)
            .unwrap_or_else(|e| panic!("{tamper:?} could not be simulated: {e}"));
        assert!(
            !attempt.pass,
            "{tamper:?} must be rejected by a covenant input"
        );
    }
}

#[test]
fn manifest_commitment_is_part_of_the_token_genesis_identity() {
    let lab = lab();
    assert_eq!(
        lab.token_id,
        lab.token_genesis_id_for_root(lab.snapshot.manifest_commitment)
            .unwrap()
    );
    let mut changed = lab.snapshot.manifest_commitment;
    changed[0] ^= 1;
    assert_ne!(
        lab.token_id,
        lab.token_genesis_id_for_root(changed).unwrap()
    );
}

#[test]
fn changing_the_snapshot_changes_both_covenant_genesis_ids() {
    let original = lab();
    let mut changed_source = demo_source();
    changed_source.holders[0].amount = "1250000001".to_string();
    let changed = SnapshotLab::new(Snapshot::from_source(changed_source).unwrap()).unwrap();
    assert_ne!(
        original.snapshot.initial_root,
        changed.snapshot.initial_root
    );
    assert_ne!(original.token_id, changed.token_id);
    assert_ne!(original.controller_id, changed.controller_id);
}

#[test]
fn malformed_or_ambiguous_snapshots_are_rejected_before_compilation() {
    let mut duplicate = demo_source();
    duplicate.holders.push(duplicate.holders[0].clone());
    assert!(Snapshot::from_source(duplicate).is_err());

    let mut fractional = demo_source();
    fractional.holders[0].amount = "1e9".to_string();
    assert!(Snapshot::from_source(fractional).is_err());

    let mut zero = demo_source();
    zero.holders[0].amount = "0".to_string();
    assert!(Snapshot::from_source(zero).is_err());

    let mut network_alias = demo_source();
    network_alias.network = "testnet".to_string();
    assert!(Snapshot::from_source(network_alias).is_err());

    let mut padded_indexer = demo_source();
    padded_indexer.checkpoint.indexer = " kasmelt-poc-fixture/1".to_string();
    assert!(Snapshot::from_source(padded_indexer).is_err());

    let mut unknown = serde_json::to_value(demo_source()).unwrap();
    unknown["holders"] = serde_json::json!([SourceHolder {
        address: "not-an-address".to_string(),
        amount: "1".to_string(),
    }]);
    assert!(Snapshot::parse_json(&unknown.to_string()).is_err());
}

/// A valid proof for leaf B presented at leaf A's index must fail. The branch
/// authenticates one position only, so a transplant recomputes a root that does
/// not match the singleton state.
#[test]
fn a_proof_transplanted_between_holders_fails() {
    let lab = lab();
    let foreign = lab.proof(1).expect("holder 1 has a valid proof");
    let attempt = lab.simulate_with_proof(0, foreign, ClaimTamper::None);
    assert!(
        attempt.map(|a| a.pass).unwrap_or(false) == false,
        "holder 1's branch must not release holder 0's entitlement"
    );
}

/// The snapshot context is part of every leaf preimage, so a structurally
/// identical proof from a DIFFERENT snapshot (same holders, other ticker) must
/// fail against this controller. This is the domain-separation guarantee: no
/// proof is portable between deployments.
#[test]
fn a_proof_from_another_snapshot_context_fails() {
    let lab_a = lab();
    let mut other = demo_source();
    other.ticker = "OTHERT".to_string();
    let lab_b = SnapshotLab::new(Snapshot::from_source(other).unwrap()).unwrap();
    let foreign = lab_b.proof(0).expect("same index, different context");
    let attempt = lab_a.simulate_with_proof(0, foreign, ClaimTamper::None);
    assert!(
        attempt.map(|a| a.pass).unwrap_or(false) == false,
        "a proof from another deployment's context must be worthless here"
    );
}

/// The minimum real tree: two holders, depth 1, one sibling per proof. The
/// cursor arithmetic has no room to hide here, and both entitlements must be
/// claimable sequentially until the reserve is empty.
#[test]
fn a_two_holder_depth_one_tree_claims_out_completely() {
    let mut lab = SnapshotLab::new(Snapshot::from_source(script_hash_source(2)).unwrap()).unwrap();
    for index in 0..2 {
        let attempt = lab.claim(index).expect("depth-1 claim must pass");
        assert!(attempt.pass, "{}", attempt.verdict);
        assert_eq!(attempt.proof_depth, 1);
    }
    assert_eq!(lab.reserve_amount, 0);
    assert_eq!(lab.claimed_count(), 2);
}

/// A single-holder snapshot still builds a width-2 tree, so the sole real
/// claim's sibling is a deterministic padding leaf. That padding path must
/// execute in the real engine, and the padding leaf itself must stay
/// unclaimable because its index is outside the holder count.
#[test]
fn a_single_holder_claims_against_a_padding_sibling() {
    let mut lab = SnapshotLab::new(Snapshot::from_source(script_hash_source(1)).unwrap()).unwrap();
    let attempt = lab.claim(0).expect("the sole entitlement must claim");
    assert!(attempt.pass, "{}", attempt.verdict);
    assert_eq!(lab.reserve_amount, 0);
    // A branch for the padding position is constructible (the tree is width 2),
    // but claiming it must fail at every reachable layer.
    let padding_proof = lab.proof(1).expect("a padding branch exists in the tree");
    assert!(
        lab.simulate_with_proof(1, padding_proof, ClaimTamper::None)
            .is_err(),
        "the padding position must never simulate as claimable"
    );
    assert!(
        lab.claim(1).is_err(),
        "the padding position must never be claimable"
    );
}

/// THE freeze attack. A claim whose controller successor commits the OLD root
/// would keep every outstanding proof valid forever: the same entitlement could
/// be claimed again and again until the reserve drained. Nothing about the
/// payout is wrong in this transaction; only the successor state lies.
#[test]
fn a_successor_that_does_not_advance_the_root_is_rejected() {
    let lab = lab();
    let attempt = lab
        .simulate_with_proof(0, lab.proof(0).unwrap(), ClaimTamper::SuccessorRoot)
        .unwrap();
    assert!(
        !attempt.pass,
        "a controller successor committing the pre-claim root must fail: {}",
        attempt.verdict
    );
}

/// The claim admits exactly one cell of the token covenant group. A second
/// token input must be rejected by the cardinality guard itself, before any
/// witness on that input is evaluated.
#[test]
fn a_claim_with_a_second_token_input_is_rejected() {
    let lab = lab();
    let attempt = lab
        .simulate_with_proof(0, lab.proof(0).unwrap(), ClaimTamper::ExtraTokenInput)
        .unwrap();
    assert!(
        !attempt.pass,
        "a second token-covenant input must fail the claim: {}",
        attempt.verdict
    );
}

/// A three-holder tree has width 4, so claiming the last holder folds a
/// deterministic PADDING leaf through the real engine. Power-of-two fixtures
/// never exercise that branch of the in-script fold.
#[test]
fn a_claim_on_a_padded_tree_folds_the_padding_sibling_in_engine() {
    let lab = SnapshotLab::new(Snapshot::from_source(script_hash_source(3)).unwrap()).unwrap();
    let attempt = lab
        .simulate_with_proof(2, lab.proof(2).unwrap(), ClaimTamper::None)
        .unwrap();
    assert!(attempt.pass, "{}", attempt.verdict);
    assert_eq!(attempt.proof_depth, 2);
}
