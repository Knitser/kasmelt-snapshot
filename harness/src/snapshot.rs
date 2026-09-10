//! One-time KRC-20 snapshot -> covenant claim proof of concept.
//!
//! This module is intentionally offline. It canonicalizes a declared holder
//! snapshot, builds the Merkle commitment, compiles the two covenant families,
//! and executes claims with the same `TxScriptEngine` a Kaspa node uses. It
//! does not fetch or bless KRC-20 state and it never broadcasts a transaction.

use crate::token_state::{
    locate_state_cuts, State as TokenState, OWNER_COVENANT_ID, OWNER_P2PK_SCHNORR, OWNER_P2SH,
    STATE_LEN,
};
use crate::{build, compile, push, InputSpec, OutputSpec};
use kaspa_addresses::{Address, Prefix, Version as AddressVersion};
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    hashing::{
        covenant_id::covenant_id,
        sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync},
        sighash_type::SIG_HASH_ALL,
        tx::id as transaction_id,
    },
    mass::{calc_storage_mass, MassCalculator, UtxoCell},
    tx::{
        ComputeCommit, CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction,
        TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA, mass::units::ComputeBudget, subnets::SUBNETWORK_ID_NATIVE,
};
use kaspa_txscript::{pay_to_address_script, pay_to_script_hash_script};
use secp256k1::{Keypair, SECP256K1};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const SPEC_PIN: &str = "kaspanet/kccs@e31a5a8";
pub const ABI_STATUS: &str =
    "KCC20-shaped; local SilverScript numeric dispatch, not final KCC-1 ABI";
pub const CODEC: &str = "kasmelt-snapshot-v1/blake2b256/full-claim";
pub const CELL_KAS: u64 = 100_000_000;
pub const AUTHORITY_KAS: u64 = 120_000_000;
pub const CLAIM_FEE: u64 = 20_000_000;
pub const MAX_HOLDERS: usize = 1_024;
/// Forty units allow 409,999 script units per input. Unlike the repository's
/// broad legacy-test budget, three such commitments remain comfortably below
/// the TN10 block compute limit after transaction-size mass is included.
pub const SNAPSHOT_BUDGET: u16 = 40;

/// A deliberately bounded fee cap for the public TN10 mechanics proof. The
/// live builder still measures the final signed transaction and refuses it if
/// the fee does not cover the harness estimate. Two TKAS is intentionally
/// generous for testnet while remaining a hard, reviewable upper bound.
pub const LIVE_TN10_FEE: u64 = 200_000_000;

type Hash32 = [u8; 32];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSource {
    pub network: String,
    pub ticker: String,
    pub krc_deploy_id: String,
    pub checkpoint: SnapshotCheckpoint,
    pub holders: Vec<SourceHolder>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCheckpoint {
    pub daa_score: String,
    pub muhash: String,
    pub indexer: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHolder {
    pub address: String,
    /// Decimal string on purpose: JavaScript must never round token amounts.
    pub amount: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Holder {
    pub index: usize,
    pub address: String,
    pub amount: i64,
    pub owner_scheme: u8,
    pub owner: Hash32,
    pub claimed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotSummary {
    pub context: String,
    pub initial_root: String,
    pub manifest_commitment: String,
    pub total: String,
    pub depth: usize,
    pub holder_count: usize,
    pub manifest_json: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct MerkleVector {
    pub index: usize,
    pub context: String,
    pub entitlement_leaf: String,
    pub claimed_leaf: String,
    pub first_padding_leaf: Option<String>,
    pub siblings: Vec<String>,
    pub root_before: String,
    pub root_after: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotError(pub String);

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SnapshotError {}

fn err(message: impl Into<String>) -> SnapshotError {
    SnapshotError(message.into())
}

fn blake2b(parts: &[&[u8]]) -> Hash32 {
    let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
    for part in parts {
        state.update(part);
    }
    let digest = state.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn parse_hex32(label: &str, value: &str) -> Result<Hash32, SnapshotError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err(format!(
            "{label} must be exactly 64 hexadecimal characters"
        )));
    }
    let bytes = hex::decode(value).map_err(|e| err(format!("invalid {label}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| err(format!("{label} must decode to 32 bytes")))
}

fn parse_decimal(label: &str, value: &str) -> Result<i64, SnapshotError> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || value.starts_with('0') && value != "0"
    {
        return Err(err(format!(
            "{label} must be canonical unsigned decimal text"
        )));
    }
    let amount = value
        .parse::<i64>()
        .map_err(|_| err(format!("{label} exceeds the KCC int ceiling")))?;
    if amount <= 0 {
        return Err(err(format!("{label} must be greater than zero")));
    }
    Ok(amount)
}

fn push_len_prefixed(out: &mut Vec<u8>, value: &str) -> Result<(), SnapshotError> {
    let len = u32::try_from(value.len()).map_err(|_| err("metadata field is too long"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn owner_from_address(network: &str, raw: &str) -> Result<(Address, u8, Hash32), SnapshotError> {
    let address = Address::try_from(raw).map_err(|e| err(format!("invalid address {raw}: {e}")))?;
    let expected_prefix = match network {
        "mainnet" => Prefix::Mainnet,
        "testnet-10" => Prefix::Testnet,
        _ => return Err(err("network must be 'mainnet' or 'testnet-10'")),
    };
    if address.prefix != expected_prefix {
        return Err(err(format!("address {raw} does not belong to {network}")));
    }
    let owner: Hash32 = address
        .payload
        .as_slice()
        .try_into()
        .map_err(|_| err(format!("address {raw} does not carry a 32-byte owner")))?;
    let scheme = match address.version {
        AddressVersion::PubKey => OWNER_P2PK_SCHNORR,
        AddressVersion::ScriptHash => OWNER_P2SH,
        AddressVersion::PubKeyECDSA => {
            return Err(err(format!(
                "ECDSA address {raw} needs KCC-2 keyed-P2PKH conversion; this POC fails closed"
            )))
        }
    };
    Ok((address, scheme, owner))
}

fn entitlement_leaf(context: &Hash32, holder: &Holder) -> Hash32 {
    blake2b(&[
        &[0x00],
        context,
        &(holder.index as u64).to_le_bytes(),
        &[holder.owner_scheme],
        &holder.owner,
        &holder.amount.to_le_bytes(),
    ])
}

fn claimed_leaf(context: &Hash32, index: usize) -> Hash32 {
    blake2b(&[&[0x02], context, &(index as u64).to_le_bytes()])
}

fn padding_leaf(context: &Hash32, index: usize) -> Hash32 {
    blake2b(&[&[0x03], context, &(index as u64).to_le_bytes()])
}

fn branch_node(left: &Hash32, right: &Hash32) -> Hash32 {
    blake2b(&[&[0x01], left, right])
}

#[derive(Clone, Debug)]
pub struct ClaimProof {
    pub index: usize,
    pub siblings: Vec<Hash32>,
}

#[derive(Clone, Debug)]
struct MerkleTree {
    context: Hash32,
    leaves: Vec<Hash32>,
    depth: usize,
}

impl MerkleTree {
    fn from_holders(context: Hash32, holders: &[Holder]) -> Self {
        let width = holders.len().max(2).next_power_of_two();
        let depth = width.trailing_zeros() as usize;
        let mut leaves = Vec::with_capacity(width);
        leaves.extend(holders.iter().map(|h| entitlement_leaf(&context, h)));
        for index in holders.len()..width {
            leaves.push(padding_leaf(&context, index));
        }
        Self {
            context,
            leaves,
            depth,
        }
    }

    fn layers(&self) -> Vec<Vec<Hash32>> {
        let mut layers = vec![self.leaves.clone()];
        while layers.last().is_some_and(|layer| layer.len() > 1) {
            let prev = layers.last().expect("one layer");
            let next = prev
                .chunks_exact(2)
                .map(|pair| branch_node(&pair[0], &pair[1]))
                .collect();
            layers.push(next);
        }
        layers
    }

    fn root(&self) -> Hash32 {
        self.layers().last().expect("root layer")[0]
    }

    fn proof(&self, index: usize) -> Result<ClaimProof, SnapshotError> {
        if index >= self.leaves.len() {
            return Err(err("claim index is outside the tree"));
        }
        let layers = self.layers();
        let mut cursor = index;
        let mut siblings = Vec::with_capacity(self.depth);
        for layer in layers.iter().take(self.depth) {
            siblings.push(layer[cursor ^ 1]);
            cursor >>= 1;
        }
        Ok(ClaimProof { index, siblings })
    }

    fn retire(&mut self, index: usize) -> Result<(), SnapshotError> {
        if index >= self.leaves.len() {
            return Err(err("claim index is outside the tree"));
        }
        self.leaves[index] = claimed_leaf(&self.context, index);
        Ok(())
    }
}

#[derive(Serialize)]
struct CanonicalManifest<'a> {
    codec: &'static str,
    network: &'a str,
    ticker: &'a str,
    krc_deploy_id: &'a str,
    checkpoint_daa_score: &'a str,
    checkpoint_muhash: &'a str,
    indexer: &'a str,
    context: String,
    initial_root: String,
    depth: usize,
    total: String,
    holders: Vec<CanonicalHolder<'a>>,
}

#[derive(Serialize)]
struct CanonicalHolder<'a> {
    index: usize,
    address: &'a str,
    owner_scheme: u8,
    owner: String,
    amount: String,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub source: SnapshotSource,
    pub holders: Vec<Holder>,
    pub context: Hash32,
    pub initial_root: Hash32,
    pub manifest_commitment: Hash32,
    pub manifest_json: String,
    pub total: i64,
    tree: MerkleTree,
}

impl Snapshot {
    pub fn parse_json(json: &str) -> Result<Self, SnapshotError> {
        let source: SnapshotSource = serde_json::from_str(json)
            .map_err(|e| err(format!("snapshot JSON is invalid: {e}")))?;
        Self::from_source(source)
    }

    pub fn from_source(mut source: SnapshotSource) -> Result<Self, SnapshotError> {
        if source.holders.is_empty() {
            return Err(err("snapshot must contain at least one holder"));
        }
        if source.holders.len() > MAX_HOLDERS {
            return Err(err(format!(
                "snapshot exceeds the POC limit of {MAX_HOLDERS} holders"
            )));
        }
        if source.ticker.is_empty()
            || source.ticker.len() > 12
            || !source
                .ticker
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Err(err("ticker must be 1-12 uppercase ASCII letters or digits"));
        }
        let deploy_id = parse_hex32("krc_deploy_id", &source.krc_deploy_id)?;
        let muhash = parse_hex32("checkpoint.muhash", &source.checkpoint.muhash)?;
        let daa_score =
            source.checkpoint.daa_score.parse::<u64>().map_err(|_| {
                err("checkpoint.daa_score must be an unsigned 64-bit decimal string")
            })?;
        if daa_score.to_string() != source.checkpoint.daa_score {
            return Err(err("checkpoint.daa_score must use canonical decimal text"));
        }
        if source.checkpoint.indexer.trim().is_empty() || source.checkpoint.indexer.len() > 120 {
            return Err(err(
                "checkpoint.indexer must name the snapshot implementation",
            ));
        }
        if source.checkpoint.indexer.trim() != source.checkpoint.indexer {
            return Err(err(
                "checkpoint.indexer must not have leading or trailing whitespace",
            ));
        }

        let mut holders = Vec::with_capacity(source.holders.len());
        for raw in &source.holders {
            let amount = parse_decimal("holder amount", &raw.amount)?;
            let (address, owner_scheme, owner) = owner_from_address(&source.network, &raw.address)?;
            holders.push(Holder {
                index: 0,
                address: address.to_string(),
                amount,
                owner_scheme,
                owner,
                claimed: false,
            });
        }
        holders.sort_by_key(|holder| (holder.owner_scheme, holder.owner));
        let mut seen = BTreeSet::new();
        for (index, holder) in holders.iter_mut().enumerate() {
            if !seen.insert((holder.owner_scheme, holder.owner)) {
                return Err(err(format!(
                    "duplicate canonical owner at {}",
                    holder.address
                )));
            }
            holder.index = index;
        }

        let total = holders.iter().try_fold(0i64, |sum, holder| {
            sum.checked_add(holder.amount)
                .ok_or_else(|| err("snapshot total exceeds the KCC int ceiling"))
        })?;

        source.krc_deploy_id = hex::encode(deploy_id);
        source.checkpoint.muhash = hex::encode(muhash);
        source.holders = holders
            .iter()
            .map(|h| SourceHolder {
                address: h.address.clone(),
                amount: h.amount.to_string(),
            })
            .collect();

        let mut context_preimage = b"KASMELT/SNAPSHOT-CONTEXT/v1\0".to_vec();
        push_len_prefixed(&mut context_preimage, &source.network)?;
        push_len_prefixed(&mut context_preimage, &source.ticker)?;
        context_preimage.extend_from_slice(&deploy_id);
        context_preimage.extend_from_slice(&daa_score.to_le_bytes());
        context_preimage.extend_from_slice(&muhash);
        push_len_prefixed(&mut context_preimage, &source.checkpoint.indexer)?;
        let context = blake2b(&[&context_preimage]);

        let tree = MerkleTree::from_holders(context, &holders);
        let initial_root = tree.root();
        let manifest = CanonicalManifest {
            codec: CODEC,
            network: &source.network,
            ticker: &source.ticker,
            krc_deploy_id: &source.krc_deploy_id,
            checkpoint_daa_score: &source.checkpoint.daa_score,
            checkpoint_muhash: &source.checkpoint.muhash,
            indexer: &source.checkpoint.indexer,
            context: hex::encode(context),
            initial_root: hex::encode(initial_root),
            depth: tree.depth,
            total: total.to_string(),
            holders: holders
                .iter()
                .map(|h| CanonicalHolder {
                    index: h.index,
                    address: &h.address,
                    owner_scheme: h.owner_scheme,
                    owner: hex::encode(h.owner),
                    amount: h.amount.to_string(),
                })
                .collect(),
        };
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| err(format!("manifest encoding failed: {e}")))?;
        let manifest_commitment = *blake3::hash(manifest_json.as_bytes()).as_bytes();

        Ok(Self {
            source,
            holders,
            context,
            initial_root,
            manifest_commitment,
            manifest_json,
            total,
            tree,
        })
    }

    pub fn summary(&self) -> SnapshotSummary {
        SnapshotSummary {
            context: hex::encode(self.context),
            initial_root: hex::encode(self.initial_root),
            manifest_commitment: hex::encode(self.manifest_commitment),
            total: self.total.to_string(),
            depth: self.tree.depth,
            holder_count: self.holders.len(),
            manifest_json: self.manifest_json.clone(),
        }
    }

    pub fn current_root(&self) -> Hash32 {
        self.tree.root()
    }

    pub fn proof(&self, index: usize) -> Result<ClaimProof, SnapshotError> {
        self.tree.proof(index)
    }

    pub fn merkle_vector(&self, index: usize) -> Result<MerkleVector, SnapshotError> {
        let holder = self
            .holders
            .get(index)
            .ok_or_else(|| err("unknown holder index"))?;
        let proof = self.tree.proof(index)?;
        let root_before = self.tree.root();
        let mut next = self.tree.clone();
        next.retire(index)?;
        let first_padding_leaf = (self.holders.len() < self.tree.leaves.len())
            .then(|| hex::encode(padding_leaf(&self.context, self.holders.len())));
        Ok(MerkleVector {
            index,
            context: hex::encode(self.context),
            entitlement_leaf: hex::encode(entitlement_leaf(&self.context, holder)),
            claimed_leaf: hex::encode(claimed_leaf(&self.context, index)),
            first_padding_leaf,
            siblings: proof.siblings.into_iter().map(hex::encode).collect(),
            root_before: hex::encode(root_before),
            root_after: hex::encode(next.root()),
        })
    }
}

#[derive(Clone, Debug)]
struct TokenTemplate {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: Hash32,
}

impl TokenTemplate {
    fn from_program(program: &[u8], state: &TokenState) -> Result<Self, SnapshotError> {
        let encoded = state.encode().ok_or_else(|| err("negative token state"))?;
        let matching: Vec<_> = locate_state_cuts(program)
            .into_iter()
            .filter(|at| program[*at..*at + STATE_LEN] == encoded)
            .collect();
        let [at] = matching.as_slice() else {
            return Err(err(format!(
                "token build has {} matching KCC-0020 state windows; expected exactly one",
                matching.len()
            )));
        };
        let prefix = program[..*at].to_vec();
        let suffix = program[*at + STATE_LEN..].to_vec();
        let hash = blake2b(&[&prefix, &suffix]);
        Ok(Self {
            prefix,
            suffix,
            hash,
        })
    }

    fn program(&self, state: &TokenState) -> Result<Vec<u8>, SnapshotError> {
        let encoded = state.encode().ok_or_else(|| err("negative token state"))?;
        let mut program = Vec::with_capacity(self.prefix.len() + STATE_LEN + self.suffix.len());
        program.extend_from_slice(&self.prefix);
        program.extend_from_slice(&encoded);
        program.extend_from_slice(&self.suffix);
        Ok(program)
    }

    fn spk(&self, state: &TokenState) -> Result<ScriptPublicKey, SnapshotError> {
        Ok(pay_to_script_hash_script(&self.program(state)?))
    }
}

#[derive(Clone, Debug)]
struct ControllerTemplate {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl ControllerTemplate {
    fn from_program(program: &[u8], root: Hash32) -> Result<Self, SnapshotError> {
        let encoded = push(&root);
        let matches: Vec<_> = program
            .windows(encoded.len())
            .enumerate()
            .filter_map(|(at, bytes)| (bytes == encoded).then_some(at))
            .collect();
        let [at] = matches.as_slice() else {
            return Err(err(format!(
                "controller build has {} root state windows; expected exactly one",
                matches.len()
            )));
        };
        Ok(Self {
            prefix: program[..*at].to_vec(),
            suffix: program[*at + encoded.len()..].to_vec(),
        })
    }

    fn program(&self, root: Hash32) -> Vec<u8> {
        let mut program = self.prefix.clone();
        program.extend_from_slice(&push(&root));
        program.extend_from_slice(&self.suffix);
        program
    }
}

fn script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let negative = value < 0;
    let mut n = value.unsigned_abs();
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    if out.last().is_some_and(|last| last & 0x80 != 0) {
        out.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        *out.last_mut().expect("non-zero") |= 0x80;
    }
    out
}

fn state_args(state: &TokenState, output: &mut Vec<u8>) {
    output.extend_from_slice(&push(&script_num(state.amount)));
    output.extend_from_slice(&push(&state.owner));
    output.extend_from_slice(&push(&[state.owner_scheme]));
    output.extend_from_slice(&push(&[state.borrow_scheme]));
    output.extend_from_slice(&push(&state.borrow_guard));
    output.extend_from_slice(&push(&state.extension_commitment));
}

fn token_array_args(states: &[TokenState]) -> Vec<Vec<u8>> {
    vec![
        states.iter().flat_map(|s| s.amount.to_le_bytes()).collect(),
        states.iter().flat_map(|s| s.owner).collect(),
        states.iter().map(|s| s.owner_scheme).collect(),
        states.iter().map(|s| s.borrow_scheme).collect(),
        states.iter().flat_map(|s| s.borrow_guard).collect(),
        states.iter().flat_map(|s| s.extension_commitment).collect(),
    ]
}

fn token_witness(
    prev_program: &[u8],
    states: &[TokenState],
    signatures: &[u8],
    authority_input: u8,
) -> Vec<u8> {
    let mut witness = Vec::new();
    for group in token_array_args(states) {
        witness.extend_from_slice(&push(&group));
    }
    witness.extend_from_slice(&push(signatures));
    witness.extend_from_slice(&push(&[authority_input]));
    witness.extend_from_slice(&push(&[])); // generated leader selector 0
    witness.extend_from_slice(&push(prev_program));
    witness
}

fn controller_witness(
    program: &[u8],
    holder: &Holder,
    proof: &ClaimProof,
    reserve: &TokenState,
    recipient: &TokenState,
) -> Vec<u8> {
    let mut witness = Vec::new();
    witness.extend_from_slice(&push(&script_num(holder.index as i64)));
    witness.extend_from_slice(&push(&[holder.owner_scheme]));
    witness.extend_from_slice(&push(&holder.owner));
    witness.extend_from_slice(&push(&script_num(holder.amount)));
    let siblings: Vec<u8> = proof.siblings.iter().flatten().copied().collect();
    witness.extend_from_slice(&push(&siblings));
    state_args(reserve, &mut witness);
    state_args(recipient, &mut witness);
    witness.extend_from_slice(&push(program));
    witness
}

fn fixed_key(seed: u8) -> Keypair {
    let mut secret = [0u8; 32];
    secret[31] = seed;
    Keypair::from_seckey_slice(SECP256K1, &secret).expect("small non-zero test key")
}

fn signature_arg(
    tx: &MutableTransaction<Transaction>,
    input_index: usize,
    key: &Keypair,
) -> Result<Vec<u8>, SnapshotError> {
    let reused = SigHashReusedValuesUnsync::new();
    let sighash =
        calc_schnorr_signature_hash(&tx.as_verifiable(), input_index, SIG_HASH_ALL, &reused);
    let signature = key.sign_schnorr(
        secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice())
            .map_err(|e| err(format!("signature digest failed: {e}")))?,
    );
    let mut arg = signature.as_ref().to_vec();
    arg.push(SIG_HASH_ALL.to_u8());
    Ok(arg)
}

fn sign_plain_input(
    tx: &mut MutableTransaction<Transaction>,
    input_index: usize,
    key: &Keypair,
) -> Result<(), SnapshotError> {
    let arg = signature_arg(tx, input_index, key)?;
    tx.tx.inputs[input_index].signature_script = push(&arg);
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub enum ClaimTamper {
    #[default]
    None,
    Proof,
    Amount,
    Destination,
    ReserveAmount,
    ControllerKas,
    ReserveKas,
    RecipientKas,
    ExtraTokenOutput,
    DropController,
    /// The successor commits the PRE-claim root: a controller that does not
    /// advance its state would let every proof stay valid forever.
    SuccessorRoot,
    /// A second cell in the token covenant group joins the claim's inputs.
    ExtraTokenInput,
}

#[derive(Clone, Debug, Serialize)]
pub struct MassEvidence {
    pub compute: u64,
    pub transient: u64,
    pub storage: Option<u64>,
    pub compute_limit: u64,
    pub transient_limit: u64,
    pub storage_limit: u64,
    pub block_legal: bool,
    pub fee_sompi: u64,
    pub lab_fee_estimate_sompi: u64,
    pub lab_fee_estimate_covered: bool,
}

fn measure_mass(tx: &MutableTransaction<Transaction>) -> MassEvidence {
    let calculator = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let non_contextual = calculator.calc_non_contextual_masses(&tx.tx);
    let limits = TESTNET_PARAMS.block_mass_limits().after();
    let input_cells: Vec<UtxoCell> = tx
        .entries
        .iter()
        .filter_map(|entry| entry.as_ref().map(Into::into))
        .collect();
    let storage = (input_cells.len() == tx.tx.inputs.len())
        .then(|| {
            calc_storage_mass(
                false,
                input_cells.iter().copied(),
                tx.tx.outputs.iter().map(UtxoCell::from),
                TESTNET_PARAMS.storage_mass_parameter,
            )
        })
        .flatten();
    let block_legal = non_contextual.compute_mass <= limits.compute
        && non_contextual.transient_mass <= limits.transient
        && storage.is_some_and(|mass| mass <= limits.storage);
    let input_value = tx
        .entries
        .iter()
        .filter_map(|entry| entry.as_ref())
        .fold(0u64, |total, entry| total.saturating_add(entry.amount));
    let output_value = tx
        .tx
        .outputs
        .iter()
        .fold(0u64, |total, output| total.saturating_add(output.value));
    let fee_sompi = input_value.saturating_sub(output_value);
    // This is the deliberately conservative fee family already used by the
    // adjacent kascov lab. It is not a live mempool quote: nodes choose their
    // own relay floor, which only an RPC-backed builder can know at runtime.
    let lab_fee_estimate_sompi = non_contextual
        .compute_mass
        .saturating_mul(100)
        .saturating_add(200_000);
    MassEvidence {
        compute: non_contextual.compute_mass,
        transient: non_contextual.transient_mass,
        storage,
        compute_limit: limits.compute,
        transient_limit: limits.transient,
        storage_limit: limits.storage,
        block_legal,
        fee_sompi,
        lab_fee_estimate_sompi,
        lab_fee_estimate_covered: fee_sompi >= lab_fee_estimate_sompi,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TransitionEvidence {
    pub label: String,
    pub transaction_id: String,
    pub pass: bool,
    pub verdict: String,
    pub input_script_units: Vec<u64>,
    pub mass: MassEvidence,
}

fn execute_transaction(label: &str, tx: &MutableTransaction<Transaction>) -> TransitionEvidence {
    let indices: Vec<usize> = (0..tx.tx.inputs.len()).collect();
    let executions = crate::engine::preflight_execute(tx, &indices);
    let failed = executions.iter().find(|execution| !execution.pass);
    let mass = measure_mass(tx);
    let pass = failed.is_none() && mass.block_legal && mass.lab_fee_estimate_covered;
    let verdict = failed
        .map(|execution| format!("input {}: {}", execution.input_index, execution.verdict))
        .unwrap_or_else(|| {
            if !mass.block_legal {
                "scripts accepted but a TN10 block-mass dimension is invalid".to_string()
            } else if !mass.lab_fee_estimate_covered {
                "scripts and mass accepted but the conservative lab fee estimate is not covered"
                    .to_string()
            } else {
                format!(
                    "all {} inputs accepted; mass and fee estimate pass",
                    executions.len()
                )
            }
        });
    TransitionEvidence {
        label: label.to_string(),
        transaction_id: hex::encode(transaction_id(&tx.tx).as_bytes()),
        pass,
        verdict,
        input_script_units: executions
            .iter()
            .map(|execution| execution.script_units_used)
            .collect(),
        mass,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SetupEvidence {
    pub token_genesis: TransitionEvidence,
    pub controller_genesis: TransitionEvidence,
    pub reserve_handoff: TransitionEvidence,
}

impl SetupEvidence {
    pub fn all_pass(&self) -> bool {
        [
            &self.token_genesis,
            &self.controller_genesis,
            &self.reserve_handoff,
        ]
        .iter()
        .all(|stage| stage.pass && stage.mass.block_legal && stage.mass.lab_fee_estimate_covered)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ClaimAttempt {
    pub pass: bool,
    pub verdict: String,
    pub transaction_id: String,
    pub script_units: u64,
    pub input_script_units: Vec<u64>,
    pub mass: MassEvidence,
    pub root_before: String,
    pub root_after: String,
    pub proof_depth: usize,
}

#[derive(Clone, Debug)]
pub struct SnapshotLab {
    pub snapshot: Snapshot,
    pub token_id: Hash32,
    pub controller_id: Hash32,
    pub reserve_amount: i64,
    pub setup: SetupEvidence,
    token_template: TokenTemplate,
    controller_template: ControllerTemplate,
    reserve_state: TokenState,
    controller_outpoint: TransactionOutpoint,
    reserve_outpoint: TransactionOutpoint,
}

impl SnapshotLab {
    pub fn new(snapshot: Snapshot) -> Result<Self, SnapshotError> {
        let deploy_key = fixed_key(1);
        let deployer = deploy_key.x_only_public_key().0.serialize();
        let genesis_state = TokenState {
            amount: snapshot.total,
            owner: deployer,
            owner_scheme: OWNER_P2PK_SCHNORR,
            borrow_scheme: 0,
            borrow_guard: [0u8; 32],
            extension_commitment: snapshot.manifest_commitment,
        };
        let token_program = compile(
            "kasmelt-snapshot-token.sil",
            &[
                genesis_state.amount.to_string(),
                hex::encode(genesis_state.owner),
                format!("0x{:02x}", genesis_state.owner_scheme),
                "0x00".to_string(),
                hex::encode(genesis_state.borrow_guard),
                hex::encode(genesis_state.extension_commitment),
                "2".to_string(),
                "2".to_string(),
            ],
        )
        .map_err(|e| err(format!("snapshot token compilation failed: {e}")))?;
        let token_template = TokenTemplate::from_program(&token_program, &genesis_state)?;

        // Stage 1: the manifest commitment is already in token genesis. The
        // temporary pubkey owner only breaks the token/controller ID cycle.
        let token_genesis =
            TransactionOutput::new(CELL_KAS, pay_to_script_hash_script(&token_program));
        let token_anchor = TransactionOutpoint::new([0x10; 32].into(), 0);
        let token_hash = covenant_id(token_anchor, [(0u32, &token_genesis)].into_iter());
        let token_id: Hash32 = token_hash.as_bytes();
        let deploy_address = Address::new(Prefix::Testnet, AddressVersion::PubKey, &deployer);
        let deploy_spk = pay_to_address_script(&deploy_address);
        let mut token_genesis_tx = build(
            vec![InputSpec {
                outpoint: token_anchor,
                spk: deploy_spk.clone(),
                value: CELL_KAS + CLAIM_FEE,
                covenant_id: None,
                sig_script: vec![],
            }],
            vec![OutputSpec {
                spk: token_template.spk(&genesis_state)?,
                value: CELL_KAS,
                covenant: Some((0, token_id)),
            }],
            SNAPSHOT_BUDGET,
        );
        sign_plain_input(&mut token_genesis_tx, 0, &deploy_key)?;
        let token_genesis_evidence = execute_transaction("token genesis", &token_genesis_tx);
        if !token_genesis_evidence.pass
            || !token_genesis_evidence.mass.block_legal
            || !token_genesis_evidence.mass.lab_fee_estimate_covered
        {
            return Err(err(format!(
                "local token genesis rejected: {}; block legal = {}",
                token_genesis_evidence.verdict, token_genesis_evidence.mass.block_legal
            )));
        }
        let token_genesis_outpoint =
            TransactionOutpoint::new(transaction_id(&token_genesis_tx.tx), 0);

        // Stage 2: now the controller can pin the real token family id.
        let controller_program = compile(
            "kasmelt-snapshot-controller.sil",
            &[
                hex::encode(snapshot.initial_root),
                hex::encode(token_id),
                hex::encode(snapshot.manifest_commitment),
                hex::encode(snapshot.context),
                snapshot.tree.depth.to_string(),
                snapshot.holders.len().to_string(),
                token_template.prefix.len().to_string(),
                token_template.suffix.len().to_string(),
                hex::encode(token_template.hash),
                format!("0x{}", hex::encode(&token_template.prefix)),
                format!("0x{}", hex::encode(&token_template.suffix)),
                CELL_KAS.to_string(),
                CELL_KAS.to_string(),
            ],
        )
        .map_err(|e| err(format!("snapshot controller compilation failed: {e}")))?;
        let controller_template =
            ControllerTemplate::from_program(&controller_program, snapshot.initial_root)?;
        let controller_genesis =
            TransactionOutput::new(CELL_KAS, pay_to_script_hash_script(&controller_program));
        let controller_anchor = TransactionOutpoint::new([0x20; 32].into(), 0);
        let controller_hash =
            covenant_id(controller_anchor, [(0u32, &controller_genesis)].into_iter());
        let controller_id: Hash32 = controller_hash.as_bytes();
        let controller_key = fixed_key(2);
        let controller_owner = controller_key.x_only_public_key().0.serialize();
        let controller_funding_spk = pay_to_address_script(&Address::new(
            Prefix::Testnet,
            AddressVersion::PubKey,
            &controller_owner,
        ));
        let mut controller_genesis_tx = build(
            vec![InputSpec {
                outpoint: controller_anchor,
                spk: controller_funding_spk,
                value: CELL_KAS + CLAIM_FEE,
                covenant_id: None,
                sig_script: vec![],
            }],
            vec![OutputSpec {
                spk: pay_to_script_hash_script(&controller_program),
                value: CELL_KAS,
                covenant: Some((0, controller_id)),
            }],
            SNAPSHOT_BUDGET,
        );
        sign_plain_input(&mut controller_genesis_tx, 0, &controller_key)?;
        let controller_genesis_evidence =
            execute_transaction("controller genesis", &controller_genesis_tx);
        if !controller_genesis_evidence.pass
            || !controller_genesis_evidence.mass.block_legal
            || !controller_genesis_evidence.mass.lab_fee_estimate_covered
        {
            return Err(err(format!(
                "local controller genesis rejected: {}; block legal = {}",
                controller_genesis_evidence.verdict, controller_genesis_evidence.mass.block_legal
            )));
        }
        let controller_outpoint =
            TransactionOutpoint::new(transaction_id(&controller_genesis_tx.tx), 0);

        // Stage 3: the preissued reserve is handed from the deploy key to the
        // controller. No key or minter authority survives this state.
        let reserve_state = TokenState {
            amount: snapshot.total,
            owner: controller_id,
            owner_scheme: OWNER_COVENANT_ID,
            borrow_scheme: 0,
            borrow_guard: [0u8; 32],
            extension_commitment: snapshot.manifest_commitment,
        };
        let handoff_fee_key = fixed_key(3);
        let handoff_fee_owner = handoff_fee_key.x_only_public_key().0.serialize();
        let handoff_fee_spk = pay_to_address_script(&Address::new(
            Prefix::Testnet,
            AddressVersion::PubKey,
            &handoff_fee_owner,
        ));
        let mut handoff_tx = build(
            vec![
                InputSpec {
                    outpoint: token_genesis_outpoint,
                    spk: token_template.spk(&genesis_state)?,
                    value: CELL_KAS,
                    covenant_id: Some(token_id),
                    sig_script: vec![],
                },
                InputSpec {
                    outpoint: TransactionOutpoint::new([0x30; 32].into(), 0),
                    spk: handoff_fee_spk,
                    value: CLAIM_FEE,
                    covenant_id: None,
                    sig_script: vec![],
                },
            ],
            vec![OutputSpec {
                spk: token_template.spk(&reserve_state)?,
                value: CELL_KAS,
                covenant: Some((0, token_id)),
            }],
            SNAPSHOT_BUDGET,
        );
        let token_signature = signature_arg(&handoff_tx, 0, &deploy_key)?;
        handoff_tx.tx.inputs[0].signature_script =
            token_witness(&token_program, &[reserve_state], &token_signature, 0);
        sign_plain_input(&mut handoff_tx, 1, &handoff_fee_key)?;
        let reserve_handoff_evidence =
            execute_transaction("full-supply reserve handoff", &handoff_tx);
        if !reserve_handoff_evidence.pass
            || !reserve_handoff_evidence.mass.block_legal
            || !reserve_handoff_evidence.mass.lab_fee_estimate_covered
        {
            return Err(err(format!(
                "local reserve handoff rejected: {}; block legal = {}",
                reserve_handoff_evidence.verdict, reserve_handoff_evidence.mass.block_legal
            )));
        }
        let reserve_outpoint = TransactionOutpoint::new(transaction_id(&handoff_tx.tx), 0);

        Ok(Self {
            reserve_amount: snapshot.total,
            snapshot,
            token_id,
            controller_id,
            setup: SetupEvidence {
                token_genesis: token_genesis_evidence,
                controller_genesis: controller_genesis_evidence,
                reserve_handoff: reserve_handoff_evidence,
            },
            token_template,
            controller_template,
            reserve_state,
            controller_outpoint,
            reserve_outpoint,
        })
    }

    pub fn source_json(&self) -> String {
        serde_json::to_string_pretty(&self.snapshot.source).expect("snapshot source serializes")
    }

    pub fn current_root(&self) -> Hash32 {
        self.snapshot.current_root()
    }

    pub fn claimed_count(&self) -> usize {
        self.snapshot.holders.iter().filter(|h| h.claimed).count()
    }

    pub fn proof(&self, index: usize) -> Result<ClaimProof, SnapshotError> {
        self.snapshot.proof(index)
    }

    pub fn simulate_with_proof(
        &self,
        index: usize,
        proof: ClaimProof,
        tamper: ClaimTamper,
    ) -> Result<ClaimAttempt, SnapshotError> {
        let holder = self
            .snapshot
            .holders
            .get(index)
            .cloned()
            .ok_or_else(|| err("unknown holder index"))?;
        self.execute(&holder, proof, tamper)
    }

    pub fn claim(&mut self, index: usize) -> Result<ClaimAttempt, SnapshotError> {
        let holder = self
            .snapshot
            .holders
            .get(index)
            .cloned()
            .ok_or_else(|| err("unknown holder index"))?;
        if holder.claimed {
            return Err(err("this entitlement is already claimed"));
        }
        let proof = self.snapshot.proof(index)?;
        let attempt = self.execute(&holder, proof, ClaimTamper::None)?;
        if !attempt.pass {
            return Err(err(format!(
                "real script engine rejected the claim: {}",
                attempt.verdict
            )));
        }

        self.snapshot.tree.retire(index)?;
        self.snapshot.holders[index].claimed = true;
        self.reserve_amount = self
            .reserve_amount
            .checked_sub(holder.amount)
            .ok_or_else(|| err("reserve underflow"))?;
        self.reserve_state.amount = self.reserve_amount;

        // Chain each accepted local transition exactly as a broadcast sequence
        // would: the next spend names this claim transaction's output IDs.
        let txid = parse_hex32("claim transaction id", &attempt.transaction_id)?;
        self.reserve_outpoint = TransactionOutpoint::new(txid.into(), 0);
        self.controller_outpoint = TransactionOutpoint::new(txid.into(), 2);
        Ok(attempt)
    }

    /// Spend an actually claimed demo recipient and split it into two ordinary
    /// P2PK token cells. This is still the POC's local numeric ABI, but it proves
    /// the claim output is not a terminal state: owner authorization and token
    /// conservation execute again in a downstream transaction.
    pub fn simulate_p2pk_recipient_split(
        &self,
        index: usize,
        claim_transaction_id: &str,
        owner_key: &Keypair,
    ) -> Result<TransitionEvidence, SnapshotError> {
        let holder = self
            .snapshot
            .holders
            .get(index)
            .ok_or_else(|| err("unknown holder index"))?;
        if !holder.claimed {
            return Err(err("recipient does not exist until its claim is accepted"));
        }
        if holder.owner_scheme != OWNER_P2PK_SCHNORR {
            return Err(err(
                "this downstream POC helper requires a Schnorr P2PK owner",
            ));
        }
        let supplied_owner = owner_key.x_only_public_key().0.serialize();
        if supplied_owner != holder.owner {
            return Err(err("supplied key does not own the claimed recipient"));
        }
        if holder.amount < 2 {
            return Err(err("claimed amount must be at least two units to split"));
        }

        let claim_txid = parse_hex32("claim transaction id", claim_transaction_id)?;
        let previous = TokenState {
            amount: holder.amount,
            owner: holder.owner,
            owner_scheme: holder.owner_scheme,
            borrow_scheme: 0,
            borrow_guard: [0u8; 32],
            extension_commitment: self.snapshot.manifest_commitment,
        };
        let first = TokenState {
            amount: holder.amount / 2,
            ..previous
        };
        let destination = fixed_key(77).x_only_public_key().0.serialize();
        let second = TokenState {
            amount: holder.amount - first.amount,
            owner: destination,
            ..previous
        };
        let fee_key = fixed_key(78);
        let fee_owner = fee_key.x_only_public_key().0.serialize();
        let fee_spk = pay_to_address_script(&Address::new(
            Prefix::Testnet,
            AddressVersion::PubKey,
            &fee_owner,
        ));
        let fee_outpoint = blake2b(&[
            b"KASMELT/RECIPIENT-SPLIT-FEE/v1\0",
            &claim_txid,
            &(index as u64).to_le_bytes(),
        ]);
        let previous_program = self.token_template.program(&previous)?;
        let mut tx = build(
            vec![
                InputSpec {
                    outpoint: TransactionOutpoint::new(claim_txid.into(), 1),
                    spk: self.token_template.spk(&previous)?,
                    value: CELL_KAS,
                    covenant_id: Some(self.token_id),
                    sig_script: vec![],
                },
                InputSpec {
                    outpoint: TransactionOutpoint::new(fee_outpoint.into(), 0),
                    spk: fee_spk,
                    value: AUTHORITY_KAS,
                    covenant_id: None,
                    sig_script: vec![],
                },
            ],
            vec![
                OutputSpec {
                    spk: self.token_template.spk(&first)?,
                    value: CELL_KAS,
                    covenant: Some((0, self.token_id)),
                },
                OutputSpec {
                    spk: self.token_template.spk(&second)?,
                    value: CELL_KAS,
                    covenant: Some((0, self.token_id)),
                },
            ],
            SNAPSHOT_BUDGET,
        );
        let owner_signature = signature_arg(&tx, 0, owner_key)?;
        tx.tx.inputs[0].signature_script =
            token_witness(&previous_program, &[first, second], &owner_signature, 0);
        sign_plain_input(&mut tx, 1, &fee_key)?;
        Ok(execute_transaction("claimed recipient split", &tx))
    }

    fn execute(
        &self,
        holder: &Holder,
        mut proof: ClaimProof,
        tamper: ClaimTamper,
    ) -> Result<ClaimAttempt, SnapshotError> {
        if proof.index != holder.index || proof.siblings.len() != self.snapshot.tree.depth {
            return Err(err("proof shape does not match the holder/tree"));
        }
        let root_before = self.current_root();
        if matches!(tamper, ClaimTamper::Proof) {
            proof.siblings[0][0] ^= 1;
        }

        let claim_holder = holder.clone();

        let mut next_tree = self.snapshot.tree.clone();
        next_tree.retire(holder.index)?;
        let root_after = next_tree.root();

        let mut reserve_next = TokenState {
            amount: self.reserve_state.amount - claim_holder.amount,
            ..self.reserve_state
        };
        if matches!(tamper, ClaimTamper::ReserveAmount) {
            reserve_next.amount = reserve_next.amount.saturating_add(1);
        }
        let mut recipient = TokenState {
            amount: claim_holder.amount,
            owner: claim_holder.owner,
            owner_scheme: claim_holder.owner_scheme,
            borrow_scheme: 0,
            borrow_guard: [0u8; 32],
            extension_commitment: self.snapshot.manifest_commitment,
        };
        // Keep the proof/witness entitlement untouched. These mutations target
        // the payout itself, proving destination and amount are independently
        // bound rather than merely failing because the leaf hash changed.
        if matches!(tamper, ClaimTamper::Amount) {
            recipient.amount = recipient.amount.saturating_add(1);
        }
        if matches!(tamper, ClaimTamper::Destination) {
            recipient.owner[0] ^= 1;
        }

        let controller_program = self.controller_template.program(root_before);
        let controller_next_program = if matches!(tamper, ClaimTamper::SuccessorRoot) {
            // The freeze attack: recreate the controller with its old root.
            self.controller_template.program(root_before)
        } else {
            self.controller_template.program(root_after)
        };
        let reserve_program = self.token_template.program(&self.reserve_state)?;

        let controller_value = if matches!(tamper, ClaimTamper::ControllerKas) {
            CELL_KAS - 1
        } else {
            CELL_KAS
        };
        let reserve_value = if matches!(tamper, ClaimTamper::ReserveKas) {
            CELL_KAS - 1
        } else {
            CELL_KAS
        };
        let recipient_value = if matches!(tamper, ClaimTamper::RecipientKas) {
            CELL_KAS - 1
        } else {
            CELL_KAS
        };

        let fee_key = fixed_key(99);
        let fee_pk = fee_key.x_only_public_key().0.serialize();
        let fee_address = Address::new(Prefix::Testnet, AddressVersion::PubKey, &fee_pk);
        let fee_spk = pay_to_address_script(&fee_address);
        let fee_fixture = blake2b(&[
            b"KASMELT/CLAIM-FEE-FIXTURE/v1\0",
            &root_before,
            &(self.claimed_count() as u64).to_le_bytes(),
        ]);
        let mut inputs = vec![
            InputSpec {
                outpoint: self.controller_outpoint,
                spk: pay_to_script_hash_script(&controller_program),
                value: CELL_KAS,
                covenant_id: Some(self.controller_id),
                sig_script: vec![],
            },
            InputSpec {
                outpoint: self.reserve_outpoint,
                spk: self.token_template.spk(&self.reserve_state)?,
                value: CELL_KAS,
                covenant_id: Some(self.token_id),
                sig_script: vec![],
            },
            InputSpec {
                outpoint: TransactionOutpoint::new(fee_fixture.into(), 0),
                spk: fee_spk.clone(),
                value: AUTHORITY_KAS,
                covenant_id: None,
                sig_script: vec![],
            },
        ];
        if matches!(tamper, ClaimTamper::ExtraTokenInput) {
            // The OpCovInputCount(tokenCovid) == 1 guard must fail before any
            // witness on this input is even evaluated.
            inputs.push(InputSpec {
                outpoint: TransactionOutpoint::new(
                    blake2b(&[b"KASMELT/EXTRA-TOKEN-INPUT/v1\0", &root_before]).into(),
                    0,
                ),
                spk: self.token_template.spk(&self.reserve_state)?,
                value: CELL_KAS,
                covenant_id: Some(self.token_id),
                sig_script: vec![],
            });
        }
        let mut outputs = vec![
            OutputSpec {
                spk: self.token_template.spk(&reserve_next)?,
                value: reserve_value,
                covenant: Some((1, self.token_id)),
            },
            OutputSpec {
                spk: self.token_template.spk(&recipient)?,
                value: recipient_value,
                covenant: Some((1, self.token_id)),
            },
            OutputSpec {
                spk: pay_to_script_hash_script(&controller_next_program),
                value: controller_value,
                covenant: Some((0, self.controller_id)),
            },
        ];
        if matches!(tamper, ClaimTamper::ExtraTokenOutput) {
            outputs.push(OutputSpec {
                spk: self.token_template.spk(&recipient)?,
                value: 1,
                covenant: Some((1, self.token_id)),
            });
        }
        if matches!(tamper, ClaimTamper::DropController) {
            outputs.pop();
        }
        if CELL_KAS * 2 + AUTHORITY_KAS
            < controller_value + reserve_value + recipient_value + CLAIM_FEE
        {
            return Err(err("claim native-value balance is invalid"));
        }
        let mut tx = build(inputs, outputs, SNAPSHOT_BUDGET);
        tx.tx.inputs[0].signature_script = controller_witness(
            &controller_program,
            &claim_holder,
            &proof,
            &reserve_next,
            &recipient,
        );
        tx.tx.inputs[1].signature_script =
            token_witness(&reserve_program, &[reserve_next, recipient], &[0u8; 65], 0);
        sign_plain_input(&mut tx, 2, &fee_key)?;

        let executions = crate::engine::preflight_execute(&tx, &[0, 1, 2]);
        let failed = executions.iter().find(|execution| !execution.pass);
        let mass = measure_mass(&tx);
        let pass = failed.is_none() && mass.block_legal && mass.lab_fee_estimate_covered;
        let verdict = failed
            .map(|execution| format!("input {}: {}", execution.input_index, execution.verdict))
            .unwrap_or_else(|| {
                if mass.block_legal && mass.lab_fee_estimate_covered {
                    "all three inputs accepted; block mass is legal and the conservative lab fee estimate is covered".to_string()
                } else if !mass.block_legal {
                    "scripts accepted but consensus mass exceeds a TN10 block limit".to_string()
                } else {
                    "scripts and mass accepted but the conservative lab fee estimate is not covered"
                        .to_string()
                }
            });
        let input_script_units: Vec<u64> = executions
            .iter()
            .map(|execution| execution.script_units_used)
            .collect();
        let script_units = executions
            .iter()
            .map(|execution| execution.script_units_used)
            .sum();
        Ok(ClaimAttempt {
            pass,
            verdict,
            transaction_id: hex::encode(transaction_id(&tx.tx).as_bytes()),
            script_units,
            input_script_units,
            mass,
            root_before: hex::encode(root_before),
            root_after: hex::encode(root_after),
            proof_depth: proof.siblings.len(),
        })
    }

    pub fn token_genesis_id_for_root(&self, extension: Hash32) -> Result<Hash32, SnapshotError> {
        let deployer = fixed_key(1).x_only_public_key().0.serialize();
        let state = TokenState {
            amount: self.snapshot.total,
            owner: deployer,
            owner_scheme: OWNER_P2PK_SCHNORR,
            borrow_scheme: 0,
            borrow_guard: [0; 32],
            extension_commitment: extension,
        };
        let program = self.token_template.program(&state)?;
        let output = TransactionOutput::new(CELL_KAS, pay_to_script_hash_script(&program));
        let anchor = TransactionOutpoint::new([0x10; 32].into(), 0);
        Ok(covenant_id(anchor, [(0u32, &output)].into_iter()).as_bytes())
    }
}

// -------------------------------------------------------------------------
// Live TN10 transaction preparation
// -------------------------------------------------------------------------
//
// SnapshotLab above is intentionally a deterministic regression fixture. It
// must never be used as a broadcaster: its keys and outpoints are public. The
// types below are a separate, fail-closed seam for a network-facing CLI. Every
// predecessor is supplied as the exact UTXO returned by RPC, and the fully
// signed transaction that passes preflight is the same value the caller may
// submit.

#[derive(Clone, Debug)]
pub struct LiveUtxo {
    pub outpoint: TransactionOutpoint,
    pub entry: UtxoEntry,
}

pub struct PreparedSnapshotTransaction {
    pub transaction: MutableTransaction<Transaction>,
    pub evidence: TransitionEvidence,
}

pub struct PreparedTokenGenesis {
    pub prepared: PreparedSnapshotTransaction,
    pub token_id: Hash32,
    pub token_program: Vec<u8>,
}

pub struct PreparedControllerGenesis {
    pub prepared: PreparedSnapshotTransaction,
    pub controller_id: Hash32,
    pub controller_program: Vec<u8>,
}

pub struct PreparedReserveHandoff {
    pub prepared: PreparedSnapshotTransaction,
    pub reserve_program: Vec<u8>,
}

pub struct PreparedLiveClaim {
    pub prepared: PreparedSnapshotTransaction,
    pub root_after: Hash32,
    pub reserve_amount_after: i64,
    pub reserve_program_after: Vec<u8>,
    pub recipient_program: Vec<u8>,
    pub controller_program_after: Vec<u8>,
}

pub struct PreparedRecipientSplit {
    pub prepared: PreparedSnapshotTransaction,
    pub first_program: Vec<u8>,
    pub second_program: Vec<u8>,
}

pub struct SnapshotNetworkPlan {
    pub snapshot: Snapshot,
    deploy_owner: Hash32,
    genesis_state: TokenState,
    token_program: Vec<u8>,
    token_template: TokenTemplate,
}

fn fixture_public_key(owner: &Hash32) -> bool {
    [1u8, 2, 3, 10, 11, 12, 13, 77, 78, 99]
        .into_iter()
        .any(|seed| fixed_key(seed).x_only_public_key().0.serialize() == *owner)
}

fn fixture_outpoint(outpoint: &TransactionOutpoint) -> bool {
    [0x10u8, 0x20, 0x30]
        .into_iter()
        .any(|byte| *outpoint == TransactionOutpoint::new([byte; 32].into(), 0))
}

fn live_build(inputs: &[LiveUtxo], outputs: Vec<OutputSpec>) -> MutableTransaction<Transaction> {
    let tx_inputs = inputs
        .iter()
        .map(|input| {
            TransactionInput::new_with_mass(
                input.outpoint,
                vec![],
                0,
                ComputeCommit::ComputeBudget(ComputeBudget(SNAPSHOT_BUDGET)),
            )
        })
        .collect();
    let tx_outputs = outputs
        .into_iter()
        .map(|output| {
            TransactionOutput::with_covenant(
                output.value,
                output.spk,
                output
                    .covenant
                    .map(|(authority, id)| CovenantBinding::new(authority, id.into())),
            )
        })
        .collect();
    let tx = Transaction::new(
        TX_VERSION_TOCCATA,
        tx_inputs,
        tx_outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    MutableTransaction::with_entries(tx, inputs.iter().map(|input| input.entry.clone()).collect())
}

fn live_address_spk(key: &Keypair) -> ScriptPublicKey {
    let owner = key.x_only_public_key().0.serialize();
    pay_to_address_script(&Address::new(
        Prefix::Testnet,
        AddressVersion::PubKey,
        &owner,
    ))
}

fn validate_live_key(label: &str, key: &Keypair) -> Result<Hash32, SnapshotError> {
    let owner = key.x_only_public_key().0.serialize();
    if fixture_public_key(&owner) {
        return Err(err(format!(
            "{label} is a public deterministic fixture key; refusing network preparation"
        )));
    }
    Ok(owner)
}

fn validate_live_funding(
    funding: &LiveUtxo,
    key: &Keypair,
    minimum: u64,
) -> Result<(), SnapshotError> {
    validate_live_key("funding key", key)?;
    if fixture_outpoint(&funding.outpoint) {
        return Err(err("fixture outpoint is forbidden in live preparation"));
    }
    if funding.entry.covenant_id.is_some() {
        return Err(err("funding input must be a plain non-covenant UTXO"));
    }
    if funding.entry.is_coinbase {
        return Err(err(
            "coinbase funding is not supported by the TN10 POC; use a settled faucet/change UTXO",
        ));
    }
    if funding.entry.block_daa_score == 0 {
        return Err(err("funding UTXO is not confirmed"));
    }
    if funding.entry.script_public_key != live_address_spk(key) {
        return Err(err("funding UTXO is not owned by the supplied funding key"));
    }
    if funding.entry.amount < minimum {
        return Err(err(format!(
            "funding UTXO has {} sompi; at least {minimum} is required",
            funding.entry.amount
        )));
    }
    Ok(())
}

fn validate_live_cell(
    label: &str,
    cell: &LiveUtxo,
    expected_value: u64,
    expected_spk: &ScriptPublicKey,
    expected_id: Hash32,
) -> Result<(), SnapshotError> {
    if fixture_outpoint(&cell.outpoint) {
        return Err(err(format!("{label} uses a forbidden fixture outpoint")));
    }
    if cell.entry.block_daa_score == 0 {
        return Err(err(format!("{label} is not confirmed")));
    }
    if cell.entry.amount != expected_value {
        return Err(err(format!(
            "{label} has {} sompi; expected {expected_value}",
            cell.entry.amount
        )));
    }
    if &cell.entry.script_public_key != expected_spk {
        return Err(err(format!(
            "{label} script does not match the prepared state"
        )));
    }
    if cell.entry.covenant_id.map(|id| id.as_bytes()) != Some(expected_id) {
        return Err(err(format!("{label} covenant id does not match")));
    }
    Ok(())
}

fn checked_change(amount: u64, extra_cell_value: u64, fee: u64) -> Result<u64, SnapshotError> {
    if fee == 0 || fee > LIVE_TN10_FEE {
        return Err(err(format!(
            "live fee must be between 1 and {LIVE_TN10_FEE} sompi"
        )));
    }
    let spent = extra_cell_value
        .checked_add(fee)
        .ok_or_else(|| err("native-value arithmetic overflow"))?;
    let change = amount
        .checked_sub(spent)
        .ok_or_else(|| err("funding UTXO cannot cover cells and fee"))?;
    if change < CELL_KAS {
        return Err(err(
            "change output would fall below the one-KAS safety floor",
        ));
    }
    Ok(change)
}

fn live_ready(
    label: &str,
    tx: MutableTransaction<Transaction>,
) -> Result<PreparedSnapshotTransaction, SnapshotError> {
    let evidence = execute_transaction(label, &tx);
    if !evidence.pass || !evidence.mass.block_legal || !evidence.mass.lab_fee_estimate_covered {
        return Err(err(format!(
            "{label} failed final signed preflight: {}",
            evidence.verdict
        )));
    }
    Ok(PreparedSnapshotTransaction {
        transaction: tx,
        evidence,
    })
}

impl SnapshotNetworkPlan {
    /// Compile a live plan around a non-fixture temporary deploy authority.
    /// The snapshot itself is still externally asserted; this constructor only
    /// establishes the exact covenant bytes that commit to it.
    pub fn new(snapshot: Snapshot, deploy_owner: Hash32) -> Result<Self, SnapshotError> {
        if snapshot.source.network != "testnet-10" {
            return Err(err("live POC preparation is restricted to testnet-10"));
        }
        if fixture_public_key(&deploy_owner) {
            return Err(err(
                "temporary deploy owner is a public deterministic fixture key",
            ));
        }
        if snapshot
            .holders
            .iter()
            .any(|holder| fixture_public_key(&holder.owner))
        {
            return Err(err(
                "snapshot contains a public deterministic fixture owner",
            ));
        }
        let genesis_state = TokenState {
            amount: snapshot.total,
            owner: deploy_owner,
            owner_scheme: OWNER_P2PK_SCHNORR,
            borrow_scheme: 0,
            borrow_guard: [0; 32],
            extension_commitment: snapshot.manifest_commitment,
        };
        let token_program = compile(
            "kasmelt-snapshot-token.sil",
            &[
                genesis_state.amount.to_string(),
                hex::encode(genesis_state.owner),
                format!("0x{:02x}", genesis_state.owner_scheme),
                "0x00".to_string(),
                hex::encode(genesis_state.borrow_guard),
                hex::encode(genesis_state.extension_commitment),
                "2".to_string(),
                "2".to_string(),
            ],
        )
        .map_err(|e| err(format!("snapshot token compilation failed: {e}")))?;
        let token_template = TokenTemplate::from_program(&token_program, &genesis_state)?;
        Ok(Self {
            snapshot,
            deploy_owner,
            genesis_state,
            token_program,
            token_template,
        })
    }

    pub fn token_program(&self) -> &[u8] {
        &self.token_program
    }

    fn controller_parts(
        &self,
        token_id: Hash32,
        root: Hash32,
    ) -> Result<(Vec<u8>, ControllerTemplate), SnapshotError> {
        let program = compile(
            "kasmelt-snapshot-controller.sil",
            &[
                hex::encode(root),
                hex::encode(token_id),
                hex::encode(self.snapshot.manifest_commitment),
                hex::encode(self.snapshot.context),
                self.snapshot.tree.depth.to_string(),
                self.snapshot.holders.len().to_string(),
                self.token_template.prefix.len().to_string(),
                self.token_template.suffix.len().to_string(),
                hex::encode(self.token_template.hash),
                format!("0x{}", hex::encode(&self.token_template.prefix)),
                format!("0x{}", hex::encode(&self.token_template.suffix)),
                CELL_KAS.to_string(),
                CELL_KAS.to_string(),
            ],
        )
        .map_err(|e| err(format!("snapshot controller compilation failed: {e}")))?;
        let template = ControllerTemplate::from_program(&program, root)?;
        Ok((program, template))
    }

    pub fn controller_program(
        &self,
        token_id: Hash32,
        root: Hash32,
    ) -> Result<Vec<u8>, SnapshotError> {
        self.controller_parts(token_id, root).map(|parts| parts.0)
    }

    pub fn reserve_program(
        &self,
        controller_id: Hash32,
        amount: i64,
    ) -> Result<Vec<u8>, SnapshotError> {
        self.token_template.program(&TokenState {
            amount,
            owner: controller_id,
            owner_scheme: OWNER_COVENANT_ID,
            borrow_scheme: 0,
            borrow_guard: [0; 32],
            extension_commitment: self.snapshot.manifest_commitment,
        })
    }

    pub fn recipient_program(&self, index: usize) -> Result<Vec<u8>, SnapshotError> {
        let holder = self
            .snapshot
            .holders
            .get(index)
            .ok_or_else(|| err("unknown holder index"))?;
        self.token_template.program(&TokenState {
            amount: holder.amount,
            owner: holder.owner,
            owner_scheme: holder.owner_scheme,
            borrow_scheme: 0,
            borrow_guard: [0; 32],
            extension_commitment: self.snapshot.manifest_commitment,
        })
    }

    pub fn prepare_token_genesis(
        &self,
        funding: LiveUtxo,
        funding_key: &Keypair,
        fee: u64,
    ) -> Result<PreparedTokenGenesis, SnapshotError> {
        validate_live_funding(&funding, funding_key, CELL_KAS + fee + CELL_KAS)?;
        let change = checked_change(funding.entry.amount, CELL_KAS, fee)?;
        let unbound =
            TransactionOutput::new(CELL_KAS, self.token_template.spk(&self.genesis_state)?);
        let token_id = covenant_id(funding.outpoint, [(0u32, &unbound)].into_iter()).as_bytes();
        let mut tx = live_build(
            &[funding.clone()],
            vec![
                OutputSpec {
                    spk: unbound.script_public_key,
                    value: CELL_KAS,
                    covenant: Some((0, token_id)),
                },
                OutputSpec {
                    spk: funding.entry.script_public_key.clone(),
                    value: change,
                    covenant: None,
                },
            ],
        );
        sign_plain_input(&mut tx, 0, funding_key)?;
        Ok(PreparedTokenGenesis {
            prepared: live_ready("TN10 token genesis", tx)?,
            token_id,
            token_program: self.token_program.clone(),
        })
    }

    pub fn prepare_controller_genesis(
        &self,
        token_id: Hash32,
        funding: LiveUtxo,
        funding_key: &Keypair,
        fee: u64,
    ) -> Result<PreparedControllerGenesis, SnapshotError> {
        validate_live_funding(&funding, funding_key, CELL_KAS + fee + CELL_KAS)?;
        let change = checked_change(funding.entry.amount, CELL_KAS, fee)?;
        let (controller_program, _) =
            self.controller_parts(token_id, self.snapshot.initial_root)?;
        let unbound =
            TransactionOutput::new(CELL_KAS, pay_to_script_hash_script(&controller_program));
        let controller_id =
            covenant_id(funding.outpoint, [(0u32, &unbound)].into_iter()).as_bytes();
        let mut tx = live_build(
            &[funding.clone()],
            vec![
                OutputSpec {
                    spk: unbound.script_public_key,
                    value: CELL_KAS,
                    covenant: Some((0, controller_id)),
                },
                OutputSpec {
                    spk: funding.entry.script_public_key.clone(),
                    value: change,
                    covenant: None,
                },
            ],
        );
        sign_plain_input(&mut tx, 0, funding_key)?;
        Ok(PreparedControllerGenesis {
            prepared: live_ready("TN10 controller genesis", tx)?,
            controller_id,
            controller_program,
        })
    }

    pub fn prepare_reserve_handoff(
        &self,
        token_id: Hash32,
        controller_id: Hash32,
        token_cell: LiveUtxo,
        funding: LiveUtxo,
        deploy_key: &Keypair,
        funding_key: &Keypair,
        fee: u64,
    ) -> Result<PreparedReserveHandoff, SnapshotError> {
        let owner = validate_live_key("temporary deploy key", deploy_key)?;
        if owner != self.deploy_owner {
            return Err(err("temporary deploy key does not own token genesis"));
        }
        validate_live_cell(
            "token genesis cell",
            &token_cell,
            CELL_KAS,
            &self.token_template.spk(&self.genesis_state)?,
            token_id,
        )?;
        validate_live_funding(&funding, funding_key, fee + CELL_KAS)?;
        let change = checked_change(funding.entry.amount, 0, fee)?;
        let reserve_state = TokenState {
            amount: self.snapshot.total,
            owner: controller_id,
            owner_scheme: OWNER_COVENANT_ID,
            borrow_scheme: 0,
            borrow_guard: [0; 32],
            extension_commitment: self.snapshot.manifest_commitment,
        };
        let reserve_program = self.token_template.program(&reserve_state)?;
        let mut tx = live_build(
            &[token_cell, funding.clone()],
            vec![
                OutputSpec {
                    spk: pay_to_script_hash_script(&reserve_program),
                    value: CELL_KAS,
                    covenant: Some((0, token_id)),
                },
                OutputSpec {
                    spk: funding.entry.script_public_key.clone(),
                    value: change,
                    covenant: None,
                },
            ],
        );
        let token_signature = signature_arg(&tx, 0, deploy_key)?;
        tx.tx.inputs[0].signature_script =
            token_witness(&self.token_program, &[reserve_state], &token_signature, 0);
        sign_plain_input(&mut tx, 1, funding_key)?;
        Ok(PreparedReserveHandoff {
            prepared: live_ready("TN10 full-supply reserve handoff", tx)?,
            reserve_program,
        })
    }

    pub fn prepare_claim(
        &self,
        token_id: Hash32,
        controller_id: Hash32,
        index: usize,
        controller_cell: LiveUtxo,
        reserve_cell: LiveUtxo,
        funding: LiveUtxo,
        funding_key: &Keypair,
        fee: u64,
    ) -> Result<PreparedLiveClaim, SnapshotError> {
        let holder = self
            .snapshot
            .holders
            .get(index)
            .cloned()
            .ok_or_else(|| err("unknown holder index"))?;
        let proof = self.snapshot.proof(index)?;
        let root_before = self.snapshot.initial_root;
        let (controller_program, controller_template) =
            self.controller_parts(token_id, root_before)?;
        validate_live_cell(
            "controller cell",
            &controller_cell,
            CELL_KAS,
            &pay_to_script_hash_script(&controller_program),
            controller_id,
        )?;
        let reserve_state = TokenState {
            amount: self.snapshot.total,
            owner: controller_id,
            owner_scheme: OWNER_COVENANT_ID,
            borrow_scheme: 0,
            borrow_guard: [0; 32],
            extension_commitment: self.snapshot.manifest_commitment,
        };
        let reserve_program = self.token_template.program(&reserve_state)?;
        validate_live_cell(
            "reserve cell",
            &reserve_cell,
            CELL_KAS,
            &pay_to_script_hash_script(&reserve_program),
            token_id,
        )?;
        validate_live_funding(&funding, funding_key, CELL_KAS + fee + CELL_KAS)?;
        let change = checked_change(funding.entry.amount, CELL_KAS, fee)?;

        let mut next_tree = self.snapshot.tree.clone();
        next_tree.retire(index)?;
        let root_after = next_tree.root();
        let reserve_next = TokenState {
            amount: self
                .snapshot
                .total
                .checked_sub(holder.amount)
                .ok_or_else(|| err("reserve underflow"))?,
            ..reserve_state
        };
        let recipient = TokenState {
            amount: holder.amount,
            owner: holder.owner,
            owner_scheme: holder.owner_scheme,
            borrow_scheme: 0,
            borrow_guard: [0; 32],
            extension_commitment: self.snapshot.manifest_commitment,
        };
        let reserve_program_after = self.token_template.program(&reserve_next)?;
        let recipient_program = self.token_template.program(&recipient)?;
        let controller_program_after = controller_template.program(root_after);
        let mut tx = live_build(
            &[controller_cell, reserve_cell, funding.clone()],
            vec![
                OutputSpec {
                    spk: pay_to_script_hash_script(&reserve_program_after),
                    value: CELL_KAS,
                    covenant: Some((1, token_id)),
                },
                OutputSpec {
                    spk: pay_to_script_hash_script(&recipient_program),
                    value: CELL_KAS,
                    covenant: Some((1, token_id)),
                },
                OutputSpec {
                    spk: pay_to_script_hash_script(&controller_program_after),
                    value: CELL_KAS,
                    covenant: Some((0, controller_id)),
                },
                OutputSpec {
                    spk: funding.entry.script_public_key.clone(),
                    value: change,
                    covenant: None,
                },
            ],
        );
        tx.tx.inputs[0].signature_script = controller_witness(
            &controller_program,
            &holder,
            &proof,
            &reserve_next,
            &recipient,
        );
        tx.tx.inputs[1].signature_script =
            token_witness(&reserve_program, &[reserve_next, recipient], &[0; 65], 0);
        sign_plain_input(&mut tx, 2, funding_key)?;
        Ok(PreparedLiveClaim {
            prepared: live_ready("TN10 Merkle claim", tx)?,
            root_after,
            reserve_amount_after: reserve_next.amount,
            reserve_program_after,
            recipient_program,
            controller_program_after,
        })
    }

    pub fn prepare_recipient_split(
        &self,
        token_id: Hash32,
        index: usize,
        recipient_cell: LiveUtxo,
        funding: LiveUtxo,
        holder_key: &Keypair,
        destination_owner: Hash32,
        funding_key: &Keypair,
        fee: u64,
    ) -> Result<PreparedRecipientSplit, SnapshotError> {
        let holder = self
            .snapshot
            .holders
            .get(index)
            .ok_or_else(|| err("unknown holder index"))?;
        if holder.owner_scheme != OWNER_P2PK_SCHNORR {
            return Err(err(
                "live recipient split currently requires a Schnorr holder",
            ));
        }
        if validate_live_key("claimant key", holder_key)? != holder.owner {
            return Err(err("claimant key does not own the claimed token cell"));
        }
        if fixture_public_key(&destination_owner) {
            return Err(err("recipient split destination is a public fixture key"));
        }
        if holder.amount < 2 {
            return Err(err("claimed amount must be at least two units to split"));
        }
        let previous = TokenState {
            amount: holder.amount,
            owner: holder.owner,
            owner_scheme: holder.owner_scheme,
            borrow_scheme: 0,
            borrow_guard: [0; 32],
            extension_commitment: self.snapshot.manifest_commitment,
        };
        let previous_program = self.token_template.program(&previous)?;
        validate_live_cell(
            "claimed recipient cell",
            &recipient_cell,
            CELL_KAS,
            &pay_to_script_hash_script(&previous_program),
            token_id,
        )?;
        validate_live_funding(&funding, funding_key, CELL_KAS + fee + CELL_KAS)?;
        let change = checked_change(funding.entry.amount, CELL_KAS, fee)?;
        let first = TokenState {
            amount: holder.amount / 2,
            ..previous
        };
        let second = TokenState {
            amount: holder.amount - first.amount,
            owner: destination_owner,
            ..previous
        };
        let first_program = self.token_template.program(&first)?;
        let second_program = self.token_template.program(&second)?;
        let mut tx = live_build(
            &[recipient_cell, funding.clone()],
            vec![
                OutputSpec {
                    spk: pay_to_script_hash_script(&first_program),
                    value: CELL_KAS,
                    covenant: Some((0, token_id)),
                },
                OutputSpec {
                    spk: pay_to_script_hash_script(&second_program),
                    value: CELL_KAS,
                    covenant: Some((0, token_id)),
                },
                OutputSpec {
                    spk: funding.entry.script_public_key.clone(),
                    value: change,
                    covenant: None,
                },
            ],
        );
        let owner_signature = signature_arg(&tx, 0, holder_key)?;
        tx.tx.inputs[0].signature_script =
            token_witness(&previous_program, &[first, second], &owner_signature, 0);
        sign_plain_input(&mut tx, 1, funding_key)?;
        Ok(PreparedRecipientSplit {
            prepared: live_ready("TN10 claimed-recipient split", tx)?,
            first_program,
            second_program,
        })
    }
}

pub fn demo_source() -> SnapshotSource {
    let amounts = ["1250000000", "730000000", "420000000", "100000000"];
    let holders = (0u8..4)
        .map(|index| {
            let key = fixed_key(index + 10);
            let owner = key.x_only_public_key().0.serialize();
            let address = Address::new(Prefix::Testnet, AddressVersion::PubKey, &owner).to_string();
            SourceHolder {
                address,
                amount: amounts[index as usize].to_string(),
            }
        })
        .collect();
    SnapshotSource {
        network: "testnet-10".to_string(),
        ticker: "NACHO".to_string(),
        krc_deploy_id: "42".repeat(32),
        checkpoint: SnapshotCheckpoint {
            daa_score: "187654321".to_string(),
            muhash: "ab".repeat(32),
            indexer: "kasmelt-poc-fixture/1".to_string(),
        },
        holders,
    }
}
