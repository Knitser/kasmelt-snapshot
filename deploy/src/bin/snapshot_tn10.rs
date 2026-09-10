//! Stage-gated public testnet-10 proof for the one-time snapshot covenant.
//!
//! This binary never consumes `SnapshotLab` fixtures. It uses confirmed RPC
//! UTXOs, three role-separated OS-random keys, final signed engine preflight,
//! an immutable transaction artifact, and an exact-output confirmation
//! barrier before the next stage can be prepared.
//!
//! The committed holder set is explicitly synthetic. Passing all five stages
//! proves the covenant mechanics on TN10; it does not prove any KRC-20 balance.

use anyhow::{bail, Context, Result};
use kasmelt_harness::snapshot::{
    LiveUtxo, PreparedSnapshotTransaction, Snapshot, SnapshotCheckpoint, SnapshotNetworkPlan,
    SnapshotSource, SourceHolder, CELL_KAS, LIVE_TN10_FEE,
};
use kaspa_addresses::{Address, Prefix, Version as AddressVersion};
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::{
    hashing::tx::id as transaction_id,
    tx::{Transaction, TransactionOutpoint, UtxoEntry},
};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::extract_script_pub_key_address;
use kaspa_wrpc_client::{
    client::{ConnectOptions, ConnectStrategy},
    KaspaRpcClient, Resolver, WrpcEncoding,
};
use secp256k1::{Keypair, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const STATE_VERSION: u32 = 1;
const CONFIRMATION_DEPTH_DAA: u64 = 30;
const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(180);
const SYNTHETIC_AMOUNT: &str = "1000000";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPins {
    repo_head: String,
    repo_diff_sha256: String,
    silverc_repo_head: String,
    silverc_sha256: String,
    live_binary_sha256: String,
    snapshot_module_sha256: String,
    token_contract_sha256: String,
    controller_contract_sha256: String,
    deploy_lock_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedOutput {
    role: String,
    transaction_id: String,
    index: u32,
    address: String,
    amount: u64,
    script_version: u16,
    script_hex: String,
    covenant_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingUpdates {
    token_id: Option<String>,
    controller_id: Option<String>,
    controller_program_sha256: Option<String>,
    current_root: Option<String>,
    reserve_amount: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingStage {
    stage: u8,
    name: String,
    status: String,
    expected_txid: String,
    artifact_path: String,
    submitted_at_virtual_daa: Option<u64>,
    outputs: Vec<ExpectedOutput>,
    updates: PendingUpdates,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StageReceipt {
    stage: u8,
    name: String,
    transaction_id: String,
    accepting_daa: u64,
    settled_virtual_daa: u64,
    explorer: String,
    artifact_path: String,
    outputs: Vec<ExpectedOutput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tn10State {
    version: u32,
    network: String,
    claim: String,
    rpc_url: String,
    funding_address: String,
    authority_address: String,
    claimant_address: String,
    source: SnapshotSource,
    manifest_json: String,
    manifest_commitment: String,
    initial_root: String,
    current_root: String,
    reserve_amount: String,
    token_program_sha256: String,
    controller_program_sha256: Option<String>,
    token_id: Option<String>,
    controller_id: Option<String>,
    next_stage: u8,
    pins: ArtifactPins,
    pending: Option<PendingStage>,
    receipts: Vec<StageReceipt>,
}

#[derive(Serialize)]
struct StageArtifact<'a> {
    schema: &'static str,
    warning: &'static str,
    network: &'static str,
    stage: u8,
    name: &'a str,
    expected_txid: &'a str,
    snapshot_manifest_json: &'a str,
    token_id: &'a Option<String>,
    controller_id: &'a Option<String>,
    pins: &'a ArtifactPins,
    evidence: &'a kasmelt_harness::snapshot::TransitionEvidence,
    input_entries: &'a [Option<UtxoEntry>],
    transaction: &'a Transaction,
    expected_outputs: &'a [ExpectedOutput],
}

fn home_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var("HOME").context("HOME is not set")?,
    ))
}

fn secure_dir() -> Result<PathBuf> {
    let dir = home_dir()?.join(".kasmelt-snapshot");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    Ok(dir)
}

fn state_path() -> Result<PathBuf> {
    Ok(secure_dir()?.join("tn10-snapshot-state.json"))
}

fn funding_key_path() -> Result<PathBuf> {
    Ok(secure_dir()?.join("tn10-deploy.key"))
}

fn authority_key_path() -> Result<PathBuf> {
    Ok(secure_dir()?.join("tn10-snapshot-authority.key"))
}

fn claimant_key_path() -> Result<PathBuf> {
    Ok(secure_dir()?.join("tn10-snapshot-claimant.key"))
}

fn assert_secure_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect secure file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} has mode {mode:04o}; secret/state files must not be group/world accessible",
                path.display()
            );
        }
    }
    Ok(())
}

fn open_new_secure(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("create secure file {}", path.display()))
}

fn load_key(path: &Path) -> Result<Keypair> {
    assert_secure_regular(path)?;
    let encoded = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let encoded = encoded.trim();
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!(
            "{} must contain exactly one 32-byte hexadecimal key",
            path.display()
        );
    }
    let bytes = hex::decode(encoded).context("decode key")?;
    Keypair::from_seckey_slice(SECP256K1, &bytes).context("invalid secret scalar")
}

fn load_or_create_role_key(path: &Path) -> Result<Keypair> {
    if path.exists() {
        return load_key(path);
    }
    let key = Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
    let mut file = open_new_secure(path)?;
    file.write_all(hex::encode(key.secret_bytes()).as_bytes())?;
    file.sync_all()?;
    assert_secure_regular(path)?;
    Ok(key)
}

fn owner(key: &Keypair) -> [u8; 32] {
    key.x_only_public_key().0.serialize()
}

fn address(key: &Keypair) -> Address {
    Address::new(Prefix::Testnet, AddressVersion::PubKey, &owner(key))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_bytes(&fs::read(path).with_context(|| {
        format!("read artifact {}", path.display())
    })?))
}

fn command_output(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn capture_pins() -> Result<ArtifactPins> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("deploy crate has no repository parent")?
        .to_path_buf();
    let silverc = kasmelt_harness::compiler_path();
    let repo_text = repo.to_string_lossy();
    let repo_head = String::from_utf8(command_output(
        "git",
        &["-C", &repo_text, "rev-parse", "HEAD"],
    )?)?
    .trim()
    .to_string();
    let repo_diff = command_output("git", &["-C", &repo_text, "diff", "--binary", "HEAD"])?;
    let silverc_repo_head = kasmelt_harness::SILVERSCRIPT_REV.to_string();
    Ok(ArtifactPins {
        repo_head,
        repo_diff_sha256: sha256_bytes(&repo_diff),
        silverc_repo_head,
        silverc_sha256: sha256_file(&silverc)?,
        live_binary_sha256: sha256_file(&std::env::current_exe()?)?,
        snapshot_module_sha256: sha256_file(&repo.join("harness/src/snapshot.rs"))?,
        token_contract_sha256: sha256_file(&repo.join("contracts/kasmelt-snapshot-token.sil"))?,
        controller_contract_sha256: sha256_file(
            &repo.join("contracts/kasmelt-snapshot-controller.sil"),
        )?,
        deploy_lock_sha256: sha256_file(&repo.join("Cargo.lock"))?,
    })
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("secure path has no parent")?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    let mut file = open_new_secure(&temp)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, path).with_context(|| format!("atomically replace {}", path.display()))?;
    assert_secure_regular(path)?;
    Ok(())
}

fn load_state() -> Result<Tn10State> {
    let path = state_path()?;
    assert_secure_regular(&path)?;
    let state: Tn10State = serde_json::from_slice(&fs::read(&path)?)
        .with_context(|| format!("parse {}; refusing to reset corrupt state", path.display()))?;
    if state.version != STATE_VERSION || state.network != "testnet-10" {
        bail!("state schema/network mismatch");
    }
    Ok(state)
}

fn save_state(state: &Tn10State) -> Result<()> {
    write_json_atomic(&state_path()?, state)
}

fn parse_hex32(label: &str, value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} is not a 32-byte hex value");
    }
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} has the wrong length"))?)
}

fn synthetic_hash(label: &[u8]) -> String {
    hex::encode(kasmelt_harness::blake2b_256(label))
}

// Connection and submission adapters derived from Kascov's labkit.
async fn connect(rpc: Option<&str>) -> Result<KaspaRpcClient> {
    let network = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let resolver = rpc.is_none().then(Resolver::default);
    let client = KaspaRpcClient::new(WrpcEncoding::Borsh, rpc, resolver, Some(network), None)?;
    client
        .connect(Some(ConnectOptions {
            block_async_connect: true,
            connect_timeout: Some(Duration::from_secs(15)),
            strategy: ConnectStrategy::Fallback,
            ..Default::default()
        }))
        .await?;
    Ok(client)
}

async fn submit(client: &KaspaRpcClient, transaction: &Transaction) -> Result<String> {
    Ok(client
        .submit_transaction(transaction.into(), false)
        .await
        .context("submit transaction")?
        .to_string())
}

async fn connect_checked(rpc: Option<&str>) -> Result<KaspaRpcClient> {
    let client = connect(rpc).await?;
    let info = client.get_server_info().await?;
    if info.network_id.to_string() != "testnet-10" {
        bail!("RPC is on {}, not testnet-10", info.network_id);
    }
    if !info.is_synced || !info.has_utxo_index {
        bail!(
            "RPC is not ready: synced={}, utxo_index={}",
            info.is_synced,
            info.has_utxo_index
        );
    }
    let dag = client.get_block_dag_info().await?;
    if dag.network.to_string() != "testnet-10" {
        bail!("DAG reports {}, not testnet-10", dag.network);
    }
    println!(
        "node    {} · {} · synced at DAA {}",
        client.url().unwrap_or_else(|| "explicit RPC".to_string()),
        info.server_version,
        info.virtual_daa_score
    );
    Ok(client)
}

fn verify_keys(state: &Tn10State) -> Result<(Keypair, Keypair, Keypair)> {
    let funding = load_key(&funding_key_path()?)?;
    let authority = load_key(&authority_key_path()?)?;
    let claimant = load_key(&claimant_key_path()?)?;
    if address(&funding).to_string() != state.funding_address
        || address(&authority).to_string() != state.authority_address
        || address(&claimant).to_string() != state.claimant_address
    {
        bail!("role-key address differs from the immutable state file");
    }
    if owner(&funding) == owner(&authority)
        || owner(&funding) == owner(&claimant)
        || owner(&authority) == owner(&claimant)
    {
        bail!("funding, temporary authority, and claimant keys must be distinct");
    }
    Ok((funding, authority, claimant))
}

fn verify_pins(state: &Tn10State) -> Result<()> {
    let now = capture_pins()?;
    if serde_json::to_value(&now)? != serde_json::to_value(&state.pins)? {
        bail!(
            "source/compiler/binary pins changed since init; refusing to prepare a different artifact"
        );
    }
    Ok(())
}

fn build_plan(state: &Tn10State, authority: &Keypair) -> Result<SnapshotNetworkPlan> {
    let snapshot = Snapshot::from_source(state.source.clone())?;
    if snapshot.manifest_json != state.manifest_json
        || hex::encode(snapshot.manifest_commitment) != state.manifest_commitment
        || hex::encode(snapshot.initial_root) != state.initial_root
    {
        bail!("canonical snapshot no longer matches the immutable state");
    }
    let plan = SnapshotNetworkPlan::new(snapshot, owner(authority))?;
    if sha256_bytes(plan.token_program()) != state.token_program_sha256 {
        bail!("compiled token bytes changed since init");
    }
    if let (Some(token_id), Some(expected)) = (
        state.token_id.as_deref(),
        state.controller_program_sha256.as_deref(),
    ) {
        let program = plan.controller_program(
            parse_hex32("token id", token_id)?,
            parse_hex32("initial root", &state.initial_root)?,
        )?;
        if sha256_bytes(&program) != expected {
            bail!("compiled controller bytes changed since controller genesis");
        }
    }
    Ok(plan)
}

fn expected_outputs(tx: &Transaction, labels: &[&str]) -> Result<Vec<ExpectedOutput>> {
    if tx.outputs.len() != labels.len() {
        bail!("output label count does not match transaction");
    }
    let txid = transaction_id(tx).to_string();
    tx.outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let address =
                extract_script_pub_key_address(&output.script_public_key, Prefix::Testnet)
                    .with_context(|| format!("derive address for output {index}"))?;
            Ok(ExpectedOutput {
                role: labels[index].to_string(),
                transaction_id: txid.clone(),
                index: index as u32,
                address: address.to_string(),
                amount: output.value,
                script_version: output.script_public_key.version(),
                script_hex: hex::encode(output.script_public_key.script()),
                covenant_id: output
                    .covenant
                    .map(|binding| binding.covenant_id.to_string()),
            })
        })
        .collect()
}

fn to_live(row: &kaspa_rpc_core::RpcUtxosByAddressesEntry) -> LiveUtxo {
    LiveUtxo {
        outpoint: TransactionOutpoint::new(row.outpoint.transaction_id, row.outpoint.index),
        entry: UtxoEntry::new(
            row.utxo_entry.amount,
            row.utxo_entry.script_public_key.clone(),
            row.utxo_entry.block_daa_score,
            row.utxo_entry.is_coinbase,
            row.utxo_entry.covenant_id,
        ),
    }
}

fn validate_rpc_match(
    row: &kaspa_rpc_core::RpcUtxosByAddressesEntry,
    expected: &ExpectedOutput,
) -> Result<()> {
    let actual_covenant = row.utxo_entry.covenant_id.map(|id| id.to_string());
    if row.utxo_entry.amount != expected.amount
        || row.utxo_entry.script_public_key.version() != expected.script_version
        || hex::encode(row.utxo_entry.script_public_key.script()) != expected.script_hex
        || actual_covenant != expected.covenant_id
    {
        bail!(
            "RPC outpoint {}:{} exists but its amount/script/covenant differs from the prepared output",
            expected.transaction_id,
            expected.index
        );
    }
    if row.utxo_entry.block_daa_score == 0 {
        bail!("RPC returned an unconfirmed entry for a required predecessor");
    }
    Ok(())
}

async fn fetch_expected_once(
    client: &KaspaRpcClient,
    expected: &ExpectedOutput,
) -> Result<Option<LiveUtxo>> {
    let parsed = Address::try_from(expected.address.as_str())?;
    let rows = client.get_utxos_by_addresses(vec![parsed.into()]).await?;
    let mut matching = rows.iter().filter(|row| {
        row.outpoint.transaction_id.to_string() == expected.transaction_id
            && row.outpoint.index == expected.index
    });
    let Some(row) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        bail!("RPC returned duplicate rows for one exact outpoint");
    }
    validate_rpc_match(row, expected)?;
    Ok(Some(to_live(row)))
}

async fn fetch_expected(client: &KaspaRpcClient, expected: &ExpectedOutput) -> Result<LiveUtxo> {
    fetch_expected_once(client, expected)
        .await?
        .with_context(|| {
            format!(
                "required confirmed outpoint {}:{} ({}) is missing or spent",
                expected.transaction_id, expected.index, expected.role
            )
        })
}

async fn select_initial_funding(client: &KaspaRpcClient, key: &Keypair) -> Result<LiveUtxo> {
    let owner_address = address(key);
    let expected_spk = kaspa_txscript::pay_to_address_script(&owner_address);
    let rows = client
        .get_utxos_by_addresses(vec![owner_address.clone().into()])
        .await?;
    let selected = rows
        .iter()
        .filter(|row| {
            row.utxo_entry.covenant_id.is_none()
                && !row.utxo_entry.is_coinbase
                && row.utxo_entry.block_daa_score > 0
                && row.utxo_entry.script_public_key == expected_spk
                && row.utxo_entry.amount > CELL_KAS + LIVE_TN10_FEE + CELL_KAS
        })
        .max_by_key(|row| row.utxo_entry.amount)
        .with_context(|| format!("no settled plain funding UTXO on {owner_address}"))?;
    let live = to_live(selected);
    println!(
        "funding {}:{} · {} sompi (selected once and pinned in the artifact)",
        live.outpoint.transaction_id, live.outpoint.index, live.entry.amount
    );
    Ok(live)
}

fn receipt_output(state: &Tn10State, stage: u8, role: &str) -> Result<ExpectedOutput> {
    let receipt = state
        .receipts
        .iter()
        .find(|receipt| receipt.stage == stage)
        .with_context(|| format!("stage {stage} has no confirmed receipt"))?;
    let matches: Vec<_> = receipt
        .outputs
        .iter()
        .filter(|output| output.role == role)
        .cloned()
        .collect();
    let [output] = matches.as_slice() else {
        bail!("stage {stage} must have exactly one {role} output");
    };
    Ok(output.clone())
}

async fn wait_for_confirmation(
    client: &KaspaRpcClient,
    outputs: &[ExpectedOutput],
) -> Result<(u64, u64)> {
    let started = Instant::now();
    loop {
        let mut scores = Vec::with_capacity(outputs.len());
        let mut all_present = true;
        for output in outputs {
            match fetch_expected_once(client, output).await? {
                Some(cell) => scores.push(cell.entry.block_daa_score),
                None => all_present = false,
            }
        }
        if all_present {
            scores.sort_unstable();
            scores.dedup();
            if scores.len() != 1 {
                bail!("outputs from one transaction report different accepting DAA scores");
            }
            let accepting = scores[0];
            let info = client.get_server_info().await?;
            if info.virtual_daa_score >= accepting.saturating_add(CONFIRMATION_DEPTH_DAA) {
                return Ok((accepting, info.virtual_daa_score));
            }
        }
        if started.elapsed() >= CONFIRMATION_TIMEOUT {
            bail!(
                "confirmation is unresolved after {} seconds; state remains pending and no retry was sent",
                CONFIRMATION_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn print_prepared(stage: u8, prepared: &PreparedSnapshotTransaction, outputs: &[ExpectedOutput]) {
    println!("\n=== stage {stage}: {} ===", prepared.evidence.label);
    println!("txid    {}", prepared.evidence.transaction_id);
    println!(
        "mass    compute {} / transient {} / storage {:?}",
        prepared.evidence.mass.compute,
        prepared.evidence.mass.transient,
        prepared.evidence.mass.storage
    );
    println!(
        "fee     {} sompi (lab floor {})",
        prepared.evidence.mass.fee_sompi, prepared.evidence.mass.lab_fee_estimate_sompi
    );
    for output in outputs {
        println!(
            "out {:>2}  {:<18} {:>14} sompi  {}",
            output.index, output.role, output.amount, output.address
        );
    }
    println!("engine  PASS · {}", prepared.evidence.verdict);
}

fn write_artifact(
    state: &Tn10State,
    stage: u8,
    name: &str,
    prepared: &PreparedSnapshotTransaction,
    outputs: &[ExpectedOutput],
) -> Result<PathBuf> {
    let path = secure_dir()?.join(format!(
        "tn10-snapshot-stage-{stage}-{}.json",
        prepared.evidence.transaction_id
    ));
    if path.exists() {
        bail!("immutable artifact already exists at {}", path.display());
    }
    let artifact = StageArtifact {
        schema: "kasmelt-tn10-snapshot-stage/v1",
        warning:
            "SYNTHETIC HOLDER SNAPSHOT — proves covenant mechanics only; not a KRC-20 balance claim",
        network: "testnet-10",
        stage,
        name,
        expected_txid: &prepared.evidence.transaction_id,
        snapshot_manifest_json: &state.manifest_json,
        token_id: &state.token_id,
        controller_id: &state.controller_id,
        pins: &state.pins,
        evidence: &prepared.evidence,
        input_entries: &prepared.transaction.entries,
        transaction: &prepared.transaction.tx,
        expected_outputs: outputs,
    };
    write_json_atomic(&path, &artifact)?;
    Ok(path)
}

fn apply_updates(state: &mut Tn10State, updates: &PendingUpdates) {
    if let Some(value) = &updates.token_id {
        state.token_id = Some(value.clone());
    }
    if let Some(value) = &updates.controller_id {
        state.controller_id = Some(value.clone());
    }
    if let Some(value) = &updates.controller_program_sha256 {
        state.controller_program_sha256 = Some(value.clone());
    }
    if let Some(value) = &updates.current_root {
        state.current_root = value.clone();
    }
    if let Some(value) = &updates.reserve_amount {
        state.reserve_amount = value.clone();
    }
}

async fn settle_pending(client: &KaspaRpcClient, state: &mut Tn10State) -> Result<()> {
    let pending = state.pending.clone().context("no pending stage")?;
    println!(
        "waiting stage {} {} · {}",
        pending.stage, pending.status, pending.expected_txid
    );
    let (accepting_daa, settled_virtual_daa) =
        wait_for_confirmation(client, &pending.outputs).await?;
    apply_updates(state, &pending.updates);
    state.receipts.push(StageReceipt {
        stage: pending.stage,
        name: pending.name.clone(),
        transaction_id: pending.expected_txid.clone(),
        accepting_daa,
        settled_virtual_daa,
        explorer: format!(
            "https://explorer-tn10.kaspa.org/txs/{}",
            pending.expected_txid
        ),
        artifact_path: pending.artifact_path.clone(),
        outputs: pending.outputs.clone(),
    });
    state.next_stage = pending.stage + 1;
    state.pending = None;
    save_state(state)?;
    println!(
        "CONFIRMED stage {} at DAA {} · settled at {}",
        pending.stage, accepting_daa, settled_virtual_daa
    );
    println!(
        "https://explorer-tn10.kaspa.org/txs/{}",
        pending.expected_txid
    );
    Ok(())
}

async fn submit_prepared(
    client: &KaspaRpcClient,
    state: &mut Tn10State,
    stage: u8,
    name: &str,
    prepared: PreparedSnapshotTransaction,
    outputs: Vec<ExpectedOutput>,
    updates: PendingUpdates,
) -> Result<()> {
    let artifact = write_artifact(state, stage, name, &prepared, &outputs)?;
    state.pending = Some(PendingStage {
        stage,
        name: name.to_string(),
        status: "prepared".to_string(),
        expected_txid: prepared.evidence.transaction_id.clone(),
        artifact_path: artifact.display().to_string(),
        submitted_at_virtual_daa: None,
        outputs,
        updates,
    });
    save_state(state)?;

    // Submit the exact in-memory transaction serialized into the artifact;
    // there is no dry-run rebuild between review and broadcast.
    let returned = submit(client, &prepared.transaction.tx).await?;
    let expected = state
        .pending
        .as_ref()
        .context("pending state disappeared")?
        .expected_txid
        .clone();
    if returned != expected {
        bail!("node returned txid {returned}, expected {expected}");
    }
    let daa = client.get_server_info().await?.virtual_daa_score;
    let pending = state
        .pending
        .as_mut()
        .context("pending state disappeared")?;
    pending.status = "submitted".to_string();
    pending.submitted_at_virtual_daa = Some(daa);
    save_state(state)?;
    println!("SUBMITTED {returned}");
    settle_pending(client, state).await
}

async fn init(rpc: Option<&str>) -> Result<()> {
    let path = state_path()?;
    if path.exists() {
        bail!(
            "{} already exists; use `status` rather than replacing live state",
            path.display()
        );
    }
    let funding = load_key(&funding_key_path()?).context(
        "the funded TN10 key is missing; run `snapshot_tn10 keygen` and fund its address with testnet-10 KAS first",
    )?;
    let authority = load_or_create_role_key(&authority_key_path()?)?;
    let claimant = load_or_create_role_key(&claimant_key_path()?)?;
    if owner(&funding) == owner(&authority)
        || owner(&funding) == owner(&claimant)
        || owner(&authority) == owner(&claimant)
    {
        bail!("role keys unexpectedly collide");
    }

    let client = connect_checked(rpc).await?;
    let info = client.get_server_info().await?;
    let rpc_url = client
        .url()
        .or_else(|| rpc.map(str::to_string))
        .context("connected client did not expose its concrete RPC URL")?;
    let claimant_address = address(&claimant).to_string();
    let source = SnapshotSource {
        network: "testnet-10".to_string(),
        ticker: "TN10POC".to_string(),
        krc_deploy_id: synthetic_hash(b"KASMELT/SYNTHETIC-KRC-DEPLOY/TN10/v1"),
        checkpoint: SnapshotCheckpoint {
            daa_score: info.virtual_daa_score.to_string(),
            muhash: synthetic_hash(b"NOT-A-KRC-MUHASH/KASMELT-TN10-MECHANICS/v1"),
            indexer: "synthetic-tn10-mechanics-only/no-krc-indexer".to_string(),
        },
        holders: vec![SourceHolder {
            address: claimant_address.clone(),
            amount: SYNTHETIC_AMOUNT.to_string(),
        }],
    };
    let snapshot = Snapshot::from_source(source.clone())?;
    let plan = SnapshotNetworkPlan::new(snapshot.clone(), owner(&authority))?;
    let pins = capture_pins()?;
    let state = Tn10State {
        version: STATE_VERSION,
        network: "testnet-10".to_string(),
        claim: "SYNTHETIC MECHANICS TEST ONLY — NOT KRC-20 STATE EVIDENCE".to_string(),
        rpc_url,
        funding_address: address(&funding).to_string(),
        authority_address: address(&authority).to_string(),
        claimant_address,
        source,
        manifest_json: snapshot.manifest_json.clone(),
        manifest_commitment: hex::encode(snapshot.manifest_commitment),
        initial_root: hex::encode(snapshot.initial_root),
        current_root: hex::encode(snapshot.initial_root),
        reserve_amount: snapshot.total.to_string(),
        token_program_sha256: sha256_bytes(plan.token_program()),
        controller_program_sha256: None,
        token_id: None,
        controller_id: None,
        next_stage: 1,
        pins,
        pending: None,
        receipts: vec![],
    };
    // Make sure funding exists before freezing the launch manifest.
    select_initial_funding(&client, &funding).await?;
    save_state(&state)?;
    println!("\ninitialized {}", path.display());
    println!("network   testnet-10");
    println!("funding   {}", state.funding_address);
    println!("authority {}", state.authority_address);
    println!("claimant  {}", state.claimant_address);
    println!("root      {}", state.initial_root);
    println!("manifest  {}", state.manifest_commitment);
    println!("\nSYNTHETIC SNAPSHOT: this proves mechanics, never a KRC balance.");
    Ok(())
}

fn status(state: &Tn10State) {
    println!("network   {}", state.network);
    println!("claim     {}", state.claim);
    println!("rpc       {}", state.rpc_url);
    println!("manifest  {}", state.manifest_commitment);
    println!("root      {}", state.current_root);
    println!("reserve   {}", state.reserve_amount);
    println!(
        "token     {}",
        state.token_id.as_deref().unwrap_or("pending")
    );
    println!(
        "controller {}",
        state.controller_id.as_deref().unwrap_or("pending")
    );
    println!("confirmed {}/5", state.receipts.len());
    println!("next      {}", state.next_stage);
    if let Some(pending) = &state.pending {
        println!(
            "pending   stage {} · {} · {}",
            pending.stage, pending.status, pending.expected_txid
        );
    }
    for receipt in &state.receipts {
        println!(
            "tx{}       {} · DAA {}",
            receipt.stage, receipt.transaction_id, receipt.accepting_daa
        );
    }
}

async fn stage(stage: u8, submit: bool, rpc_override: Option<&str>) -> Result<()> {
    if !(1..=5).contains(&stage) {
        bail!("stage must be between 1 and 5");
    }
    let mut state = load_state()?;
    verify_pins(&state)?;
    let rpc = rpc_override.unwrap_or(&state.rpc_url);
    let client = connect_checked(Some(rpc)).await?;

    if state.pending.is_some() {
        let pending_stage = state.pending.as_ref().expect("checked").stage;
        if pending_stage != stage {
            bail!("stage {pending_stage} is unresolved; refusing stage {stage}");
        }
        return settle_pending(&client, &mut state).await;
    }
    if state.next_stage != stage {
        bail!(
            "state expects stage {}, not {}; completed stages cannot be rebuilt",
            state.next_stage,
            stage
        );
    }

    let (funding_key, authority_key, claimant_key) = verify_keys(&state)?;
    let plan = build_plan(&state, &authority_key)?;
    let fee = LIVE_TN10_FEE;

    let (name, prepared, labels, updates) = match stage {
        1 => {
            let funding = select_initial_funding(&client, &funding_key).await?;
            let result = plan.prepare_token_genesis(funding, &funding_key, fee)?;
            (
                "token genesis",
                result.prepared,
                vec!["token", "change"],
                PendingUpdates {
                    token_id: Some(hex::encode(result.token_id)),
                    controller_id: None,
                    controller_program_sha256: None,
                    current_root: None,
                    reserve_amount: None,
                },
            )
        }
        2 => {
            let token_id = parse_hex32(
                "token id",
                state.token_id.as_deref().context("token id missing")?,
            )?;
            let funding = fetch_expected(&client, &receipt_output(&state, 1, "change")?).await?;
            let result = plan.prepare_controller_genesis(token_id, funding, &funding_key, fee)?;
            (
                "controller genesis",
                result.prepared,
                vec!["controller", "change"],
                PendingUpdates {
                    token_id: None,
                    controller_id: Some(hex::encode(result.controller_id)),
                    controller_program_sha256: Some(sha256_bytes(&result.controller_program)),
                    current_root: None,
                    reserve_amount: None,
                },
            )
        }
        3 => {
            let token_id = parse_hex32(
                "token id",
                state.token_id.as_deref().context("token id missing")?,
            )?;
            let controller_id = parse_hex32(
                "controller id",
                state
                    .controller_id
                    .as_deref()
                    .context("controller id missing")?,
            )?;
            let token_cell = fetch_expected(&client, &receipt_output(&state, 1, "token")?).await?;
            let funding = fetch_expected(&client, &receipt_output(&state, 2, "change")?).await?;
            let result = plan.prepare_reserve_handoff(
                token_id,
                controller_id,
                token_cell,
                funding,
                &authority_key,
                &funding_key,
                fee,
            )?;
            (
                "full-supply reserve handoff",
                result.prepared,
                vec!["reserve", "change"],
                PendingUpdates {
                    token_id: None,
                    controller_id: None,
                    controller_program_sha256: None,
                    current_root: None,
                    reserve_amount: None,
                },
            )
        }
        4 => {
            let token_id = parse_hex32(
                "token id",
                state.token_id.as_deref().context("token id missing")?,
            )?;
            let controller_id = parse_hex32(
                "controller id",
                state
                    .controller_id
                    .as_deref()
                    .context("controller id missing")?,
            )?;
            let controller =
                fetch_expected(&client, &receipt_output(&state, 2, "controller")?).await?;
            let reserve = fetch_expected(&client, &receipt_output(&state, 3, "reserve")?).await?;
            let funding = fetch_expected(&client, &receipt_output(&state, 3, "change")?).await?;
            let result = plan.prepare_claim(
                token_id,
                controller_id,
                0,
                controller,
                reserve,
                funding,
                &funding_key,
                fee,
            )?;
            (
                "Merkle claim",
                result.prepared,
                vec!["reserve", "recipient", "controller", "change"],
                PendingUpdates {
                    token_id: None,
                    controller_id: None,
                    controller_program_sha256: None,
                    current_root: Some(hex::encode(result.root_after)),
                    reserve_amount: Some(result.reserve_amount_after.to_string()),
                },
            )
        }
        5 => {
            let token_id = parse_hex32(
                "token id",
                state.token_id.as_deref().context("token id missing")?,
            )?;
            let recipient =
                fetch_expected(&client, &receipt_output(&state, 4, "recipient")?).await?;
            let funding = fetch_expected(&client, &receipt_output(&state, 4, "change")?).await?;
            let result = plan.prepare_recipient_split(
                token_id,
                0,
                recipient,
                funding,
                &claimant_key,
                owner(&funding_key),
                &funding_key,
                fee,
            )?;
            (
                "claimed-recipient spend",
                result.prepared,
                vec!["claimant-half", "funding-half", "change"],
                PendingUpdates {
                    token_id: None,
                    controller_id: None,
                    controller_program_sha256: None,
                    current_root: None,
                    reserve_amount: None,
                },
            )
        }
        _ => unreachable!(),
    };

    let outputs = expected_outputs(&prepared.transaction.tx, &labels)?;
    print_prepared(stage, &prepared, &outputs);
    if !submit {
        println!("\nDRY RUN · nothing broadcast. Add --submit to send this exact stage.");
        return Ok(());
    }
    submit_prepared(&client, &mut state, stage, name, prepared, outputs, updates).await
}

fn usage() -> &'static str {
    "usage:\n  snapshot_tn10 keygen\n  snapshot_tn10 init [--rpc URL]\n  snapshot_tn10 status\n  snapshot_tn10 stage <1|2|3|4|5> [--submit] [--rpc URL]"
}

fn option_value<'a>(args: &'a [String], flag: &str) -> Result<Option<&'a str>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .with_context(|| format!("{flag} requires a value"))?;
    if value.starts_with("--") {
        bail!("{flag} requires a value");
    }
    Ok(Some(value))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).context(usage())?;
    let rpc = option_value(&args, "--rpc")?;
    match command {
        "keygen" => {
            let key = load_or_create_role_key(&funding_key_path()?)?;
            println!("testnet funding address: {}", address(&key));
            Ok(())
        }
        "init" => init(rpc).await,
        "status" => {
            status(&load_state()?);
            Ok(())
        }
        "stage" => {
            let number = args
                .get(1)
                .context(usage())?
                .parse::<u8>()
                .context("stage must be an integer from 1 to 5")?;
            stage(number, args.iter().any(|arg| arg == "--submit"), rpc).await
        }
        _ => bail!(usage()),
    }
}
