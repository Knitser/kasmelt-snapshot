//! Snapshot commitments, covenant transaction construction, and script execution.

pub mod engine;
pub mod snapshot;
pub mod token_state;

use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    mass::units::ComputeBudget,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        ComputeCommit, CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction,
        TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use std::path::PathBuf;

pub const SILVERSCRIPT_REV: &str = "d25bd3427a093c17327ca3d6b9e1aa5f7688c863";

pub struct InputSpec {
    pub outpoint: TransactionOutpoint,
    pub spk: ScriptPublicKey,
    pub value: u64,
    pub covenant_id: Option<[u8; 32]>,
    pub sig_script: Vec<u8>,
}

pub struct OutputSpec {
    pub spk: ScriptPublicKey,
    pub value: u64,
    pub covenant: Option<(u16, [u8; 32])>,
}

/// Populate fixture UTXOs and explicit covenant group bindings.
pub fn build(
    inputs: Vec<InputSpec>,
    outputs: Vec<OutputSpec>,
    budget: u16,
) -> MutableTransaction<Transaction> {
    let entries = inputs
        .iter()
        .map(|input| {
            UtxoEntry::new(
                input.value,
                input.spk.clone(),
                0,
                false,
                input.covenant_id.map(Into::into),
            )
        })
        .collect();
    let inputs = inputs
        .into_iter()
        .map(|input| {
            TransactionInput::new_with_mass(
                input.outpoint,
                input.sig_script,
                0,
                ComputeCommit::ComputeBudget(ComputeBudget(budget)),
            )
        })
        .collect();
    let outputs = outputs
        .into_iter()
        .map(|output| {
            TransactionOutput::with_covenant(
                output.value,
                output.spk,
                output
                    .covenant
                    .map(|(index, id)| CovenantBinding::new(index, id.into())),
            )
        })
        .collect();
    MutableTransaction::with_entries(
        Transaction::new(
            TX_VERSION_TOCCATA,
            inputs,
            outputs,
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        ),
        entries,
    )
}

pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .to_path_buf()
}

/// Set SILVERC for a release build or a custom target directory.
pub fn compiler_path() -> PathBuf {
    std::env::var_os("SILVERC")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository_root().join("target/debug/snapshot-silverc"))
}

pub fn compile(contract: &str, args: &[String]) -> Result<Vec<u8>, String> {
    if !matches!(
        contract,
        "kasmelt-snapshot-token.sil" | "kasmelt-snapshot-controller.sil"
    ) {
        return Err("unsupported contract".to_string());
    }
    let compiler = compiler_path();
    let output = std::process::Command::new(&compiler)
        .arg(repository_root().join("contracts").join(contract))
        .args(args)
        .output()
        .map_err(|e| {
            format!(
                "run {}: {e}; build with cargo build --workspace --locked",
                compiler.display()
            )
        })?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    hex::decode(String::from_utf8_lossy(&output.stdout).trim()).map_err(|e| e.to_string())
}

pub fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .hash(bytes)
        .as_bytes()
        .try_into()
        .expect("32-byte digest")
}

/// Minimal Kaspa script push encoding. Derived from Kascov; see NOTICE.md.
pub fn push(value: &[u8]) -> Vec<u8> {
    let mut out = match value {
        [] => return vec![0],
        [0x81] => return vec![0x4f],
        [v] if (1..=16).contains(v) => return vec![0x50 + v],
        _ if value.len() <= 75 => vec![value.len() as u8],
        _ if value.len() <= 255 => vec![0x4c, value.len() as u8],
        _ if value.len() <= 65535 => {
            let mut prefix = vec![0x4d];
            prefix.extend_from_slice(&(value.len() as u16).to_le_bytes());
            prefix
        }
        _ => {
            let mut prefix = vec![0x4e];
            prefix.extend_from_slice(
                &u32::try_from(value.len())
                    .expect("script push fits u32")
                    .to_le_bytes(),
            );
            prefix
        }
    };
    out.extend_from_slice(value);
    out
}
