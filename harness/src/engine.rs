//! Budgeted Kaspa script execution. Adapted from Kascov's preflight; see NOTICE.md.

use kaspa_consensus_core::{
    hashing::sighash::SigHashReusedValuesUnsync,
    tx::{MutableTransaction, Transaction},
};
use kaspa_txscript::{
    caches::Cache, covenants::CovenantsContext, EngineCtx, EngineFlags, TxScriptEngine,
};

pub struct InputExec {
    pub input_index: usize,
    pub pass: bool,
    pub verdict: String,
    pub script_units_used: u64,
}

pub fn preflight_execute(
    tx: &MutableTransaction<Transaction>,
    indices: &[usize],
) -> Vec<InputExec> {
    indices
        .iter()
        .map(|&index| {
            let mut result = InputExec {
                input_index: index,
                pass: false,
                verdict: "missing input or UTXO".into(),
                script_units_used: 0,
            };
            if tx.entries.len() != tx.tx.inputs.len() || tx.entries.iter().any(Option::is_none) {
                return result;
            }
            let Some(input) = tx.tx.inputs.get(index) else {
                return result;
            };
            let Some(entry) = tx.entries.get(index).and_then(Option::as_ref) else {
                return result;
            };
            let verifiable = tx.as_verifiable();
            let context = match CovenantsContext::from_tx(&verifiable) {
                Ok(context) => context,
                Err(error) => {
                    result.verdict = format!("covenant bindings: {error}");
                    return result;
                }
            };
            let cache = Cache::new(10_000);
            let reused = SigHashReusedValuesUnsync::new();
            let ctx = EngineCtx::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&context);
            let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
                &verifiable,
                input,
                index,
                entry,
                ctx,
                EngineFlags {
                    covenants_enabled: true,
                    ..Default::default()
                },
                input.compute_commit.allowed_script_units(),
            );
            match engine.execute() {
                Ok(()) => {
                    result.pass = true;
                    result.verdict = "script accepted".into();
                }
                Err(error) => result.verdict = error.to_string(),
            }
            result.script_units_used = engine.used_script_units().0;
            result
        })
        .collect()
}
