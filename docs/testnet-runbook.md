# Repeating the synthetic TN10 test

This runbook creates new covenant UTXOs on **testnet-10 only**. It does not migrate a real KRC-20 token. Do not use a mainnet wallet, seed, private key, or real-value funding.

## Before starting

1. Clone this Git repository and run `bash scripts/check.sh`.
2. Use a dedicated test environment with Git and the built workspace available.
3. Ensure a synced testnet-10 wRPC node with UTXO indexing is accessible. The runner can use the public resolver or an explicit compatible endpoint through `--rpc URL`.
4. Keep this checkout and its compiler/binary unchanged throughout a run. Initialization pins the source, executable, compiler, and lockfile; later stages fail closed if those pins differ.

The runner writes restrictive-permission key/state/artifact files under `$HOME/.kasmelt-snapshot/`, separate from the old Kasmelt test directory. It never prints private keys. Back up that directory securely if you need to retain control of the test assets. Do not commit it or serve it over HTTP.

## Generate a dedicated funding address

```sh
target/debug/snapshot_tn10 keygen
```

This creates or reuses the dedicated funding key and prints its public testnet address. Fund it with testnet-10 coins from a faucet or another test wallet. The runner selects a confirmed non-coinbase funding UTXO; coinbase-only funding is not eligible. Inspect dry-run funding requirements and allow enough for native covenant cells plus all five transaction fees. Each transaction has a fixed 2 TKAS fee allowance; the builder verifies its mass and refuses insufficient funding.

## Initialize

```sh
target/debug/snapshot_tn10 init
target/debug/snapshot_tn10 status
```

Initialization connects read-only, generates separate temporary-authority and claimant keys, selects available funding, and freezes a **synthetic one-holder** snapshot. It does not broadcast. The checkpoint score comes from the node; the token identity and MuHash are synthetic labels, not KRC evidence.

Initialization refuses to overwrite an existing ledger. Do not delete a pending run merely to bypass a check. For a separate run use an isolated OS user/environment and new test-only funding.

## Prepare and submit each stage

Run each stage once without `--submit` to inspect the exact planned transaction. Broadcast only after review:

```sh
target/debug/snapshot_tn10 stage 1
target/debug/snapshot_tn10 stage 1 --submit
```

Continue with stages 2 through 5 only after the predecessor is confirmed:

| Stage | Transaction |
| --- | --- |
| 1 | Token genesis: preissue the supply to the temporary authority |
| 2 | Controller genesis: commit the token ID and initial snapshot root |
| 3 | Full-supply reserve handoff to the controller covenant ID |
| 4 | Merkle claim: transfer the complete synthetic allocation |
| 5 | Recipient-authorized split into two conserved token outputs |

`stage N` defaults to **no broadcast**. `stage N --submit` creates a real testnet transaction. The browser console has no equivalent submit route.

Before broadcasting, the runner verifies each known predecessor's exact outpoint, value, script, and covenant ID; checks the actual signed transaction in the local engine; and measures its TN10 compute/transient/storage mass. It persists the signed artifact and expected transaction ID before sending.

## Pending or failed submission

The runner waits until all required outputs are observed and the virtual DAA score is at least 30 beyond their accepting score. This is an observation margin, **not protocol finality**.

If the process times out or receives an uncertain response, inspect `status`, the saved artifact, the expected transaction ID, and the node. Retrying the same pending stage reconciles expected outputs; it does not automatically rebroadcast or construct a conflicting transaction. A transaction that was never accepted may therefore require manual reconciliation. Do not edit the ledger to mark it confirmed, bypass pin checks, or replace the funding key.

Reorg recovery and automated fee replacement are not implemented. A spent/missing predecessor, stale node, changed artifact, or unresolved submission stops progression.

## Inspect results

```sh
target/debug/snapshot_tn10 status
target/debug/snapshot_console
```

The console shows a key-free projection of a local TN10 ledger when one exists. Without one, it displays the separately labelled archived August 26 run. Neither view contacts a node to reverify historical inclusion.

Keep public transaction IDs and program hashes as evidence. Remove private keys, concrete private RPC URLs, local paths, and signing artifacts from any public report. A successful run establishes only the tested mechanics; it is not approval to launch a production distribution.
