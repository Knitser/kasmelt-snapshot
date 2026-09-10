# Kasmelt Snapshot

A reference implementation for a one-time KRC-20 holder snapshot migration to native Kaspa covenant tokens.

The distribution is fixed at launch. A holder's Merkle proof releases their exact allocation from a covenant-controlled reserve and retires that entitlement. The old KRC-20 token remains untouched. This is a **snapshot migration, not a continuous lock-and-mint bridge**.

## Status

- Two executable SilverScript contracts: a conserved-supply token and a Merkle claim controller.
- A local purple web console, canonical snapshot/manifest tooling, and transaction builders.
- An archived five-transaction **testnet-10 run from August 26, 2026**, including a successful recipient spend. The holder and checkpoint were synthetic.
- Pinned public dependencies and an offline regression test for the archived manifest and compiled contract hashes.

This is research code for integration and review, **not a production migration service**. It does not retrieve or prove KRC-20 balances. Its token follows a pinned KCC-20 state layout, but does not implement the final/generic KCC ABI. See [compatibility and limitations](docs/integration.md).

## Start here

| If you want to… | Read |
| --- | --- |
| Review the claim rules | [Controller contract](contracts/kasmelt-snapshot-controller.sil) |
| Review token ownership and conservation | [Token contract](contracts/kasmelt-snapshot-token.sil) |
| Integrate a community snapshot | [Integration guide](docs/integration.md) |
| Reproduce a manifest or proof | [Snapshot format and byte codec](docs/snapshot-format.md) |
| Inspect the previous network test | [TN10 evidence](docs/tn10-evidence.md) |
| Run a fresh synthetic network test | [TN10 runbook](docs/testnet-runbook.md) |

## Build and test

Use Git, Rust/Cargo, and the native C/C++ build tools for your platform. This package was verified with Rust 1.96.0 on macOS. The first build is substantial: it compiles the pinned Kaspa engine and SilverScript compiler. Internet access is needed to download their public sources and the locked crates; no access to a private Kascov checkout is required.

```sh
bash scripts/check.sh
```

Build before running the tests: the harness invokes the workspace's `target/debug/snapshot-silverc` executable. For a custom target directory or release build, set `SILVERC` to that executable's absolute path.

## Try the local console

```sh
cargo run --locked --bin snapshot_console
```

Open http://127.0.0.1:8793. If that port is occupied, pass `-- --port 8794`.

Choose a holder, claim the allocation, and try claiming it again. The console executes real covenant scripts against local fixture transactions. It never connects to a wallet or broadcasts a transaction. State is in memory and resets when the process restarts. Do not publish this development server as a community claim service.

## Export a snapshot

```sh
target/debug/snapshot_manifest example > snapshot.json
target/debug/snapshot_manifest summary snapshot.json
target/debug/snapshot_manifest build snapshot.json > manifest.json
target/debug/snapshot_manifest proof snapshot.json 0 > initial-proof.json
```

Amounts are integer **base-unit strings**, not floating-point numbers. The exporter validates and canonicalizes the supplied data; it does not certify that those balances existed. Its proof is for the initial root only. A live claim client must regenerate proofs from the accepted current root after other claims.

## Repository layout

```text
contracts/    SilverScript token and controller
harness/      snapshot codec, builders, local engine adapter, regression tests
compiler/     small CLI around the pinned public SilverScript compiler
deploy/       offline web console, manifest CLI, guarded TN10 runner
fixtures/     synthetic snapshot input
evidence/     key-free historical TN10 record
docs/         format, architecture, integration limits, runbook
vendor/       attributed macOS compatibility patch
```

For a community launch, the remaining work includes independently verified KRC snapshot data, current KCC interoperability, wallet signing, proof-state indexing, multi-holder network testing, and independent security review. [The integration guide](docs/integration.md) separates these obligations from what the existing tests establish.

MIT licensed. See [NOTICE.md](NOTICE.md) for component licenses and attribution.

See [SECURITY.md](SECURITY.md) for the sharing boundary, fixture-key warning, and known upstream dependency caveats.
