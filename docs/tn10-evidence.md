# Recorded TN10 mechanics test

The archived August 26, 2026 run contains five accepted testnet-10 transactions for a synthetic one-holder snapshot. Its final transaction spends and splits the claimed asset into two conserved 500,000-unit outputs.

This is historical evidence, not a new testnet broadcast or a fresh verification of node inclusion at the time of this handoff. The immutable transaction IDs can be inspected independently through a node or explorer. Public explorer availability is not a security assumption of the contracts.

## Receipts

| Stage | Transaction | Accepting DAA | Observed virtual DAA |
| --- | --- | ---: | ---: |
| 1 · token genesis | [`182433bfb393…`](https://explorer-tn10.kaspa.org/txs/182433bfb39331da6f94ae2e6fc51d847371cfdbcb678fc6e65e637368ef945b) | 553951220 | 553951263 |
| 2 · controller genesis | [`5006a86a1239…`](https://explorer-tn10.kaspa.org/txs/5006a86a1239624f23b632ed3f78444032ee79db942ad7f4b728250faac636e8) | 553951550 | 553951592 |
| 3 · full-supply reserve handoff | [`0ff8ff1b9a47…`](https://explorer-tn10.kaspa.org/txs/0ff8ff1b9a47849ef76bfa28c23310eddd95b7544774c92f792ee34953f6a8bd) | 553951835 | 553951872 |
| 4 · Merkle claim | [`bf2b54689e8d…`](https://explorer-tn10.kaspa.org/txs/bf2b54689e8dd09f0270c1d098b7fe4295527f7646fc06815a8c9ac491240503) | 553952213 | 553952250 |
| 5 · claimed-recipient spend | [`f3b6fbf2cde4…`](https://explorer-tn10.kaspa.org/txs/f3b6fbf2cde49c12ee21ad3e23510b1a22499730c0f8e3b4df4799a16843285c) | 553952511 | 553952556 |

The runner used a 30-DAA observation margin. This is an operational gate, not protocol finality.

## Committed identities

```text
token ID       ba12f3cdc6f4d8c0223499ef95312f944556a19c278f6e56ea973852f4019106
controller ID  2895f0a618f17970fa1dd8bafb205b0c4f0cc5e9e6083ad4b2d179de19b03a66
initial root   3825944810b10bf673d769d22cd752f67b673e69799903aa524f1155fa0afd4a
claimed root   c393a33fd78d0104ad83331e73a762fa5e094e89579b7c2d8ff35a2b64abb6de
manifest       8d533ed59193e142ce9ba3b367acb6813ee33c3439ca14a91d1ed3958d91e530
```

Supply was 1,000,000 TN10POC base units. The complete allocation was claimed; the remaining reserve amount was zero. The reserve UTXO still carries native testnet KAS.

## Reproduce the commitments offline

[The evidence JSON](../evidence/tn10-2026-08-26.json) contains only the public snapshot, commitments, program hashes, source hashes, and receipt identifiers. It intentionally omits operational private keys, saved signing artifacts, private RPC details, and workstation paths.

```sh
cargo build --workspace --locked
cargo test --locked -p kasmelt-harness --test tn10_reproduction
target/debug/snapshot_manifest summary fixtures/tn10-snapshot.json
```

The regression reconstructs the exact canonical manifest and initial Merkle root, then compiles both contracts from the pinned public compiler source and compares their SHA-256 hashes with the archived deployment. It does not reconstruct historical funding transactions or authenticate historical inclusion; those are separate node checks.

```text
token program SHA-256       198e052353ae4d88ca304cd796e79a9b7aaaf78dc7549d4ee78c884ffcac41c7
controller program SHA-256  fca3083fcff1866da4d1dcde459d4699ecdc5bf0536136c50c18c0b70e6ad2ac
```

The contract sources are preserved byte-for-byte from the recorded implementation. Supporting build and UI code has been made standalone.

## Test coverage and limits

The current snapshot corpus exercises canonicalization, golden Merkle vectors, 1/2/3/5-holder and padded trees, the maximum 1,024-holder proof, signed setup, sequential full claims, reserve exhaustion, recipient splitting, and live transaction construction from supplied confirmed inputs. Negative cases include replay, stale or transplanted branches, wrong amounts/destinations, reserve inflation, extra inputs/outputs, unchanged roots, invalid singleton successors, native-KAS draining, bad snapshots, and public fixture owners in network preparation.

The historical run itself covered **one synthetic holder**, not many live competing claims. No KRC history or genuine indexer MuHash was verified. The local UI tests and maximum-depth test do not replace a full-network large-distribution test. There is no final-KCC interoperability certification, independent audit, or production approval.
