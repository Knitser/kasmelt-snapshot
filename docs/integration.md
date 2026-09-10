# Community migration integration

This package provides the covenant mechanism and a reproducible reference implementation. It is not a complete community bridge backend. This guide identifies what can be reused and what an integrating team must supply.

## Trust model

The one-time snapshot approach follows the proposal described by Michael Sutton: agree on one historical KRC-20 distribution, commit it at launch, then enforce claims with native covenants. It does not let a covenant authenticate arbitrary Kasplex API responses. Hashing an API response binds its contents; it does not prove who produced it or whether it reflects valid KRC state.

The initial distribution remains an external trust decision. Independent KRC indexers should reproduce the same checkpoint, rule version, complete holder set, and state commitment before launch. Two agreeing indexers are a useful minimum review gate, not a cryptographic proof of correctness. They must not simply proxy the same API.

After a correct reserve handoff, a proof submitter has no discretion over the amount or destination. The covenant checks those against the committed leaf. Anyone can fund and submit that transaction; no privileged relayer signature is part of the claim path. An unavailable proof server can delay users, so the manifest and state history must be publicly recoverable.

The old KRC-20 token remains valid. A migration does not burn it, freeze it, or guarantee that exchanges and holders will stop valuing it.

## Contract architecture

The implementation uses a preissued reserve rather than a recurring minter. Supply is issued once; each claim splits an allocation from that conserved supply.

```text
Input                         Claim                          Output
controller(root R)       ── Merkle verification ──>      controller(root R')
reserve(N, controller)   ── token conservation ──>       reserve(N - allocation)
fee funding                                             recipient(allocation, owner)
```

The token contract enforces ownership, nonnegative amounts, conservation, disabled borrowing, and an unchanged manifest commitment. The controller enforces the current proof, exact allocation and destination, an authenticated reserve, exactly two token outputs, and one authenticated successor controller. It also constrains the native KAS values of the successor cells.

Claims are all-or-nothing. A successful claim replaces the entitlement leaf with its deterministic claimed marker. Replaying the old proof fails against the successor root. Because there is one controller UTXO, claims are serialized: competing transactions spend the same predecessor, and losing clients must discover the accepted state and rebuild their proofs.

## Launch sequence and temporary authority

The controller must know the token covenant ID, but the reserve must eventually be owned by the controller ID. The bootstrap resolves that dependency in three transactions:

1. Issue the full token supply to a temporary Schnorr deployment key, with the immutable manifest commitment.
2. Create the controller, committing the token ID, initial root, manifest, token template, and claim rules.
3. Transfer the complete supply to `owner_scheme = covenant-id/v1`, with the controller covenant ID as owner.

The temporary key controls the supply until step 3. Do not announce an operational migration after genesis alone. Verify the accepted full-supply handoff, exact reserve/controller scripts, covenant IDs, and all output values first. The reference controller has no administrator repair or rescue entrypoint. An incorrect committed snapshot cannot simply be edited later.

## Reusable entry points

| Component | Role | Boundary |
| --- | --- | --- |
| `Snapshot::parse_json` / `Snapshot::from_source` | Validate, normalize, sort, total, and commit the holder set | Supplied checkpoint and balances are not authenticated |
| `Snapshot::merkle_vector` | Build an initial entitlement proof | Must refresh after accepted claims |
| `SnapshotLab` | Execute setup, claims, and negative cases locally | Deterministic public fixture keys and funding; never broadcast |
| `SnapshotNetworkPlan` | Compile programs and construct transactions from live UTXO inputs | Caller must obtain and verify authoritative chain state |
| `snapshot_manifest` | Export manifest bytes, summary, and initial proof | Offline only; no signing |
| `snapshot_tn10` | Guarded five-stage network mechanics test | Hardcoded one-holder synthetic distribution, not an arbitrary production deployer |
| `snapshot_console` | Demonstrate claims and display receipts | Loopback, in-memory, no wallet or broadcast endpoint |

The local state codec and script-engine adapter were extracted from Kascov into this repository. They do not require a private repository dependency. See [NOTICE](../NOTICE.md).

## Work required for a real community launch

1. **Historical snapshot extraction.** Specify the token deployment identity, accepted checkpoint/hash, indexing rules and version, base-unit precision, blacklist behavior, and treatment of escrow/listing/CEX balances. Current paginated balances are not necessarily a consistent historical snapshot. Preserve all source exports and reconcile their totals.
2. **Independent reproduction.** Define the indexer's exact MuHash input serialization and checkpoint semantics. Compare independently reconstructed full holder sets and commitments, publish differences, and obtain community acceptance before genesis. This package only commits the supplied 32-byte MuHash value; it neither calculates nor authenticates KRC indexer state.
3. **Standard compatibility.** Port the adapter to the agreed KCC dispatch, state/template, owner, leader/delegator, and transfer interfaces. Add independent implementation vectors and wallet/indexer recognition tests. Do not treat the current scripts as final KCC-20 artifacts.
4. **Proof-state service.** Index accepted controller/reserve outpoints, validate transitions, replay root updates, and serve fresh branches. A verifier must reproduce the same state from public data; a server response alone must not authorize a claim. Support rejected competing transactions, reorg rollback, and restart recovery.
5. **Wallet transactions.** Build exact outputs from verified inputs, select fees and native KAS funding, expose wallet/PSKT review and signing, and broadcast only after local verification. A claimed recipient must be able to spend the asset in an independent wallet.
6. **Scale.** The current tree is capped at 1,024 holders and a positive `i64` total. Large communities need deterministic sharding or a separately tested scaling design. Each shard needs a bound identity and reserve, independent root evolution, and verifiable global supply accounting.
7. **Network and security acceptance.** Test many holders, contention, all-entitlements exhaustion, real relay fees and mass, recovery, and downstream composition on a supported testnet. Commission independent contract, codec, transaction-builder, and wallet review before involving real value.

## Compatibility pins

| Component | Pin |
| --- | --- |
| Execution engine and RPC | `kaspanet/rusty-kaspa@98a4ccd8d200853787f227bd4536ac540cf34957` |
| Compiler | `kaspanet/silverscript@d25bd3427a093c17327ca3d6b9e1aa5f7688c863` |
| Token state semantics | `kaspanet/kccs@e31a5a855bdebd3bdc4456e5bd40179e9f98a3e8` |
| Snapshot codec | `kasmelt-snapshot-v1/blake2b256/full-claim` |

SilverScript's own pinned dependencies include a second Rusty Kaspa revision. The compiler boundary passes serialized script bytes, not types from one engine into the other. `Cargo.lock` records both sources. The archived-program test checks the resulting bytes.

The reference exposes SilverScript's numeric dispatch, not the generic KCC-1 transfer dispatch. It uses a local BLAKE2b template commitment rather than the length-delimited BLAKE3 template convention in the pinned KCC-1 draft. Borrowing is disabled. Schnorr and P2SH snapshot owners are accepted; ECDSA owners are rejected. P2SH downstream spending and broad merge/composition remain unproved by this corpus.

The [KCC repository](https://github.com/kaspanet/kccs) lists KCC-1, KCC-2, and KCC-20 as Draft at the September 10, 2026 handoff. Review its current accepted changes before implementing interoperability; do not silently update dependency pins and assume existing covenant IDs or bytes remain compatible.

## Review checklist

- Recompute the exact manifest bytes and root from independently verified source data.
- Audit the bootstrap while the temporary key still owns the reserve.
- Verify conservation, foreign-template decoding, output counts/bindings, native KAS pins, and recipient authorization.
- Reject malformed owners, duplicate decoded owners, overflow, unknown fields, out-of-range proof indices, stale proofs, and changed manifests.
- Publish clean source/compiler/dependency pins and reproducible program commitments.
- Keep operational keys, wallet seeds, and local run ledgers outside this repository.
- Do not expose the local console as an authenticated production API. Its loopback origin/header checks are not user authentication.
- Treat an unproven safety property as open work, not an implicit guarantee.
