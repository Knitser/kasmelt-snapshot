# Snapshot format and byte codec

This is the versioned wire format implemented by `harness/src/snapshot.rs`. Both the console and `snapshot_manifest` CLI use this parser. Values in the example are fixtures, not a historical token distribution.

## Canonical snapshot input

The UI and `Snapshot::parse_json` accept exactly this object shape; all three structures reject unknown fields:

```json
{
  "network": "testnet-10",
  "ticker": "NACHO",
  "krc_deploy_id": "4242424242424242424242424242424242424242424242424242424242424242",
  "checkpoint": {
    "daa_score": "187654321",
    "muhash": "abababababababababababababababababababababababababababababababab",
    "indexer": "kasmelt-poc-fixture/1"
  },
  "holders": [
    {
      "address": "kaspatest:qpm54elctz55z8j77sjxkuxxt2k9vjvcp0juz7y3h0kp0z2a5qyvkjhyc5n0w",
      "amount": "730000000"
    },
    {
      "address": "kaspatest:qzsyxnv7gleusc34ga78kxhx4ewngsk5nvv58s4h22ngu2j8ufruwz0q63ukq",
      "amount": "1250000000"
    }
  ]
}
```

Strings are intentional: JavaScript must never round token amounts, DAA scores, or 64-bit identifiers.

| Field | Accepted form |
|---|---|
| `network` | Exact `mainnet` or `testnet-10`; aliases are rejected. |
| `ticker` | 1–12 uppercase ASCII letters or digits. |
| `krc_deploy_id` | Exactly 32 bytes as 64 hexadecimal characters; normalized to lowercase. |
| `checkpoint.daa_score` | Canonical unsigned `u64` decimal string: no sign or leading zeros. |
| `checkpoint.muhash` | Exactly 32 bytes as 64 hexadecimal characters; normalized to lowercase. In this POC it is committed metadata, not independently checked. |
| `checkpoint.indexer` | At most 120 UTF-8 bytes, non-blank, with no leading or trailing whitespace. |
| `holders` | 1–1,024 entries. Input order is ignored. |
| `holders[].address` | Correct network prefix, exactly 32 owner bytes, and either Schnorr pubkey (`0x00`) or P2SH (`0x03`). ECDSA addresses fail closed. |
| `holders[].amount` | Canonical positive decimal `i64` string. No zero, exponent, fraction, sign, or leading zeros. |

Balances must already be aggregated per owner. After address decoding, duplicate `(owner_scheme, owner[32])` tuples are rejected instead of summed. The checked sum of all balances must fit positive KCC `int`, currently at most `9,223,372,036,854,775,807` base units.

Addresses are rewritten to the Kaspa library's canonical string, then holders are sorted lexicographically by:

```text
(owner_scheme byte, owner[32] raw bytes)
```

The sorted zero-based position is the holder's permanent Merkle index. Reordering source JSON therefore produces the same manifest and root.

## Byte-exact snapshot and Merkle codec

The codec identifier is:

```text
kasmelt-snapshot-v1/blake2b256/full-claim
```

All Merkle/context hashes below are unkeyed BLAKE2b-256. Concatenation has no implicit length or separator beyond the bytes shown. `u32le`, `u64le`, and positive `i64le` are fixed-width little-endian. UTF-8 lengths are byte lengths.

### Snapshot context

```text
context_preimage =
    UTF8("KASMELT/SNAPSHOT-CONTEXT/v1\0")
  || u32le(len(network)) || UTF8(network)
  || u32le(len(ticker))  || UTF8(ticker)
  || krc_deploy_id[32]
  || u64le(daa_score)
  || checkpoint_muhash[32]
  || u32le(len(indexer)) || UTF8(indexer)

context = BLAKE2b-256(context_preimage)
```

### Leaves and branches

For sorted holder `i`:

```text
entitlement_leaf(i) = BLAKE2b-256(
    0x00
  || context[32]
  || u64le(i)
  || owner_scheme[1]
  || owner[32]
  || positive_i64le(amount)
)

node(left, right) = BLAKE2b-256(
    0x01 || left[32] || right[32]
)

claimed_leaf(i) = BLAKE2b-256(
    0x02 || context[32] || u64le(i)
)

padding_leaf(i) = BLAKE2b-256(
    0x03 || context[32] || u64le(i)
)
```

The tree width is `next_power_of_two(max(holder_count, 2))`. Entitlement leaves occupy indices `0` through `holder_count - 1`; deterministic padding leaves fill the remaining indices. Adjacent leaves are hashed as ordered `(left, right)` pairs until one root remains.

A proof contains exactly `depth` siblings, bottom-up. At each level, an even cursor hashes `node(current, sibling)` and an odd cursor hashes `node(sibling, current)`, then shifts the cursor right by one bit. The controller rejects an index outside the real holder count, so a padding leaf can never be claimed.

This POC permits only a **full claim**. The accepted transition replaces `entitlement_leaf(i)` with `claimed_leaf(i)`. A second use of that proof fails against the new root. A proof prepared for another holder before the root moves is also stale and must be regenerated.

### Manifest commitment

The canonical manifest contains the codec string, source identity/checkpoint, computed context and initial root, tree depth, total, and the complete sorted holder list with decoded owner tuples. Top-level keys are emitted in this order:

```text
codec, network, ticker, krc_deploy_id, checkpoint_daa_score,
checkpoint_muhash, indexer, context, initial_root, depth, total, holders
```

Each holder emits `index, address, owner_scheme, owner, amount` in that order. Rust serializes the typed structure with `serde_json::to_string_pretty` using its normal two-space pretty layout; there is no trailing newline. The immutable token extension is:

```text
manifest_commitment = BLAKE3-256(UTF8(canonical_manifest_json))
```

The manifest commitment, not the evolving root, stays unchanged in every token UTXO. It is embedded in token genesis, so changing it changes the token genesis program and covenant ID. Publish the generated manifest bytes; reconstructing “equivalent” JSON with different whitespace or key order is not byte-equivalent.

The default four-holder fixture is pinned as a golden interoperability vector:

```text
initial_root        = 2bd10ce7e683ae276b00f5fb744ce867925d09781c908592ef4fd028039ed91a
manifest_commitment = efc1a6cb806f1d471b92f03857883f33c4bb9eb14b0d2cac9ed85b3b5f7070f2
```
