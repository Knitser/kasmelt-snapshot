# Security and sharing boundaries

This is a testnet reference implementation, not audited production infrastructure. A passing test suite or dependency scan is not a security certification.

## What is included

- The two snapshot contracts, canonical codec, transaction builders, tests, and local web console.
- A small attributed subset of Kascov's MIT-licensed codec, script execution, push encoding, and RPC-adapter code. Kascov's complete private source tree, indexer, deployment infrastructure, and service configuration are not included.
- Public chain identifiers, program hashes, and synthetic fixture addresses. These identify historical transactions and contracts; they do not authorize spending.
- Optional links to public `kascov.io` transaction pages. Merely opening the console does not call Kascov's API. The offline tooling does not depend on that service.

Public on-chain data should not be confused with permission to copy an entire website, brand asset, private database, user dataset, or unpublished service implementation. Preserve upstream code licenses and attribution. Private GitHub visibility controls access; it does not change the included software licenses.

## Keys and signing artifacts

The local lab and regression tests intentionally use deterministic, publicly derivable fixture keys. **Never fund their addresses, on any network.** They exist so tests can be reproduced. The live builder refuses the known fixture owners and fixture outpoints; that check cannot detect every weak key a caller might invent.

The TN10 runner generates separate random funding, temporary-authority, and claimant keys. No operational keys are included in this repository. New keys, local state ledgers, concrete RPC endpoints, and signed submission artifacts are stored outside the checkout in `$HOME/.kasmelt-snapshot/`. The runner checks Unix file permissions, uses exclusive creation for key files, and never returns secrets through the browser.

Use an isolated, trusted Unix test environment. Windows key-directory ACL enforcement is not implemented. The filesystem guards are not a substitute for protecting the host from other processes running as the same user. Avoid symlinked state directories, simultaneous runner instances, shared backups, public reverse proxies, and cloud-synced key folders.

Ignore rules are defense in depth, not a guarantee. Before every release, inspect the exact staged files and fresh history for `.env` files, keys, credentials, wallet material, operational ledgers, PSKTs, and signed-but-unbroadcast transactions. If an operational secret was ever shared, removing the file is insufficient: replace the credential or move affected assets to fresh keys.

## Trust boundaries

| Boundary | Enforcement / limitation |
| --- | --- |
| Snapshot JSON to commitment | Strict fields, bounded input/holder count, canonical amounts, decoded owner validation, duplicate rejection, checked totals; no KRC-history authenticity proof |
| Proof to claim outputs | Current-root verification, full-leaf retirement, exact destination/amount, token conservation, output bindings and KAS pins |
| Local browser to fixture engine | Loopback-only listener, body/header limits, custom mutation header and origin check; no wallet/RPC/broadcast routes |
| CLI to compiler | Explicit executable path and argument array, fixed contract filename allowlist, pinned public sources; custom `SILVERC` is trusted local configuration |
| RPC to network builder | Testnet-10/sync checks, exact predecessor matching, script/mass preflight; RPC availability and reorg recovery remain operational concerns |
| Bootstrap key to reserve | Temporary key owns the supply until the full handoff is accepted; verify that handoff before treating the migration as operational |

The console is an unauthenticated, in-memory development tool, not a production multi-user claim service. Its CSP permits inline code/styles for the bundled page. A public origin override does not add authentication, tenancy, rate limiting, or durable state.

## Dependency review

Dependency pins are preserved in `Cargo.lock`. The September 10, 2026 handoff review identified [RUSTSEC-2026-0258](https://github.com/hyperium/hyper/security/advisories/GHSA-q83h-524g-xf6h) in `h2` 0.4.15; the handoff lockfile updates it to the patched 0.4.16 release. The Kaspa execution and SilverScript source revisions remain pinned, and the contract reproduction test checks that the compiled program commitments are unchanged.

`cargo audit` also reports upstream maintenance warnings for `async-std`, `atty`, `derivative`, `instant`, `paste`, and `proc-macro-error`, plus the Windows-specific `atty` unaligned-read warning. These are not silently waived or represented as a clean full audit. Reassess them when updating the pinned upstream stack and before supporting Windows or real-value use.

The final handoff scan returned zero vulnerability advisories and seven informational warnings against advisory database commit `b50980aad8b8f14f77e25a97b32dd94bf008b0af`. Withdrawn `chacha20` 0.10.1 and `wide` 1.6.0 lock entries were replaced with 0.10.2 and 1.7.0. The standalone suite passed 29 tests after these updates, including both archived program hashes. This result is dated September 10, 2026 and can become stale.

Run `cargo audit` against a current advisory database before any deployment. It covers known dependency advisories, not novel contract vulnerabilities, external Git repositories in full, business logic, snapshot correctness, or host security. Independent review and the production acceptance work in [the integration guide](docs/integration.md) remain required.
