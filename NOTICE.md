# Third-party notices

The snapshot implementation is maintained by Michiel Hamblok. The original Rust packages specify the MIT license; that license is preserved in LICENSE.

The state codec, script push encoder, transaction preflight, and TN10 RPC adapters derive from the MIT-licensed Kascov project, copyright 2026 Michiel Hamblok. The handoff contains only the required implementation, with no dependency on Kascov's private repository or indexer service.

The compiler wrapper uses the public Kaspa SilverScript project at revision `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`. Its repository license is preserved in `licenses/SilverScript-ISC.txt`. The wrapper retains the positional constructor parser used by the original test build.

`vendor/block` contains block 0.1.6 by Steven Sheldon, declared MIT in its upstream Cargo manifest. The vendored source, README, attribution, and manifest are retained. The upstream repository has no separate LICENSE file. The local changes are described in `vendor/block/PATCH.md`.

The snapshot design follows the one-time holder commitment discussed by Michael Sutton and other Kaspa contributors. The contracts use the six-field state order from the August 2026 KCC-0020 draft. This attribution does not imply endorsement or an external security review.

Dependencies and their exact source revisions are recorded in Cargo.lock.
