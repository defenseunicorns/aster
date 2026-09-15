# Reconciliation bake-off

This bake-off evaluates alternative set-reconciliation techniques without
changing Aster's production protocol. The first candidate is the public Rust
[`negentropy` crate, exactly version 0.5.1][negentropy-crate]. It is an
`aster-lab` development dependency only. Its messages are not part of Aster's
wire format, and its decoder is not exposed to peers.

The harness answers a narrow question: for valid inputs, how do reconciliation
work, causal message depth, and encoded protocol payload change with set size,
distribution shape, and symmetric difference? It is not interoperability,
security, denial-of-service, loss-recovery, or production-readiness evidence.

## Identifier mapping

Aster reconciles typed 33-byte `ObjectId` values: one object-kind byte followed
by a 32-byte identifier. Negentropy accepts exactly 32-byte identifiers paired
with a `u64` ordering value. The semantic-v1 comparison therefore always runs
fixed sessions for `SourceEnvelope` and `BlobChunk`, even when a kind is empty.
For each kind it runs both left-initiated and right-initiated directions because
the crate exposes difference lists only to its initiator. Both peers therefore
learn their missing identifiers, matching Aster's full-duplex result visibility
without inventing an unmeasured result message. The candidate passes the
unchanged 32-byte Aster identifier and uses ordering value `0`. Results from
different object kinds must never be combined into one Negentropy set or
compared after dropping the kind discriminator. Fixed kind/direction sessions
prevent the harness from using omniscient knowledge of which kinds happen to
exist only on the remote peer.

This mapping preserves Aster's type separation and avoids introducing clock
semantics into the experiment. A production design would also have to retain
Aster's authorization checks, object validation, and fetch protocol; Negentropy
only identifies differences between sets.

## Known limits of this comparison

- The harness exercises an honest exchange: both sides emit valid Negentropy
  messages. It does not establish that the candidate safely parses hostile
  network input.
- The two byte counters have deliberately different scopes. Aster reports
  complete canonical sync-message CBOR after exercising both its production
  encoder and decoder. Negentropy reports raw candidate payload bytes. Those
  payloads omit the authenticated Aster wrapper a production adapter would need
  for deterministic initiator/responder roles, exchange and object-kind
  binding, replay and stale-frame handling, reconnect state, and multiplexing.
  Both counters exclude authenticated-transport and fragmentation overhead.
  The output identifies the scope as `aster_sync_cbor` or
  `negentropy_raw_payload`; the numbers are not an apples-to-apples carrier-byte
  claim. Aster's count includes each peer's encoded `WANT` object request after
  discovery. Negentropy's count ends when both reverse-role sessions identify
  the differences; it includes no equivalent object-request message. The output
  marks that distinction with `includes_object_requests` and retains Aster's
  `want_bytes` as a separately subtractable field.
- Version 0.5.1 decodes an ID-list count and uses it to reserve a `HashSet`
  before proving that the input contains that many 32-byte identifiers. This
  untrusted preallocation is a production blocker. Admission would require a
  strict bounded decoder that validates the count against remaining bytes
  before allocation, plus malicious-frame tests and fuzzing. The relevant
  implementation is in the published VCS snapshot's
  [`lib.rs`][negentropy-lib] and
  [`encoding.rs`][negentropy-encoding].
- Negentropy requires a frame-size limit of either zero (unlimited) or at least
  4096 bytes. Smaller carriers would need an authenticated outer fragmentation
  and reassembly layer. This bake-off's byte count does not by itself prove
  suitability for a small-MTU physical carrier.
- Its range fingerprint is 16 bytes (128 bits), so a fingerprint collision is
  a residual possibility. Aster's current exact reconciliation must not be
  silently replaced by this probabilistic result. See the published VCS
  snapshot's
  [`constants.rs`][negentropy-constants] and fingerprint implementation in
  [`storage.rs`][negentropy-storage].
- Negentropy is an alternating set-comparison protocol. It does not itself
  claim lossy delivery, reordering, retransmission, session persistence, or
  restart recovery. Those properties would remain Aster transport and runtime
  responsibilities. The current harness makes no loss or restart claim.
- The bundled vector storage materializes, sorts, and seals the complete set.
  Its default fingerprint method scans the requested range. Measurements must
  therefore report build work separately from reconciliation work; a future
  persistent range index could have a different profile.
- Build timing starts from the already-selected typed `ObjectId` sets. It
  includes Aster inventory construction or Negentropy per-kind mapping, vector
  construction, sorting, and sealing. Reconciliation timing includes Aster's
  current selected-inventory clones and decode work, or Negentropy's raw-frame
  parsing. It excludes authorization-query and durable-store selection work on
  both sides. Release-profile timings are machine-local comparison data, not a
  portable performance claim.
- Large divergence can approach explicit transfer of the identifiers. Results
  for small deltas must not be generalized. The matrix adds 10%, 50%, and 100%
  per-side divergence to the fixed delta cases and emits bounded error rows
  instead of concealing a message, parser, or reducer ceiling.

Negentropy's range-based approach is intended for reconciling sets that mostly
overlap. Its published algorithmic basis describes communication proportional
to the symmetric difference with logarithmic rounds under its model
([paper][negentropy-paper]); the bake-off measures the concrete Rust crate and
Aster framing assumptions rather than treating that result as a deployment
guarantee.

## Minisketch control candidate

Minisketch is not currently a dependency or a production-path proposal. A
future lab control may pin the current upstream C++ implementation at commit
[`4a179c61e3cbe3ac2b3c027764ce8eb5183155e1`][minisketch-upstream] and place it
behind a separately built comparator or a narrowly audited internal adapter.
It would test only the sparse-difference case: derive unpredictable,
session-specific 64-bit tokens from Aster `ObjectId` values, enforce a small
decode-capacity ceiling, and fall back to Aster's exact Merkle reconciliation
whenever decoding fails, exceeds capacity, or does not reproduce the expected
root. A Minisketch result must never authorize an object or replace final exact
verification. The upstream [protocol guidance][minisketch-protocol-tips]
explains the salt, collision, capacity, and denial-of-service constraints that
such a control must preserve.

Do **not** add the published `minisketch-rs` 0.1.9 crate. Its safe
`deserialize` method can pass an undersized slice to a native read, while its
safe `serialize` length check is reversed and can pass an undersized slice to a
native write ([wrapper source][minisketch-rs-buffers]). It also embeds the much
older native commit [`de98387a...`][minisketch-rs-native], rather than the
explicitly reviewed upstream revision above. These are memory-safety and
provenance blockers even for a test dependency.

## Running the matrix

Install the repository's pinned tools, then run the bounded default matrix:

```sh
mise install
mise run reconcile-bakeoff
```

The default covers 1, 256, and 1,000 items per side, uniform and clustered
distributions, applicable fixed per-side differences from 0, 1, 10, 100, and
1,000, and 10%, 50%, and 100% divergence. Duplicate and oversized cases are
omitted. Each side has the stated cardinality, so the reported symmetric
difference is twice the requested per-side difference.

The 10,000-item matrix is opt-in so the normal development loop remains short:

```sh
mise run reconcile-bakeoff-scale
```

This and every other named non-`*-report` task are gates: after emitting every
row and a final summary, they exit nonzero if either implementation reported an
algorithm error or any result differed from the exact oracle. To keep any
algorithm error from determining the process exit status, use the explicitly
algorithm-error-tolerant diagnostic command; oracle mismatches still fail:

```sh
mise run reconcile-bakeoff-scale-report
```

The 100,000-item matrix is deliberately opt-in because it consumes materially
more time and memory:

```sh
mise run reconcile-bakeoff-full
```

The corresponding algorithm-error-tolerant diagnostic command is
`mise run reconcile-bakeoff-full-report`.

The named tasks fix their caps at 1,000, 10,000, or 100,000 items. When invoking
the test directly, `ASTER_BAKEOFF_MAX_ITEMS` defaults to `1000`, rejects values
above the hard 100,000-item ceiling, and may be set to an intermediate cap. It
selects the predefined cardinalities at or below that cap; it does not create a
new row at the cap itself:

```sh
ASTER_BAKEOFF_MAX_ITEMS=5000 ASTER_BAKEOFF_ALLOW_ALGORITHM_ERRORS=0 \
  cargo test --release --locked -p aster-lab --test reconciliation_bakeoff \
  emit_reconciliation_bakeoff_matrix -- --ignored --nocapture
```

The command runs the release profile and emits versioned tab-separated records.
Each successful row identifies the algorithm, shape, set size, requested and
actual difference, build and reconciliation time, protocol-message count,
maximum causal message depth, byte-count scope, encoded bytes, peak pending
encoded bytes, both-peer result visibility, whether object requests are
included, and whether that concrete run matched the exact oracle. An
`oracle_match` is not proof that a probabilistic protocol is exact;
`production_exact_verification_required=true` records that Negentropy still
needs exact final verification. `fallback_exercised=false` means this harness
does not implement or claim a production fallback. Bounded algorithm failures
are emitted as `status=error` rows and do not prevent later matrix cases from
running. The final `status=summary` row records row, algorithm-error, and
oracle-mismatch totals. A gating command fails after all rows are preserved when
either total is nonzero. Only the explicitly named `*-report` tasks permit
algorithm-error rows to exit successfully; oracle mismatches always fail.

Treat timing as a local benchmark, not a portable performance claim. Record the
host, build profile, toolchain, and command when preserving results. Promotion
beyond `aster-lab` requires separate adversarial parser work, independent
interoperability, bounded-resource tests, and transport tests under loss,
reordering, interruption, and restart.

## Public sources

- [`negentropy` 0.5.1 on crates.io][negentropy-crate]
- [Published 0.5.1 VCS snapshot][negentropy-vcs]
- [Published 0.5.1 API documentation][negentropy-docs]
- [Negentropy protocol reference and cross-language test suite][negentropy-reference]
- [Set reconciliation paper][negentropy-paper]
- [MIT dependency license][negentropy-license]
- [Pinned upstream Minisketch control][minisketch-upstream]
- [Minisketch protocol and security guidance][minisketch-protocol-tips]
- [`minisketch-rs` unsafe buffer handling][minisketch-rs-buffers]
- [`minisketch-rs` embedded native revision][minisketch-rs-native]

[negentropy-crate]: https://crates.io/crates/negentropy/0.5.1
[negentropy-vcs]: https://github.com/rust-nostr/negentropy/tree/d6b555ee3aa0413e597ac1e289d70c739c464b27
[negentropy-docs]: https://docs.rs/negentropy/0.5.1/negentropy/
[negentropy-lib]: https://github.com/rust-nostr/negentropy/blob/d6b555ee3aa0413e597ac1e289d70c739c464b27/src/lib.rs
[negentropy-encoding]: https://github.com/rust-nostr/negentropy/blob/d6b555ee3aa0413e597ac1e289d70c739c464b27/src/encoding.rs
[negentropy-constants]: https://github.com/rust-nostr/negentropy/blob/d6b555ee3aa0413e597ac1e289d70c739c464b27/src/constants.rs
[negentropy-storage]: https://github.com/rust-nostr/negentropy/blob/d6b555ee3aa0413e597ac1e289d70c739c464b27/src/storage.rs
[negentropy-reference]: https://github.com/hoytech/negentropy
[negentropy-paper]: https://arxiv.org/abs/2212.13567
[negentropy-license]: https://github.com/rust-nostr/negentropy/blob/d6b555ee3aa0413e597ac1e289d70c739c464b27/LICENSE
[minisketch-upstream]: https://github.com/bitcoin-core/minisketch/tree/4a179c61e3cbe3ac2b3c027764ce8eb5183155e1
[minisketch-protocol-tips]: https://github.com/bitcoin-core/minisketch/blob/4a179c61e3cbe3ac2b3c027764ce8eb5183155e1/doc/protocoltips.md
[minisketch-rs-buffers]: https://github.com/eupn/minisketch-rs/blob/31f1c440be6fb585f6ec02b34fa4d0ca61e99edb/src/lib.rs#L310-L341
[minisketch-rs-native]: https://github.com/sipa/minisketch/tree/de98387a83ccd5dd7399333ddcf52e1d4f344e53
