# B1/B2/C dissemination composition freeze — BVB-724

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


## Outcome first

The smallest runnable differential is complete.

| Arm | Exact temporal-relay result | Responsibility cost | Decision |
|---|---|---|---|
| B1 — immutable p2panda operation over BPv7 | One signed operation crossed A-to-B, survived B restart, crossed B-to-C with A absent, retained its canonical identity and signature, and was inserted into C's p2panda store. Relay plaintext was visible. | 2 durable mechanism families, 5 logical durable instances, 4 runtime transition owners | **Incremental buy.** Retain for one bounded follow-up; this is not production selection. |
| B2 — interactive p2panda `LogSync` over BPv7 | The required one-pass schedule stopped after A `Have`, then C `Have` plus `Done`; C had no operation. Exact upstream `LogSync` completed only after four alternating waves, three B restarts, seven directed peer declarations, and six BP bundles. | 3 durable mechanism families, 7 logical durable instances, 10 runtime transition owners; endpoint protocol state stayed in live memory | **Cost/stop.** Complete the record, but stop this adoption arm for the one-pass scenario. |
| C — thin BPv7 data profile | One unsigned profile crossed the one-pass schedule byte-identically and parsed at C. Relay plaintext was visible; there is no reconciliation or application model. | 1 durable mechanism family, 3 logical durable instances, 4 runtime transition owners | **Control only.** Retain as the mechanics baseline, not as a candidate selection. |

None of these results receives application-delivery, BPSec, requirements-level
QoS, custody, duplicate-bound, loop-bound, process-restart-resume, independent
interoperability, or production-admission credit.

## Immutable freeze

The exact source/build/execution tuple is the append-only `BVB-724` row.

| Item | Frozen value |
|---|---|
| p2panda | v0.7.1, commit `083b48215964e92a564f3c83a1c607b00e94aa64`, archive SHA-256 `1f0f25be7c209d4042b0e84ad07d1e089951f1780762fe8696e27c8524376db4` |
| dtn7-rs | commit `c30181b4b111e2adc5538931c797c0f7190acc4c`, archive SHA-256 `7b7c8207f1c9aa3fc666b2a54a2160203946c48d7236b4d06c5a7073eb7ade1c` |
| Adapter manifest | SHA-256 `57fc48398103cb4175d6a8e21043adce379eace8e15f5b6120ca7dde40ad4c9a` |
| Adapter lock | SHA-256 `1527f4e3b286529411c129ccacce646216dde5873117fe87582cf3c23b89ab52`; 533 packages including root; registry plus frozen local p2panda paths; no git sources |
| Adapter source | SHA-256 `992298043e19fc1a6146685320164fa7e0878b67f32b900953d5ae3bddb43b1c` |
| Adapter binary | SHA-256 `f68a625d54d2e5da680bb0a8152a0886123b294382f281d6a267a289af15d877` |
| Composite SBOM | CycloneDX 1.5; 393 dependency components; SHA-256 `bbe46448f509756848afd736b125a1148dce4ddf68a383e404eabf06f3a6373d` |
| Toolchain | `rustc 1.97.1 (8bab26f4f 2026-07-14)`; `cargo 1.97.1 (c980f4866 2026-06-30)`; `aarch64-apple-darwin` |
| Executed dtn7-rs daemon | debug `dtnd` SHA-256 `dc00874ab000a8687ea71bda4913402772a30a6e78b771955d28b7e807169be1` |
| Unified run | `composition-007`, 2026-08-23T02:10:38Z through 2026-08-23T02:12:11Z |

The adapter built from the frozen graph with `cargo build --locked --offline`.
Any dependency update, network resolution, git source, or package substitution
is outside the freeze. The p2panda and dtn7-rs upstream components are
`MIT OR Apache-2.0`; the evaluator adapter uses the same expression. This exact
research composition is not admitted. Its SBOM is frozen, but no new
composite-graph advisory or license-pass claim is made: `BVB-709` recorded that
disposition as pending, and the qualified upstream findings in the existing
p2panda and BPv7 freezes remain applicable.

Raw source, build, SBOM, daemon state, and trial files remain local and ignored.
The visible raw-evidence manifest is
archived `composition-007.raw-manifest.sha256`.

## Experimental boundary

All arms used dtn7-rs with sled, epidemic routing, loopback MTCP, discovery
disabled, explicit peer declarations, and a 3,600-second bundle lifetime.
Contacts were forced; there was no ambient peer discovery.

For the one-pass schedule, A contacted B while C did not exist, then A and B
stopped. B restarted from the same work directory and contacted C while A was
absent. The drivers first sent SIGINT, then used SIGTERM after the grace period;
this is a crash-like restart, not graceful-shutdown evidence.

The shared source item was:

- payload: `dissemination-comparison-canary-v1-A-to-B-to-C-4a91d872`;
- p2panda operation ID:
  `4928297720be5560bacf493e108b2e31bb89e4f87f4fdc8fbae0ff5db7c105f4`;
- p2panda author:
  `bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5`;
- operation envelope: 259 bytes, SHA-256
  `997b70e6f33a6b1a1e8d885789f0bee5aa44204e3aae3b453a299a76cb5aedac`.

## B1 — immutable operation over BPv7

The adapter used the frozen low-level p2panda `Operation` builder and
`SqliteStore` APIs. A created, signed, validated, and stored one operation; the
adapter framed the raw 186-byte header and 57-byte body without replacing the
operation hash. dtn7-rs carried the 259-byte envelope in one reported 344-byte
bundle. B reported one stored `ForwardPending` bundle before restart. C
received byte-identical bytes, validated the signature, author, topic/log
identity, operation hash, and body, then inserted the operation into a fresh
p2panda SQLite store.

This is narrower than a high-level p2panda `Node` or `StreamPublisher` result.
Earlier local high-level attempts did not produce a runnable temporal handoff
in this environment; their ignored raw evidence is retained. The successful
arm therefore proves a viable immutable-operation seam, not high-level replica
or application behavior.

## B2 — exact interactive LogSync over BPv7

The adapter ran the exact frozen upstream `p2panda_sync::LogSync` state machine
at A and C and serialized each `LogSyncMessage` with Postcard before BP
transport. The behavior is structural: upstream `LogSync` sends local `Have`,
then waits to receive remote `Have` before it can compute `remote_needs` and
send `PreSync` or `Operation`.

The required one-pass schedule therefore stopped precisely:

1. A-to-B carried A's 70-byte `Have` while C was absent.
2. After B restart, B-to-C delivered that `Have` while A had no contact and its
   LogSync process was paused.
3. C emitted its two-byte `Have` and one-byte `Done`; C had no operation.
4. A had to return to receive both responses before it emitted the four-byte
   `PreSync`, 248-byte `Operation`, and one-byte `Done`.
5. Only a fourth B-to-C wave, after another B restart and with A fully absent,
   delivered those final messages to C.

The completed extension used 326 application-frame bytes across six BP
bundles totaling 778 bytes as reported by `dtnsend`. A's receipt recorded four
outgoing and two incoming protocol messages and one sent operation. C's receipt
recorded two outgoing and four incoming messages and one received, signature-
validated operation. C's `OperationReceived` event did not insert that
operation into its SQLite store and did not produce an application effect.

The A LogSync process remained alive but `SIGSTOP`-paused between waves one and
three; C's process remained alive between waves two and four. Thus this run
does not prove protocol-state recovery after endpoint process restart. Durable
mailboxes kept frame files, but the upstream protocol state and per-run dedup
buffer remained volatile.

The adoption stop is narrow and explicit: exact upstream interactive LogSync
over BP does not meet the frozen one-pass temporal-relay topology. Do not add
more contacts, mailbox recovery semantics, or session reconstruction to this
arm unless the product scenario changes or a separately sourced asynchronous
reconciliation protocol is registered. The four-wave completion remains a
useful cost measurement, not scenario credit.

## C — thin BPv7 data-profile control

The evaluator-defined `BPDP0001` envelope contains a version/magic value, an
unverified source label, a BLAKE3 identifier of the payload bytes, and the raw
payload. It is 206 bytes and has SHA-256
`486b0fdaab204ffc01d94d5b784e5c796d6d3f9545e2452e6c0de25dff4e1d30`.
dtn7-rs carried it in one reported 290-byte bundle through the same one-pass
schedule; C received byte-identical bytes and parsed the fields.

This is deliberately not a thin-data-profile candidate. It has no signature,
source binding, State/Event/Record/Blob semantics, anti-entropy, application
store, or application effect. It controls for the minimum framing and BP
mechanics only.

## Durable-owner and state-machine count

The count distinguishes mechanism families, logical per-node/endpoint
instances, physical roots, and active transition owners. A B2 endpoint's inbox
and outbox pair is one logical mailbox owner but two physical roots.

| Arm | Durable mechanism families | Logical durable instances | Physical durable roots | Runtime transition owners |
|---|---:|---:|---:|---:|
| B1 | 2: p2panda SQLite; dtn7-rs sled | 5 | 5 | 4: three BP roles plus forced-contact coordinator |
| B2 | 3: p2panda SQLite; dtn7-rs sled; durable adapter mailboxes | 7 | 9 | 10: three BP roles, two LogSync machines, four mailbox pumps, coordinator |
| C | 1: dtn7-rs sled | 3 | 3 | 4: three BP roles plus forced-contact coordinator |

One-shot operation validation/store insertion and the C encoder/decoder are not
counted as long-lived state machines. The evaluator coordinator is counted but
receives no upstream-product credit. The complete responsibility and duplicate-
mechanism map is
archived `composition-007-owner-map.json`.

## Requirement-scoped outcomes

| Requirement | B1 | B2 exact one-pass | C control | Evidence boundary |
|---|---|---|---|---|
| DM-12-05 payload-blind temporal relay | **Partial** | **Not met** | **Partial** | B1/C bridge contacts but expose plaintext; B2 neither delivers the operation in one pass nor hides it |
| DM-5.6-03 durable temporal forwarding | **Met** | **Not met** | **Met** for control bytes | B restart and later B-to-C delivery pass for B1/C; persisted B2 `Have` is insufficient to deliver the item |
| DM-6-07 payload-blind relay | **Not met** | **Not met** | **Not met** | The fixed canary is recoverable from B's durable sled database in every arm |
| DM-5.6-05 bounded duplicates | **Unknown** | **Unknown** | **Unknown** | Duplicate items/contacts and a declared bound were not injected |
| DM-5.6-06 bounded loops | **Unknown** | **Unknown** | **Unknown** | A cyclic relay topology was not run |

The relay-plaintext conclusion is direct, not inferred: the canary occurs in
the preserved B sled database at
`b1/b/store.db/db`, `b2/state/b-dtn/store.db/db`, and `c/b/store.db/db` inside
the ignored `composition-007` trial tree.

## Duplicate responsibility map

| Responsibility | B1 | B2 | C |
|---|---|---|---|
| Semantic identity | p2panda operation hash; BP bundle ID remains transport-only | p2panda operation hash plus per-frame BP bundle identities | bespoke payload BLAKE3 ID plus BP bundle ID; no source binding |
| Durable state | endpoint p2panda stores intentionally layered with three BP stores | p2panda stores, three BP stores, and two endpoint mailbox owners duplicate persisted protocol bytes | three BP stores only |
| Retry/forwarding | BP epidemic forwarding; no application retry | BP forwarding plus interactive LogSync turns and mailbox handoff; no unified recovery contract | BP epidemic forwarding only |
| Expiration | BP lifetime only; p2panda retention/app TTL separate | independent BP lifetime per frame; LogSync/mailbox expiration unowned | BP lifetime only; profile TTL absent |
| Deduplication | p2panda hash/store plus BP tracking; bound untested | p2panda store/hash, volatile LogSync dedup, BP tracking, mailbox names and seen sets | BP tracking only; semantic lifecycle absent |
| Reconciliation | none in this spike | upstream LogSync, with return-contact dependency | none |
| Source identity | p2panda signature; no mission-to-BP identity binding | p2panda signature; no mission-to-BP identity binding | unverified label |
| Blob progress | no owner | no owner | no owner |
| Membership/revocation/key generation | no owner | no owner | no owner |
| Application effect | store insert only | validated event only | parse only |

## Proposal 0005 audit: remaining dissemination cells

This comparison closes the minimum B1/B2/C responsibility differential, but it
does not close the broader Proposal 0005 dissemination program:

1. Run duplicate injection and cyclic routing to resolve DM-5.6-05 and
   DM-5.6-06 for any surviving BP composition.
2. Compose the surviving temporal path with a selected source-protection and
   metadata-protection profile, then rerun relay state/capture inspection for
   DM-12-05 and DM-6-07. This report assigns no BPSec or security-profile credit.
3. Exercise application consumption and idempotent durable effect separately
   from BP endpoint receipt or p2panda store insertion.
4. For B1, add only a bounded immutable control/reconciliation exchange before
   claiming convergence, forks, pruning, retained history, or Blob behavior.
5. Keep B2 stopped for the one-pass topology unless a decision explicitly
   accepts return contacts or registers a different durable asynchronous
   reconciliation design; endpoint process-restart recovery is still unknown.
6. Treat C's State/Event/Record/Blob, anti-entropy, source identity, and policy
   surface as wholly unimplemented; the present C arm is only a control.
7. Hardy later closed the second-implementation temporal-topology cell in
   BVB-794. Cross-implementation exchange of one frozen application profile is
   still unknown; the two daemon runs are independent functional oracles, not
   interoperability evidence.
8. Run fragmentation, expiration, delivery-reporting, propagation policy,
   resource bounds, loss/size sweeps, and any separately selected custody-like
   or BIBE mechanism without crediting base BPv7 for them.
9. Preserve independent interoperability as unknown until a second
   implementation exchanges the frozen application profile and required
   positive/negative vectors.

These are remaining cells, not permission to broaden this freeze or consult a
new source. Each future arm requires its own registered source/composition and
bounded experiment.

## Reproduction and receipts

Historical execution commands are retained with the archived experiment.

The machine-readable summary is
archived `composition-007.summary.json`.
The three normalized envelopes bind the exact `BVB-724` tuple and the current
source-register SHA-256
`6e313a94f45e284c46d87c4d0d984fa99202fb6ce211db6bed82dc36558c31ca`
(current through `BVB-727` when validation ran). Later append-only rows do not
change the `BVB-724` source tuple; they require a current-ledger envelope or a
verified register snapshot before revalidation.
