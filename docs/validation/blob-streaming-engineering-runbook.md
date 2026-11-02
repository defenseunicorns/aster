# Blob streaming engineering runbook

This runbook validates the semantic-v9/profile-5 Blob pipeline from a local
application publish through selected-contact transfer and receiver-local read.
It is engineering validation, not a production deployment or release
qualification procedure.

The current receiver settlement, durable-resume, and timeout contract is machine
checked:

<!-- ASTER-BLOB-CAPABILITY:BEGIN -->
```json
{
  "schema": 1,
  "surface": "runbook",
  "settlement_order": [
    "authenticated_finish_and_content_verification",
    "canonical_apply_promotion",
    "result",
    "result_ack_or_eof_attempt_settlement"
  ],
  "available_before_attempt_settlement": true,
  "durable_resume_authority": [
    "lifecycle_owned_provisional_source_or_upload_state",
    "native_pack_checkpoint_journal"
  ],
  "attempt_settlement_owns_durable_resume": false,
  "sender_hard_deadline_basis": "exact_native_pack_wire_length",
  "receiver_initial_hard_deadline_basis": "profile_wire_ceiling_before_authenticated_open",
  "contact_no_progress_timeout_seconds": 30,
  "contact_progress_signal": "completed_authenticated_profile5_operation",
  "authenticated_progress_timeout_seconds": 120,
  "plaintext_segment_bytes": 1048576,
  "encoded_record_max_bytes": 1048706,
  "length_prefixed_data_max_bytes": 1048710,
  "checkpoint_batch_max_bytes": 134217728,
  "capacity_authority": "configured_blob_depot_limits"
}
```
<!-- ASTER-BLOB-CAPABILITY:RENDERED -->
The receiver verifies authenticated FINISH and content, atomically promotes the native pack before sending RESULT. RESULT_ACK or EOF settles only the transport attempt and does not own durable resume state. AVAILABLE may precede attempt settlement. Durable resume authority is lifecycle-owned provisional source or upload state plus the native pack checkpoint journal. The sender hard deadline uses exact native-pack wire length; before authenticated OPEN, the receiver uses the profile wire ceiling. A contact with no completed authenticated Profile-5 operation expires after 30 seconds; each such operation refreshes that outer watchdog. An individual authenticated Profile-5 operation times out after 120 seconds of inactivity, and the size-derived hard attempt bound remains absolute. The 1,048,576-byte plaintext segment, 1,048,706-byte ASTRBS02 record ceiling, 1,048,710-byte length-prefixed DATA body ceiling, and 134,217,728-byte checkpoint ceiling are distinct. Provisional upload state, lifecycle-owned provisional source state, native pack checkpoint journals, and completed native packs share configured Blob depot limits.
<!-- ASTER-BLOB-CAPABILITY:END -->

## Understand the selected profile

Profile 5 is the semantic-v9 selection. It is not a migration back to v8.
Semantic v7/v8 peers retain profile 4 for compatibility; a semantic-v9 peer
selects profile 5. Profile 5 stores and transfers the same append-only,
authenticated `ASTRBS02` pack records. It does not repack, re-encrypt, or
translate them through the profile-4 `ASTRBT01`/`ABX1` carrier representation.

Blob profile negotiation: semantic v7/v8 select profile 4; semantic v9 selects
profile 5. Profile 5 size terms: 1,048,576 plaintext bytes per segment;
1,048,706 bytes per maximum encoded `ASTRBS02` record; 1,048,710 bytes per
maximum length-prefixed DATA body. The checkpoint maximum is 134,217,728 bytes
(128 MiB). Provisional uploads, lifecycle-owned provisional network sources,
and completed native packs share the configured Blob depot limits.

| Selection | Object maximum | Canonical chunks | Authenticated source |
| --- | ---: | ---: | ---: |
| semantic v7/v8, profile 4 | 64 MiB | 1,024 | 1 MiB |
| semantic v9, profile 5 | 8 GiB | 8,192 native segments | 401,902 bytes |

Profile 4 retains canonical 64-KiB chunks. Profile 5 instead transfers one
complete length-prefixed `ASTRBS02` record per DATA body. SOURCE is sent in
records no larger than 1 MiB, with a 16-MiB authenticated-open maximum. The
receiver selects a checkpoint batch no larger than 128 MiB.

The bounded exchange is:

```text
PLAN -> OPEN -> SOURCE -> ACCEPT -> ASTRBS02 pack DATA -> CHECKPOINT
     -> FINISH -> RESULT -> ACK
```

An authenticated empty Blob uses exactly `PLAN -> OPEN -> SOURCE -> ACCEPT ->
FINISH(0) -> RESULT -> ACK`: it has no DATA or CHECKPOINT. A successful read of
that publication returns exactly one authenticated empty terminal page at
offset zero. Missing content, denied access, or an offset beyond nonempty
content must never be converted into that EOF.

## Keep publication and synchronization independent

Local publish succeeds after the local durable commit and does not wait for a
peer. Synchronization starts when an eligible destination becomes available or
requests the content. During terminal settlement, canonical-first status can
become available before the transport attempt has fully closed.

Every attempt is gated independently by authenticated peer identity, current
Blob interest, route authorization, content proof, and nonrevocation. Status is
canonical-first: `blob-status` reports receiver-local durable publication
state, not carrier connectivity or source-side intent. Lifecycle-owned
provisional source or upload state binds the verified plan and depot/store
authority; the native pack checkpoint journal records generation, segment
index, plaintext offset, pack offset, and wire offset. Before redb publishes a
checkpoint as resume authority, it reopens that exact journal checkpoint and
rejects a physically superseded capability. A fresh instance or reopen of the
same single contact-agreed adapter therefore resumes the same publication
without translating durable state. RESULT_ACK or EOF settles only the transport
attempt after atomic promotion and owns no durable resume state.
Cross-transport selection and failover are not implemented.

The current adapter is Iroh QUIC. The adapter interface is carrier-independent
and retains the bindings needed by a reliable ordered full-duplex non-IP
adapter. That keeps a future BLE adapter possible; this change does not
implement BLE or multi-adapter failover.

Current Blob API capability: the Rust API, native-gRPC agent, and asterctl
support bounded local publication and authenticated reads. Status boundary:
local publication success is a durable local commit; blob-status is
receiver-local durable state, not remote delivery, peer status, or convergence
status. Download resume: post-merge work; interrupted asterctl downloads
currently restart at byte zero.

### Migrate the unreleased application client

PR 110 intentionally replaces the PR 95 `v1alpha1` `PublishBlob`
client-streaming request/unary receipt with the current bidirectional stream.
PR 95 was not deployed to production, so its generated client has no
compatibility promise. Do not retain or operate an additive legacy upload
method: two public mutation grammars would create competing recovery contracts
without a deployed consumer.

For this alpha cutover, stop old clients, upgrade the agent, regenerate client
bindings from `proto/aster/application/v1alpha1/aster.proto`, and implement the
`metadata -> accepted -> data(offset) -> checkpoint -> finish -> complete`
exchange. Preserve operation keys and exact intent so an uncertain publication
can converge through the node's durable upload authority. No Blob content or
database migration is required by this application-wire change.

The first server response is `PublishBlobAccepted`. Its nonzero 32-byte
`publication_id` exists before data byte zero and must be retained by native
clients. Every checkpoint belongs to that same publication. The terminal
result must return the identical ID. A client may use it with
`InspectBlobPublication` while upload is still in progress. The phases are
receiver-local durable state: `AWAITING_DATA`, `RECEIVING`,
`READY_TO_FINALIZE`, `AVAILABLE`, or `EXPIRED_OR_RETIRED`. Transfer-byte
counters use one domain throughout: exact length-prefixed `ASTRBS02` pack
payload bytes. They are not storage reservation or filesystem byte counts.
`asterctl blob-publish` emits its one result only after completion, so shell
workflows obtain `publicationId` from that result; direct RPC clients can
observe it at acceptance.

### Reset or reimport an incompatible development depot

The native Profile-5 pack is an unreleased storage format and is not migrated
from earlier experimental pack encodings. On startup, an incompatible pack row
fails closed with `unsupported Profile-5 pack schema; reset the development
depot or reimport Blob data`. Stop the node before recovery. If the old Blob
bytes remain authoritative elsewhere, export them with the build that created
the depot, start the current build with a new empty depot, and republish the
files with their original application operation keys and metadata. Otherwise,
archive the old depot for diagnosis and initialize a new empty development
depot. Never delete or rewrite individual database rows: that would bypass
lifecycle, capacity, and physical-lineage accounting.

## Capacity and timeout bounds

The local native-pack promotion pool has two workers and two queued jobs.
That bound limits concurrent promotion, not disk consumption. Depot
reservations, completed provisional upload staging, database/journal
allocation, and promotion workers may overlap. Staging is not a second publication
authority: only atomic promotion of the completed authenticated native pack
creates the Blob publication. Check both state and depot filesystems and leave
operational reserve; an observed capacity snapshot is not a reservation.

Profile-5 transfer has separate authenticated-progress and absolute attempt
bounds. Their exact current inputs and values are generated from the typed
capability record at the top of this runbook.

The node's general 30-second contact bound is a no-progress watchdog, not a
maximum object-transfer duration. While one Profile-5 transport operation is
active, that outer watchdog temporarily follows the lane's 120-second
authenticated-operation idle bound; completion restores the 30-second contact
bound and refreshes its progress generation. Unauthenticated bytes do not
refresh either bound. The size-derived hard attempt deadline remains absolute.
This keeps a stalled contact bounded while allowing one healthy large-object
operation to settle without forced 30-second resume churn.

The legacy ten-minute attempt constant is not the normal-success deadline for
profile 5. CLI/agent RPC deadlines are a separate local application concern;
set them long enough for the local upload or read and recover an unknown
publish outcome with the same operation key.

## Publish, observe, and read

The CLI accepts nonempty regular files. Publication is local and remains valid
with no configured peer:

```sh
TOKEN_FILE=/run/aster/client.token
SOURCE=/data/imagery-1g.bin
OUTPUT=/data/received-imagery-1g.bin

stat --format='bytes=%s' "$SOURCE"
sha256sum "$SOURCE"
df -B1 /var/lib/aster-agent /var/lib/aster-depot /data
asterctl --token-file "$TOKEN_FILE" --json status

asterctl --token-file "$TOKEN_FILE" --timeout 900 --json blob-publish \
  --file "$SOURCE" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --operation-key imagery-flight-2026-10-20 \
  --priority immediate \
  --media-type application/octet-stream \
  --progress always 2>publish-progress.log
```

Save the publication ID, Blob ID, and operation key. If the command is
interrupted or its result is unknown, repeat the exact bytes, metadata, TTL,
and operation key. A different key means a different application operation.
The agent caps a Blob RPC at 15 minutes, so a larger client `--timeout` cannot
extend one local upload. If the cap is reached, retry the exact publication;
operation-key idempotency returns or resumes its durable local outcome. Peer
synchronization is separate and resumes from lifecycle-owned provisional
source state plus the native pack checkpoint journal.

Run status on the destination node. It is safe to start this after local
publication and before or after a peer becomes reachable:

```sh
PUBLICATION_ID='PASTE_BASE64_PUBLICATION_ID'

asterctl --token-file "$TOKEN_FILE" --timeout 900 --json blob-status \
  --publication-id "$PUBLICATION_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --wait
```

Read the returned Blob ID to a path that does not exist, then compare the
application-level hashes:

```sh
BLOB_ID='PASTE_BASE64_BLOB_ID'

asterctl --token-file "$TOKEN_FILE" --timeout 900 blob-read \
  --id "$BLOB_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --output "$OUTPUT" \
  --progress always 2>read-progress.log

sha256sum "$OUTPUT"
```

An interrupted CLI download removes its staged bytes and currently restarts at
zero. That is independent of node-to-node native-pack resume, which continues
from lifecycle-owned provisional source state plus the native pack checkpoint
journal after a fresh instance or reopen of the same single contact-agreed
adapter. If the 15-minute read RPC cap
is reached, confirm `blob-status` still
reports `AVAILABLE`, remove any owner-only abandoned staging file after
inspection, and retry the read; the CLI download itself does not resume.

The Rust streaming API also admits an empty Blob. Open a
`BlobPublishStreamRequest` with `total_len: 0`, perform no `write`, and call
`finish`. Read it with `BlobReadPageRequest { offset: 0, ... }`; the result must
be empty and complete. The file-based CLI deliberately rejects empty sources.

For a nonempty Rust upload, call `open_publish_stream`, begin at
`stream.durable_offset()`, pass absolute offsets to `write`, and call `finish`
only after exactly `total_len` bytes. Reopening the exact operation returns the
durable local frontier. Do not infer progress from bytes merely submitted by
the caller.

## Check peer compatibility and policy

- A v9-to-v9 contact selects profile 5 and can transfer empty through 8-GiB
  publications.
- A v7/v8 contact selects profile 4. It can receive only compatible nonempty
  publications up to 64 MiB / 1,024 chunks / a 1-MiB authenticated source.
- A profile-5 attempt does not fall back in place to profile 4. Content outside
  profile-4 bounds remains local for that older peer.
- Peer configuration alone grants nothing. Confirm exact Blob interest plus
  current route/content authorization on the receiver.

## Diagnose an operational run

Record the source length/hash, both node IDs, semantic/profile selection,
bind/listen addresses, selected carrier path, free bytes on state and depot
filesystems, publication/Blob IDs, operation key, and wall-clock timestamps.
Keep progress logs and the source/receiver node logs.

```sh
rg 'CONTACT .*blob_stream_(sent|received|resumed)_bytes=[1-9]' /path/to/node.log
rg 'profile|carrier_path|checkpoint|interest|route|content|revok|timeout' \
  /path/to/node.log
```

`blob_stream_sent_bytes` and `blob_stream_received_bytes` count bytes actually
carried by the contact. `blob_stream_resumed_bytes` counts durable prefixes
skipped across every Profile-5 exchange aggregated into that contact. It can
therefore equal a complete object when a later reconciliation round observes
an already-present publication; that is a zero-byte exact retry, not evidence
that the preceding fresh transfer skipped the object. Checkpoints and
partitions show durable progress. Pipeline service counters overlap; do not add
them to derive elapsed time. A CONTACT line alone is not proof of publication
receipt.

## Measure transport and end-to-end performance

Build the current transport example and retain its hash:

```sh
cargo build --locked --release -p aster-node \
  --features device-validation \
  --example blob_stream_transport_benchmark
BIN=target/release/examples/blob_stream_transport_benchmark
sha256sum "$BIN"
```

Use a persistent filesystem with enough free space for the completed source and
receive packs. CM4 `/tmp` is commonly a small tmpfs, so use `/var/tmp` for the
full-size control. In separate terminals, start the receiver first:

```sh
TMPDIR=/var/tmp "$BIN" pack-receive 127.0.0.1:18293 1073741824
TMPDIR=/var/tmp "$BIN" pack-send \
  127.0.0.1:0 127.0.0.1:18293 1073741824
```

Run the receiver first on one device and the sender on another. Bind Aster to
the network under test; retaining ZeroTier for remote administration does not
prove that payloads used WLAN. The device-validation receiver waits up to five
minutes for the completed source pack to be prepared; this is harness
orchestration only. Production local publication does not wait for a peer, and
the production contact listener has node lifetime rather than Blob-attempt
lifetime.

```sh
# receiver: rpi4-1
TMPDIR=/var/tmp ./blob_stream_transport_benchmark \
  pack-receive 192.168.60.79:18293 1073741824

# sender: rpi4-2
TMPDIR=/var/tmp ./blob_stream_transport_benchmark pack-send \
  192.168.60.80:0 192.168.60.79:18293 1073741824
```

Capture an adjacent raw-file baseline on the same selected interface, for
example with `iperf3` or an audited `nc` plus source/receiver `sha256sum`.
Compare raw throughput, the transport example, local publish, network
replication, and receiver read separately; do not collapse those stages into
one unexplained rate.

For a composed selected-node run, cross-build or build the `blob_benchmark`
example and retain its SHA-256. Its named 1-GiB campaign records first
visibility, contact settlement, connected shutdown, restart, and full download
verification as separate intervals:

```sh
python3 tools/blob_benchmark.py \
  --campaign profile5-1g \
  --variant candidate /absolute/repo /absolute/blob_benchmark \
  --output /durable/new-profile5-1g-results \
  --state /scratch/new-profile5-1g-state
```

Do not use `total_ns` alone as operational latency: it deliberately includes
validation-only shutdown and restart work. Use `publish_to_visible_ns` for the
first receiver-readable boundary and `publish_to_settled_ns` when terminal
contact accounting is also required.

Before device work, run the focused contract checks:

```sh
python3 conformance/blob_stream_oracle.py
python3 tools/check-protocol-version-contract.py
python3 tools/test-protocol-version-contract.py
python3 tools/test-run-fuzz-smoke.py
tools/run-fuzz-smoke.sh
```

The oracle/vectors and fuzz smoke validate the protocol grammar and decoder;
they do not establish CM4 throughput. A CI-built ARM64 binary still needs the
three CM4 devices to validate raw WLAN baseline, one-node local publication,
v9-to-v9 transfer, interruption/resume, receiver read/hash, memory/disk bounds,
and v8/v9 compatibility. Record exact commands, hashes, selected paths, and
receipts. Do not carry earlier device numbers forward as qualification for a
new binary.
