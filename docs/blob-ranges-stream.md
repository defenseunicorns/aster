# Receipt-free Blob range streaming

Historical draft.3 specification. The current hybrid runtime requires semantic
v9/profile 5 and does not execute this profile-4 dialogue. The original codecs
and vectors remain available for format validation.

## Required profile and compatibility boundary

Protocol draft.3 semantics v7 and v8 use profile ID `4`,
`BlobRangesStreamV1`, exclusively for Blob lane `4`. The current Blob offer is
`[4]`, not `[4, 1]`. Profile `3` remains reserved for the approved
`BlobCustodyV1` design and is not offered or selected. Semantic v7 uses the
profile-4 stream in durable-only mode; semantic v8 layers authenticated finite
custody into that same profile-4 stream.
Both authenticated offers must intersect on it; the digest commits both exact
offers and all lane selections. A peer without profile 4 fails the protected
profile exchange. A v5/v6 Blob carrier attempt fails explicitly before carrier
IO. Old implementations that require LegacyV6 in every offer also reject the
new offer rather than misdecoding a stream. There is no retry using old Blob
range/result/ack mechanics. Both endpoints must be upgraded for Blob sync.

The generic parser still reads historical offers and vectors; it does not
provide a legacy Blob transfer implementation. Event, State, Record, and
EventBridge profiles and grammar are unchanged. Source/manifest/depot formats
are unchanged, so durable partial prefixes remain usable after upgrade.
There are no per-range application storage receipts. QUIC delivery
acknowledgements remain transport details, not proof of durable remote storage.

## Turn grammar and bounds

After the original Event uni-turn pair is finished or skipped, a Blob
contact may admit one additional role-ordered pair. Admission is shared by all
connection clones, rejects active/incomplete original turns, and is single-use.
The initiator-to-responder Blob direction precedes the reverse direction.

For each direction:

1. The receiver sends one protected application schedule over the existing
   bidirectional mechanics stream. Plaintext is `ABRS` + version byte `01` + a
   big-endian u16 count, followed by that many canonical existing
   `BlobRangeFetchV5` encodings (123 bytes each).
2. The sender returns a protected schedule-acceptance frame containing only the
   SHA-256 schedule hash. This confirms the schedule, not storage of any data.
3. The sender opens the role-ordered uni-turn and emits
   exactly one protected response per scheduled index: `ABRD` + `01` + schedule
   hash (32 bytes) + big-endian u16 index, followed by a canonical existing
   `BlobRangeV5` encoding. Its status is data or unavailable.
4. The sender emits `ABRE` + `01` + schedule hash + big-endian u16 scheduled count,
   then transport FIN. The receiver requires this exact terminal and EOF, rejecting
   missing/wrong/trailing records. An empty schedule has just the terminal and FIN.

There are at most 64 ranges per direction. A schedule is at most 7,879 plaintext
bytes. A data frame is at most 16,519 plaintext bytes (39-byte wrapper plus the
existing 16,480-byte range response maximum). The terminal is 39 plaintext bytes.
The terminal and all frame overheads are reserved before scheduling; the schedule
is further limited by remaining contact bytes and frames. Later reverse-direction
mutable lanes and EventBridge keep their existing reserves. A minimum nonempty
stream fits within the unchanged
three-exchange/17,127-byte Blob lane reserve inherited from the historical
carrier allocation.
Source-item accounting counts one selected source turn per nonempty direction,
not one source item per range. Range work is independently capped at 64 attempts
per direction (128 across both directions), including unavailable responses. This
does not shrink the historical Event allocator to fit a new shared range counter.
Existing contact/operation deadlines and uni-turn aggregate byte limits remain
in force. At most one range payload is read or served at a time; the schedule is
bounded metadata, not a whole-Blob buffer. No durable remote-progress registry
is added.

Each nonempty schedule addresses one source/content proof, with carrier objects
in ascending order and an exact total length per object. Within each object,
range offsets and lengths are canonical and contiguous in ascending order. Duplicate,
gapped, conflicting, mixed-source, noncanonical, truncated, oversized, or trailing
schedule entries fail closed. It begins at the receiver's authoritative durable
prefix, not necessarily at zero. Request records include the direction. Schedule,
data, and terminal protection uses contextual AAD binding the negotiated profile
digest, Blob lane, and direction; data and terminal also repeat the exact schedule
hash and index/count.

## Authority and interrupted recovery

The receiver selects work with `selected_pending_blob_contact_work`; each data
record is authenticated and checked against its exact scheduled tuple before
the version-derived, mode-aware append path. Both sides refresh contact policy for
every protected record, and the receiver checks current source metadata before
each append. The sender authenticates the immutable source/content and builds its transfer
plan once per bounded schedule. Each range reloads and compares the exact source
bytes and rechecks durable projection/completion, entitlement, revocation/expiry,
object identity, current lineage, and depot policy before serving bytes. An
unavailable response does not append bytes. After an unavailable range or typed
append-capacity deferral, the receiver authenticates and validates the remaining
bounded records and terminal but discards their payloads, so later data cannot
append across a missing prefix. Capacity deferral advances the selected source's
scheduling cursor without changing durable prefixes or claiming publication. This
also applies when an already installed source cannot yet be published at turn
startup: it yields to the next eligible source rather than monopolizing selection.
Store append-coherence failures remain
fatal rather than being reclassified as recoverable transport interruptions.

Each accepted ciphertext prefix is independently durable before the next record.
A stream failure or missing terminal does not roll it back and does not mark it
as remotely acknowledged. The next contact derives the missing suffix from Store.
Only a valid schedule-bound terminal and EOF authorize the receiver to attempt
carrier completion, publication promotion, or the turn's one cursor outcome.
`recover_and_finalize_pending_blob` retains complete carrier verification and
whole-plaintext verification. Publication becomes visible only after full
verification; partial ciphertext is not delivered as plaintext. A terminal
means the sender finished its attempts, not that remote storage or publication
succeeded. If all bytes arrived before a lost terminal, a later authenticated
empty schedule can finalize and promote the retained complete prefix without
refetching it.

## Version-derived lifecycle and storage policy

Profile `4` is one raw range-stream grammar with policy selected by the
authenticated semantic version. Semantic v7 admits and serves durable sources
only. Semantic v8 admits durable sources and finite sources carrying an exact
verified custody capability; a decoded claim alone is never admission
authority. The finite source's positive TTL and authenticated cumulative age
are bound to its exact source transfer and publication identity. Duplicate
custody observations merge a nondecreasing age lower bound. Continuous local
monotonic residence increases that bound; a restart or clock-domain gap adds no
invented time, makes continuity loss sticky, and withholds the source until the
lower bound itself proves expiry.

Proven expiry and eligible bounded pressure recovery retire the exact
publication or pending source logically before it can be inventoried, served,
read, delivered, completed, or promoted. A policy or continuity failure instead
withholds or rejects the affected work unless its exact maintenance path later
authorizes retirement. Live-publication retirement creates retained retirement
evidence and preserves the applicable physical-lineage and accepted-publication
replay fences. Pending-source expiry removes the source, prefixes, and ordinary
references while preserving its applicable physical-lineage fence; it does not
invent a publication-retirement row. Those bounded non-evictable authorities
prevent same-lineage substitution and, where applicable, publisher-dot replay
after ordinary retirement evidence ages out. Selected retirement evidence is
retained for 45 days of conservative lower-bound age, then expires through
bounded maintenance.

Storage-pressure recovery may atomically retire only eligible work below the
incoming priority, with expired work ranked first. Selection is version-aware:
durable contacts cannot expose finite candidates, and custody contacts require
compatible finite provenance. Logical retirement and physical reclamation are
separate. Reclamation first persists an exact variant deletion manifest, then
removes only that manifest's rows/files under independent row, file, and byte
budgets; a restart resumes the same authorized victim. Missing or delayed exact
deletion authority fails closed and cannot take credit for unrelated cleanup.

## Validation scope

`conformance/blob_stream_oracle.py` constructs the profile offer and 37
schedule, range-data, and terminal vectors independently with Python's standard
library. Rust checks acceptance/rejection, exact re-encoding, schedule hashes,
order, counts, lengths, tuple bindings, and malformed records. The gate checks
that the retained corpus matches the Python construction. This supplies
code-path and language diversity, not independent-team interoperability evidence.
Counted live transfer regressions require one source/content authentication per
schedule and a fresh depot check per range. Signed revocation committed at the
sender after the first range rejects the next send with no second depot read;
the receiver-side revocation regression remains separate.

Tests cover required bilateral selection and explicit incompatibility, historical vectors, bounded
schedule/terminal rejection, one-contact multi-range transfer, and real in-flight
interruption immediately before or after the first durable append. The interruption
seam pauses the sender before its terminal, closes the live connection, reopens
Store, and checks that only missing ciphertext is fetched with zero duplicates and
that final plaintext matches its expected length and SHA-256. This is transport
interruption/reopen evidence, not a power-loss claim. Saturated Event contacts test
all six mutable directions with current peers, alongside an exact contact-reserve
boundary unit test. The selected-frame
fuzzer also exercises the schedule decoder and canonical roundtrip.

The live fault suite additionally covers a lost terminal after the final append:
reopen retains the complete prefix but no publication or cursor rotation, and a
zero-byte authenticated reconnect performs the terminal-gated promotion. It also
covers corrupted AEAD and wrong
contextual AAD on the second range (the first durable prefix survives), and a
real signed publisher revocation committed while both endpoints are paused after
the first append (the next append is rejected). A controlled typed staging-capacity
error at the second append verifies prefix retention, bounded remainder draining,
and progress of a second eligible source before retrying the first. A separate
real publication-quota test rotates two fully installed but capacity-deferred
sources. An authenticated unavailable second range followed by later data no
longer triggers a noncontiguous append; reopen fetches exactly the missing suffix.
The new live fault tests assert the requested injection fired and use real transport and
Store reopen boundaries. The append-quota error is injected at the Store call
boundary, not a physical disk-full experiment; publication quota and revocation
are actual Store transitions. This is not exhaustive adversarial or power-loss
evidence.

These tests are current-code reference evidence, not independent
interoperability, device, physical-disk-full, power-loss, or performance
acceptance. They do not promote requirements traceability status.
