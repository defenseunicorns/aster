#

# Linux Event MVP qualification receipt validator specification

- Status: initial implementation contract frozen; implementation review pending
- Target profile: `aster-linux-event-mvp-evaluation-v0.1`
- Target annex: `linux-event-mvp-evaluation-profile-v0.1-annex-template.md`, supplemented by machine schema `aster-linux-event-mvp-qualification-machine-schema/v0.1`
- Register gate advanced: preparation for `P0-1-E06`
- Evidence effect: none

This document specifies a side-effect-free validator for one completed Linux
Event MVP candidate-annex bundle. It translates the accepted profile and the
provisional annex schema into deterministic structural, binding, and
profile-deviation checks. The initial machine contract is frozen by
[`linux-event-mvp-qualification-v0.1.json`](schemas/linux-event-mvp-qualification-v0.1.json).
It does not close E06, approve
a candidate, produce a qualification receipt, create a `pass` result, verify a
cryptographic signature, or authorize release.

The profile and integration owner decisions recorded in §9 authorize this
initial implementation. `P0-1-E06` remains Open until the required owners review
the implementation and its retained test evidence.

## 1. Purpose and non-goals

The validator answers only these questions:

1. Is the supplied bundle syntactically complete for the selected annex outcome?
2. Do immutable identifiers and digests bind one source, package attempt,
   provider, configuration, inventory, scenario set, receipt index, and decision?
3. Do the supplied values stay inside the exact v0.1 profile?
4. Are failed or unexecuted paths represented by the required typed
   `not-produced` and `not-run` values rather than omissions?
5. Are signature and approval records referenced consistently, without claiming
   that their cryptographic signatures were verified?

The validator does not:

- run a qualification workload, contact a device, install a package, load a
  provider, read credentials, or inspect a state directory;
- create or complete an annex;
- synthesize missing evidence, owners, dates, identities, signatures, digests,
  measurements, or results;
- emit a qualification `pass` receipt or convert component, generated-client,
  engineering, VM, namespace, or same-host evidence into physical qualification;
- authenticate package or approval signatures;
- decide whether an unresolved owner decision should be approved;
- weaken the generic configuration schema or reinterpret its broader accepted
  values as v0.1 values; or
- claim that structurally valid input is an issued or qualified candidate.

## 2. Inputs, output, and execution contract

### 2.1 Inputs

The command accepts exactly these local, explicit inputs:

- one required explicit read-only bundle root beneath which the candidate body,
  receipt index, detached records, and their referenced evidence bytes resolve;
- one canonical machine-readable candidate body whose exact bytes are the
  signable-body input under the later frozen annex schema;
- one immutable receipt-index document;
- zero or more detached approval-reference records;
- exactly one detached release-decision-reference record when the annex is
  presented as complete; and
- an optional separate read-only artifact root used only to recompute sizes and
  SHA-256 digests for explicitly referenced, non-secret artifact files.

No network access is permitted. Input paths must resolve beneath an explicit
read-only root. The implementation must open each path relative to a retained
root-directory descriptor with no-follow semantics, reject symlinks and special
files, verify the opened file's identity and size with descriptor metadata,
stream and hash the bytes from that same descriptor, and reject a file whose
identity or metadata changes during the read. Path traversal, duplicate map
keys, non-UTF-8 text, non-finite numbers, and files exceeding implementation
limits are rejected before semantic validation. The implementation may use only
public, approved dependencies. Dependency name, version, and public-source
logging is a repository development/release obligation, not a validator runtime
input, output, or side effect.

The validator must never request or accept private keys, bearer-token values,
mission plaintext, private trust material, raw credentials, unsanitized customer
identity, or device-access secrets. The frozen machine schema must allowlist
every permitted field path and distinguish public/sanitized references from raw
secret-value fields. An unknown field or a value in a prohibited raw-value path
is a hard rejection and is not copied into output. Field-name heuristics are not
a security boundary.

### 2.2 Result model

The validator emits a deterministic validation report, not a qualification
receipt. The report has:

- `validator_schema` and validator source/build identity;
- input body and index digests computed from the supplied bytes;
- `disposition`: `conformant`, `nonconformant`, or `indeterminate`;
- sorted findings with stable code, field path, severity, and source citation;
- checked binding identifiers and typed blocker strings;
- a statement that qualification, signature authenticity, and release authority
  were not established; and
- no copied secret-bearing or identity-bearing source values.

`conformant` means only that all implemented structural and profile checks
succeeded. It must be rendered with the exact non-claim
`structural/profile validation only; not qualification or signature verification`.
`nonconformant` means at least one deterministic rejection rule fired.
`indeterminate` means a required semantic decision is not frozen or referenced
bytes required by the selected validation mode are unavailable. Signature
authenticity is always reported as outside this validator's contract; its
absence from the checks does not by itself prevent a structurally conformant
result when all required signature-reference metadata and bytes are present.
An implementation/runtime error is distinct from all three dispositions and
exits nonzero. Disposition precedence is deterministic: any deterministic
rejection yields `nonconformant`; otherwise any unresolved required check yields
`indeterminate`; otherwise the result is `conformant`. Findings are sorted by
severity, stable code, and field path, and duplicate code/path findings are
collapsed before report serialization.

The frozen process exit codes are `0` for `conformant`, `2` for
`nonconformant`, `3` for `indeterminate`, and `70` for validator failure.

### 2.3 Determinism and side effects

For identical input bytes, validator version, and artifact root, the canonical
report bytes must be identical. The report must sort maps, field paths, finding
codes, receipt identities, and approval-reference digests according to the
frozen canonicalization rules. It must not include current time, absolute input
paths, hostnames, usernames, process IDs, or environment-dependent ordering.

Validation must not create state, open listeners, load providers, execute
artifact commands, mutate the annex, or write outside an explicitly selected
report path. A validation-only test must prove zero provider calls, listener
binds, subprocesses, and network attempts.

## 3. Canonical value grammar

Unless the frozen annex schema later says otherwise, the implementation enforces:

- SHA-256 digest: `sha256:` followed by exactly 64 lowercase hexadecimal digits;
- Git source object: exactly 40 lowercase hexadecimal digits;
- RFC 3339 UTC time: a fully specified timestamp ending in `Z`;
- counts, byte sizes, milliseconds, and seconds: base-10 non-negative integers
  without exponent or fractional syntax;
- executed result: exactly `pass` or `fail`, always paired with an immutable
  receipt reference and digest;
- final decision: exactly `issue`, `refuse`, or `defer`;
- global G3 output binding:
  `produced:sha256:<64-lowercase-hex>` when any G3 output exists, otherwise
  `not-produced:blocked-at-G<N>:sha256:<64-lowercase-hex>`;
- per-output missing G3 binding:
  `not-produced:blocked-at-G3:sha256:<64-lowercase-hex>`;
- downstream unexecuted binding:
  `not-run:blocked-at-G<N>:sha256:<64-lowercase-hex>`; and
- gate token `G<N>`: exactly one of `G1`, `G2`, `G3`, `G4`, `G5`, or `G6`.

The literal `<...>`, an empty string, `null`, `unknown`, `pending`, `scheduled`,
`warning`, an untyped `not-run`, and an untyped `not-produced` are never completed
values. Normalization must not repair uppercase digests, abbreviated commits,
local timestamps, changed field names, or malformed blocker tokens.

## 4. Candidate binding model

The validator constructs a monotonic chain of gate keys. No earlier record is
required to bind facts that do not exist yet:

1. The root key binds candidate ID/revision, frozen schema version/digest, exact
   profile ID/version/digest, and the G1 emission/capacity-contract references.
   The candidate supplies the profile digest as the required
   `prerequisites.profile_digest` field; it must equal the digest of the retained
   accepted profile bytes and must never default to the machine-schema digest.
2. The G2 key binds the root key plus the G1 exit digest, full source commit,
   dependency lock/toolchain, sanitized strict configuration, and harness
   source/version/configuration digest.
3. The G3 key binds the G2 key plus the G2 exit digest, global G3 binding,
   attempt-manifest digest when produced, every per-output binding, complete
   artifact-set digest when present, and provider implementation/version/source
   identity/contract digest.
4. The G4 key binds the G3 key plus the G3 exit digest, mandatory inventory,
   owner-controlled device and peer bindings, network conditions, scenario-set
   identity, and focused-test procedure identities.
5. The G5 key binds the G4 key plus the G4 exit digest and the four workload-row
   identities. The canonical scenario-set digest covers each scenario's mission
   authority, scope, topic, durable subscription, participant set,
   configuration, artifact, network condition, workload label, and
   state-directory identity commitment.

A gate receipt binds the key available at that gate and its predecessor exit
digest. Descendant keys incorporate the prior key and exit digest, so later
candidate facts cannot retroactively change an earlier receipt. After Sections
1–14 facts and the exact receipt index are final, the canonical body includes an
immutable receipt-index reference, byte size, media type, and digest. The
validator hashes the exact supplied receipt-index bytes and requires them to
match that Section 12 body representation before computing the signable-body
digest. Section 15 approvals and the detached G6 decision bind that body digest,
the G5 key when reached (or the latest reached gate key), candidate ID, schema
digest, and exact global G3 binding. Earlier receipts do not and cannot bind the
later body digest.

A mismatch in any layered key, predecessor digest, source, artifact, provider,
configuration, harness, inventory, device/peer binding, network condition,
scenario set, workload identity, schema, receipt index, or later body digest is
candidate drift and cannot be repaired by a later summary.

The validator must build a directed binding graph and reject:

- multiple values for a singleton candidate identity;
- a receipt that does not point to the exact candidate inputs it claims;
- a downstream G3–G5 executed result after an earlier blocking failure (a G6
  `refuse` or `defer` disposition is the required exception);
- a typed blocker whose gate is later than the field it blocks;
- a global `not-produced` binding when any G3 output exists;
- a complete artifact set that disagrees with the G3 attempt manifest;
- a final decision or approval reference bound to another body, candidate,
  schema, or G3 binding; or
- cycles created by including Section 15 approvals or the release decision in
  the signable body.

## 5. Field-to-source matrix

The source column identifies normative repository prose. The evidence source is
where a completed annex obtains the candidate-specific value; it is not a source
of new profile semantics. Every row is mandatory unless the annex schema marks
it conditional.

| Validator field group | Normative source | Candidate evidence source | Required validation |
|---|---|---|---|
| Schema identity | Annex §§Completion conventions, 1, 13, 15 | Frozen schema record | Reviewed non-proposed version, immutable digest, same digest in body/approvals/decision |
| Profile identity and claim | Profile §§Profile identity and reuse, Consequences; Annex §1 | Immutable profile bytes and claim/non-claims record | Exact ID/version; required `prerequisites.profile_digest` matches the retained profile bytes and root binding; non-production Event-only claim; exclusions retained |
| Candidate identity and checkpoint | Annex §1 | Release-owned candidate record | Unique ID/revision; exact checkpoint date; review time is not approval |
| Global G3 binding | Annex §§Completion conventions, 1, 3, 13 | G3 exit or failure receipt and attempt manifest | Exact produced/no-output grammar; partial outputs force produced attempt manifest |
| Complete artifact-set binding | Annex §§1, 3, 13 | Complete artifact-set manifest | Required for issue; agrees with every produced attempt entry |
| Source commit | Profile §Profile identity; Annex §§2, 13 | G2 exit record | Full lowercase Git object; identical across all dependent results |
| Dependency lock and toolchain | Annex §2; Profile §Artifact and installation contract | Lockfile and toolchain manifests | Path/format/version/size/digests present; no drift across build/replay |
| Strict configuration | Profile §§Topology and carriers, Emission modes, Capacity and workload matrix; Annex §§2, 8 | Sanitized canonical effective-config bundle | Schema/version/reference/size/digest; no secret fields; exact profile values |
| Qualification harness | Profile §Profile identity and reuse; Annex §2 | Harness source/version and config manifest | Immutable identity and digest; same harness/config across dependent gates |
| Deterministic and client gates | Profile §Acceptance and retained evidence; Annex §§2, 9 | G2/G6 command and process receipts | Exact command/environment bindings; executed result plus receipt; Go is client evidence only |
| Normative API methods | Profile §Application boundary and bindings; Annex §9 conditions 2 and 6 | Rust/Go process-gate manifests and receipts | Exact `GetStatus`, publish/query/subscription/poll/stream/ack/delete/gaps method set; Rust server and generated-Go client roles remain distinct |
| Service exposure and identity | Profile §§Supported platform and deployment, Artifact and installation contract; Annex §§3, 9 | Package manifest, unit/config manifests, and CM4 install/readiness receipts | Dedicated unprivileged identity; application/health listeners loopback-only in the dedicated namespace; no host port, ingress, remote tunnel, or unrelated sidecar; bearer auth retained |
| ARM64 package row | Profile §§Supported platform and deployment, Artifact and installation contract; Annex §3 | G3 attempt and artifact manifests | `aarch64`/`arm64`, native `.deb`, exact size/digest, provider-composed executable, all required outputs accounted |
| Package authentication reference | Annex §§3, 13 | Authentication result and detached-signature/signed-repository reference | Method/result/reference/digest structurally present; no claim of cryptographic verification by this validator |
| Installation and lifecycle procedures | Profile §§Protected provisioning boundary, Resource and lifecycle targets, Artifact contract; Annex §§3–4 | Immutable procedure records and target receipts | Exact procedure versions/digests; no secret-bearing commands; exact-artifact/state rules |
| D06 design and amendment | Profile §Protected provisioning boundary; Register `P0-1-D06`/`P0-1-E01`; Annex §4 | Committed design records and E01 approval references | Exact provider contract and published digests; do not infer E01 approval |
| E01 Security and Deployment | Register `P0-1-E01`; Annex §4 | Two separate signed approval-reference records | Both required before any G3 `pass` and for issue; each approval time is not later than production of the bound G3 artifact; exact roles, timestamps, digests, provider/package boundary, limitations, and acceptance plan |
| Provider and admin artifact | Profile §Protected provisioning boundary; Annex §4 | G3 provider/admin manifests | Exact implementation/version/source/build/architecture/contract; immutable admin command-set digest |
| Provider lifecycle results | Profile §Protected provisioning boundary; Annex §§4, 9 | Installed-package lifecycle receipts | Install/load/rotations/backup/recovery/revoke/rekey/destroy results and exact candidate bindings |
| Sanitized mission/policy identity | Profile §Protocol, security, and mission policy; Annex §5 | Owner-controlled public identifiers/commitments and policy manifest | One root, one signer, distinct roster, one scope/topic per scenario, semantic 6, profile/suite `0x0001`, no fallback |
| Relay disposition | Profile §Topology and carriers; Annex §6 | Relay acceptance bundle or signed `relay not used` reference | Exactly one branch; direct remains required; relay branch is one customer-controlled pinned DER-trust `direct_preferred` relay |
| Participant inventory | Profile §§Profile identity, Supported platform, Topology; Annex §7 | Frozen sanitized inventory plus owner-controlled binding digest | Exactly two mandatory physical CM4 Rev 1.1 aarch64 nodes; exact image/OS/kernel/systemd/ext4; same G3 artifact; distinct IDs |
| Third CM4 | Profile §Topology; Annex §7 | Frozen inventory | Omitted or declared with allowed support role and affected scenarios; no undeclared candidate traffic |
| Manual peer/device binding | Profile §Topology; Annex §8 | Owner-controlled canonical peer/device-binding record | Zero–19 exact address/identity pairs per node; canonical digest; no retrieval or exposure of protected access data |
| Network conditions | Profile §§Topology, Acceptance; Annex §§7–9 | Frozen sanitized network-condition record | Exact digest and scenario binding; no invented bandwidth/loss/NAT claim |
| Canonical scenario set | Profile §§Topology, Capacity matrix, Acceptance; Annex §§8–9 | Frozen scenario-set manifest | Per-scenario authority, scope, topic, durable subscription, participants, state-directory commitment, config, peer/device/network bindings, artifact, workload label, and start/end identity agree |
| Discovery and carrier state | Profile §Topology; Annex §8 | Effective-config receipt | Discovery exactly off; direct IP enabled; relay state matches §6 |
| Store and application limits | Profile §Capacity and workload matrix; Annex §8 | Effective status/config receipts | 10,000 aggregate store items; 67,108,864 aggregate store bytes; ledger accounting separate; one total app connection; eight node-global in-flight operations |
| Operation-ledger configuration | Profile §§Durable publish-operation containment, Capacity and workload matrix; Annex §§8, 9, 11 | Effective configuration/status and audit receipts | 1,000,000 permanent records; 201,326,592 logical bytes; 10,000-record emergency reserve; fixed 64-active-alias bound; values agree across candidate, status, and receipts |
| Harness limits | Profile §Capacity and workload matrix; Annex §8 | Harness manifest and run receipts | One client; pages 16; scans 128; unacknowledged maximum 256; payloads 0–65,536 bytes |
| Emission mode | Profile §Emission modes; Annex §8 | Config/status/restart receipts | Only `normal`/`receive_only`; configured equals effective; restart for change; no radio-silence claim |
| Operation-ledger boundary | Profile §Durable publish-operation containment; Annex §§8, 9, 11 | Status, audit, and capacity receipts | Warning no later than 512; profile stop at 1,024; keys 1–256 bytes; exact retry adds zero; active records compact only to permanent fences; configured caps remain separate |
| Mission timing | Profile §§Intended use, Capacity matrix; Annex §§8–9 | Workload receipt timestamps | Exactly 24 hours disconnected publication; no more than 24 hours later convergence/evidence; publication stops at 24 hours |
| Authenticated observability | Profile §Minimum observability and failure contract; Annex §§8, 9, 11 | Authenticated status and sanitized error receipts | Configured/effective mode; item/payload use and limits; operation total/active/retired/reverse rows, bytes, configured ceilings, ordinary/emergency and profile headroom; profile warning at 512; configured-ledger state `OK` below 70%, `WARNING` at 70%, `CRITICAL` at 90%, and `EXHAUSTED` when no ordinary active record fits; 60-second restart-local rate/estimate remain observational; audit state/progress; pending-delivery/saturation; contact counts; bounded peer outcome; no sensitive unauthenticated detail |
| Packet/log/error inspection | Profile §§Metadata exposure budget, Acceptance condition 12; Annex §9 condition 12 | Candidate-bound inspection record, inspected-surface manifest, metadata-budget reference, and immutable receipt | Exact candidate/artifact/provider/configuration/inventory/scenario bindings; explicit packet/log/error surfaces and procedure digest; `pass`/`fail` or typed blocker; no forbidden plaintext or credentials found within the stated budget; claim no broader than the retained inspected surfaces |
| Four workload rows | Profile §Capacity and workload matrix; Annex §9 | Four immutable workload receipts or typed blockers | Exact row names, nodes, payloads, counts/rates/durations, start/end, candidate/inventory/config bindings |
| Thirteen acceptance conditions | Profile §Acceptance and retained evidence; Annex §9 | Condition-specific receipts or typed blockers | One unambiguous record per condition; issue requires all executed pass against exact candidate |
| Crash/restart/state preservation | Profile §§Event and retry semantics, Resource and lifecycle targets, Acceptance; Annex §§3, 9 conditions 5, 8, 10 | Forced-loss, same-version restart, peerless reopen, reinstall/rollback, uninstall/state receipts | Existing state directory retained; durable Events, active/retired ledger records and fences, subscriptions, pending deliveries, acknowledgements, and controls preserved; no snapshot restore/downgrade |
| Evidence classifications | Profile §Acceptance; Annex §10 | Receipt index | Exact evidence type and one independent environment class; no class promotion |
| Resource measurements | Profile §Resource and lifecycle targets; Annex §11 | Per-node/per-scenario measurement receipts | Exact unit/method/node/workload/start/end/result/reference/digest and threshold treatment |
| Receipt index | Annex §12 | Immutable index and referenced receipt bytes | Unique IDs; reference/size/media/digest; producer/tool/time; claim/non-claims; replay reference; exact candidate binding |
| G1–G6 chain | Profile §Qualification dependency chain; Register chain; Annex §13 | Gate exit/failure records | Serial predecessor digests; no later execution after blocking gate; issue requires G1–G5 pass in order |
| D15 disposition | Register `P0-1-D15`; Annex §14 | Committed proposal and role-approval references plus exact candidate graph | Exact recorded tuples/digests; evaluation-only; production remains open; candidate graph must not drift |
| Canonical signable body | Annex §15 | Canonical body manifest | Includes Sections 1–14 facts and prerequisite references; excludes Section 15 approvals and final decision |
| Detached approval references | Annex §15 | One record per reached final role | Exact body/candidate/schema/G3 binding and record digest; typed blocker for unreached roles in refuse/defer |
| Detached release decision | Annex §§1, 15 | Release-owned signed record reference | Exact decision vocabulary and binding; sorted Section 15 approval digests; signature reference only |
| Archival bundle | Annex §15 | Optional archive manifest | Not an input to signatures and grants no additional claim |

### 5.1 Four workload rows

The validator compares values, never derives replacements:

| Row ID | Exact profile shape | Timing/count checks |
|---|---|---|
| API boundary | 2 nodes; payloads 0, 4 KiB, 64 KiB | Exactly one Event at each boundary; durable publish, transfer, query, delivery, and acknowledgement evidence; publishing-node assignment awaits the machine-schema decision below |
| Small topology | 2 nodes; 4 KiB | Exactly 10 Events total at 1 Event/s; direct coverage and explicit relay disposition; the profile calls this row “Two-node topology,” so a canonical machine label awaits owner freeze |
| Offline soak | 2 nodes; 4 KiB | 10 Events/hour/node for exactly 24 hours disconnected; 240 accepted local operations/node; sustained publication stops at the boundary; reconnection/evidence completes within the following 24 hours |
| Capacity-warning probe | 2 nodes; 4 KiB | 512 distinct local operations plus one exact retry; warning no later than 512; retry adds zero ledger rows/bytes; per-node operation and retry assignment awaits owner freeze |

Each row starts from a fresh zero-workload state directory while retaining its
provisioning controls. Replacing a state directory to reset a lifetime counter,
restarting the mission calendar, silently retrying a failed scenario, or pooling
receipts across changed inputs is a rejection.

### 5.2 Resource and lifecycle checks

For each mandatory CM4 node, validate the exact measured field, unit, method
reference/digest, workload or scenario ID, start/end state, result, and receipt:

| Measurement | v0.1 validation rule |
|---|---|
| Stripped deployed provider-composed executable | `<= 16 MiB` |
| Steady-state RSS after declared stabilization | `<= 64 MiB` |
| Peak RSS over the complete declared scenario | `<= 128 MiB` |
| Idle CPU with no contact or client request | `<= 5%` of one core |
| Readiness after start/restart | `<= 10 seconds` |
| Graceful stop | `<= 30 seconds` |
| Deployment memory | `>= 1 GiB`, interpretation pending owner decision below |
| Initial state-path free space | `>= 256 MiB` at each scenario start |
| State growth and final free space | measured; no added pass/fail threshold |
| Logical item use | measured against 10,000 aggregate and 5,840 ordinary store slots; 480 Events is only the two-node soak projection; ledger rows are separate |
| Logical byte use | measured against 67,108,864 aggregate and 50,266,112 ordinary logical bytes |
| Operation-ledger rows/bytes | total/active/retired/reverse rows and logical bytes measured; configured 1,000,000-record/201,326,592-byte ceilings, 10,000-record emergency reserve, and 1,024 profile boundary kept distinct |
| Operation headroom/warning/audit | non-negative ordinary/emergency and profile headroom; profile warning no later than 512; configured-ledger state `OK` below 70%, `WARNING` at 70%, `CRITICAL` at 90%, and `EXHAUSTED` when no ordinary active record fits; completed healthy bounded audit with consistent progress/total; 60-second restart-local rate/estimate are observation-only |
| Energy | measured and reported; no v0.1 pass/fail threshold |

Binary units must be frozen before implementation (`KiB`, `MiB`, and `GiB`
are presumed to mean powers of 1024 by the source documents but the machine
schema must state this explicitly). Physical database/filesystem growth cannot
be replaced by plaintext payload arithmetic.

## 6. Typed blocker validation

Typed blockers preserve actual failure state; they do not make a candidate
qualifying.

### 6.1 Global G3 cases

1. No G3 output exists because G1, G2, or the G3 attempt itself blocked before
   producing any output: the global binding is
   `not-produced:blocked-at-G1:sha256:<hex>` or
   `not-produced:blocked-at-G2:sha256:<hex>` or
   `not-produced:blocked-at-G3:sha256:<hex>`. No-output blockers at G4, G5, or G6
   are impossible because those gates require a produced G3 predecessor. Every
   artifact-specific and downstream field uses a compatible typed blocker.
2. Any G3 output exists, including a partial attempt: the global binding is
   `produced:sha256:<hex>` for the attempt-manifest digest. Every required output
   has either its actual `produced:sha256:<hex>` output-digest binding or
   `not-produced:blocked-at-G3:sha256:<hex>`.
3. A complete G3 pass has every required per-output entry produced, successful
   package-authentication result/reference, and a complete artifact-set manifest.
4. Any missing per-output entry, failed authentication, or incomplete manifest
   forbids `issue` and requires `refuse` or `defer`.

### 6.2 Downstream cases

A field not executed because an earlier gate stopped the candidate uses
`not-run:blocked-at-G<N>:<receipt-digest>`. The referenced digest must identify
the same failure/exit fact throughout all descendants. An executed result always
retains its real `pass` or `fail` and receipt digest; it is never rewritten as
`not-run` after a later stop.

The validator computes the gate order `G1 < G2 < G3 < G4 < G5 < G6` and rejects
blockers that point forward, contradict an executed predecessor, skip an
available actual result, or permit G3–G5 execution after a blocking failure.
G6 is the exception: it may and should execute after an earlier failure to sign
`refuse` or `defer`, but never `issue`. A `refuse`/`defer` record must preserve
all actual outputs and approvals that were produced before the stop.

## 7. Signature and approval-reference checks

The validator treats signatures as detached references and binding metadata.
Without a separately approved trust store, signer-identity policy, signature
format, and verification implementation, it must not report a signature as
cryptographically valid.

It may validate only that:

- every required approval/decision record has an immutable reference, media
  type, byte size, record digest, signer role, sanitized signer identifier,
  signed body digest, candidate ID, schema digest, G3 binding, decision token,
  and RFC 3339 UTC time as applicable; the validator opens the exact supplied
  detached-record bytes under §2.1, recomputes their byte size and SHA-256 from
  the same descriptor, and requires both to match the reference metadata;
- E01 has two distinct records with Security and Deployment roles and the exact
  D06 design/amendment/provider bindings; both records must exist before any G3
  result can be `pass`, and neither approval timestamp may be later than the
  production time of the bound G3 artifact;
- Section 15 records all sign the same canonical body digest;
- the final decision names the bytewise-sorted lowercase list of Section 15
  candidate-approval record digests;
- prerequisite E01 and D15 records are referenced in the body but are not
  substituted for Section 15 candidate approvals;
- Section 15 approvals and the final decision are excluded from the body digest;
  and
- an optional archive digest is not used as a signature input.

The report must use `signature-reference-present` or
`signature-reference-binding-invalid`, never `signature-verified`, unless a
later approved implementation explicitly adds cryptographic verification and
updates this specification.

### 7.1 Acceptance-condition-12 inspection reference

Acceptance condition 12 is a retained inspection-evidence requirement, not a
request for the validator to inspect packet captures, logs, or devices. Its
record must contain the exact candidate, G3 artifact, provider, configuration,
inventory, scenario-set, and applicable workload bindings; an immutable
manifest of the packet, log, and error surfaces actually inspected; the stated
metadata-budget reference/digest; inspection procedure/tool identity and
digest; execution time; `pass`/`fail` plus receipt reference/digest, or an exact
typed downstream blocker when the condition was not reached.

An `issue` requires an executed `pass`. A missing, failed, unbound, or drifted
record is nonconformant. The retained claim may state only that no forbidden
plaintext or credentials were found within the named surfaces and stated
metadata budget. It must not generalize that observation to uninspected
surfaces, all traffic, all logs, all errors, production, or another candidate.
The validator compares metadata and referenced-byte bindings only; it does not
copy packet/log/error content into its report or claim to repeat the inspection.

## 8. Negative-test specification

All fixtures are in-memory synthetic validator records, contain no real
credential or device-access data, and carry an unmistakable
`synthetic-test-only` marker on every record. They are never emitted into an
evidence directory or packaged as receipts. No fixture uses `issue` with
fabricated `pass` receipts. The suite defines separate baseline families for:

- a pre-G3 no-output `defer` with G2 blocker;
- a zero-output G3 `defer` with G3 blocker;
- a partial-G3 `defer` with an attempt manifest;
- a G4 failure with actual synthetic failure records, G5 typed blockers, and a
  G6 `defer`; and
- a fully populated reference model whose final decision remains `defer`, used
  only in memory to reach checks that require executed fields.

Each baseline family has a frozen expected disposition before mutation. Each
negative case changes exactly one property and asserts
`nonconformant`, the exact finding code and field path, and absence of unrelated
findings unless multiple errors are inherently coupled.

### 8.1 Parsing, canonicalization, and safety

| Code | Mutation | Required rejection |
|---|---|---|
| `QVR001` | Duplicate map key or duplicate receipt ID | Ambiguous input |
| `QVR002` | Unknown required field spelling or unsupported schema version | Unrecognized schema contract |
| `QVR003` | Placeholder, null, empty, `pending`, or `scheduled` required value | Incomplete field |
| `QVR004` | Uppercase/short digest, abbreviated commit, or repaired identifier | Noncanonical immutable identity |
| `QVR005` | Non-UTC/local timestamp, fractional count, negative size, overflow | Invalid scalar grammar |
| `QVR006` | Path escapes root, symlink, special file, oversized input, or file identity/metadata changes between open and completed hash | Unsafe input boundary or replacement race |
| `QVR007` | Unknown field, prohibited raw private-key/bearer/mission-plaintext field, or raw value appears in an allowlisted reference-only path | Prohibited sensitive content; no heuristic field-name decision |
| `QVR008` | Same bytes produce order- or host-dependent report | Nondeterministic validator output |
| `QVR009` | Validation attempts provider load, listener, subprocess, network, or state write | Side-effect-free contract violation |

### 8.2 Candidate and artifact bindings

| Code | Mutation | Required rejection |
|---|---|---|
| `QVB001` | Source commit differs between G2, artifact, receipt, or decision | Candidate source drift |
| `QVB002` | Config, harness, provider, inventory, network, or peer-binding digest differs across dependent records | Candidate input drift |
| `QVB003` | Global G3 `not-produced` while any output exists | Partial output not manifested |
| `QVB004` | Global G3 `produced` with absent attempt manifest | Missing attempt identity |
| `QVB005` | Existing output lacks actual produced digest | Unbound output |
| `QVB006` | Missing output lacks G3 typed not-produced digest | Untyped missing output |
| `QVB007` | Complete artifact-set manifest differs from attempt entries | Artifact-set inconsistency |
| `QVB008` | Wrong architecture, non-native package, or package not bound to G2 | Invalid package binding |
| `QVB009` | Package authentication reference/result absent or failed for issue | Unauthenticated issue candidate |
| `QVB010` | Receipt digest/size/media/reference mismatch | Invalid immutable receipt reference |
| `QVB011` | Two candidate records inside the supplied bundle reuse one ID but disagree on source/artifact/provider/config/environment | Internally inconsistent candidate identity; cross-bundle reuse is not claimed without a registry input |
| `QVB012` | Exact supplied receipt-index bytes, size, media type, or digest disagree with the Section 12 body representation | Receipt-index/body binding failure |

### 8.3 Platform, device, topology, and configuration

| Code | Mutation | Required rejection |
|---|---|---|
| `QVP001` | One mandatory node, three required nodes, VM, CM5, x86_64, or nonphysical environment | Wrong participant/platform profile |
| `QVP002` | Wrong/missing image, Debian, kernel, systemd, hardware revision, architecture, or local ext4 fact | Incomplete target binding |
| `QVP003` | Duplicate node identity or different G3 artifact on the two mandatory nodes | Inventory inconsistency |
| `QVP004` | Third CM4 carries traffic while omitted or marked spare with no affected scenarios | Undeclared participant |
| `QVP005` | More than 19 peers, identity-free address, noncanonical peer list, or binding differs from run | Manual-peer violation |
| `QVP006` | Discovery enabled or effective state missing | Discovery profile deviation |
| `QVP007` | Direct disabled, public/default relay, WebPKI, relay-only, multiple relays, or silent relay omission | Carrier profile deviation |
| `QVP008` | More than one mission authority, scope, topic, or durable subscription per scenario | Scenario shape deviation |
| `QVP009` | Wrong aggregate storage, operation-ledger, reserve, connection, in-flight, page, scan, unacknowledged, or payload limit | Limit deviation |
| `QVP010` | Emission mode outside allowed values, live change, mismatch, or radio-silence claim | Emission contract deviation |
| `QVP011` | Protocol not 6, profile/suite not `0x0001`, fallback, or multiple roots/signers | Mission-policy deviation |
| `QVP012` | Mission and relay authority are conflated | Authority-separation failure |
| `QVP013` | Required API method missing/renamed, or Go evidence presented without the Rust-server boundary | API-contract deviation |
| `QVP014` | Service identity is privileged, listener is not loopback-only, namespace boundary is missing, or host port/ingress/tunnel/unrelated sidecar is present | Service-exposure deviation |
| `QVP015` | Required authenticated status or ledger-audit field is absent/mismatched, or unauthenticated health/error contains detailed identifier/coordinate data | Observability/privacy deviation |
| `QVP016` | `/livez` or `/readyz` is detail-bearing, bearer authentication is absent on the application/status boundary, `SIGHUP` changes anything beyond bearer token, or `SIGINT`/`SIGTERM` lacks bounded drain/shutdown evidence | Health/authentication/signal deviation |
| `QVP017` | Invalid configuration, credentials, provider state, mission profile/policy, or durable state reaches readiness instead of failing closed | Startup fail-closed violation |

### 8.4 Workload, timing, capacity, and resources

| Code | Mutation | Required rejection |
|---|---|---|
| `QVW001` | Missing/duplicate workload row or renamed row | Incomplete workload matrix |
| `QVW002` | API row changes node count, payload set, or one-Event-per-boundary count | API-boundary deviation |
| `QVW003` | Small-topology row uses per-node 10 Events, wrong payload, count, or rate | Small-topology deviation |
| `QVW004` | Soak is shorter/longer, restarts calendar, publishes after 24 hours, changes rate/payload/node count, omits intervening restart, convergence, exact gaps, at-least-once redelivery, acknowledgement, or peerless reopen, or exceeds convergence window | Soak deviation |
| `QVW005` | Capacity probe changes 512 operations, omits exact retry, warns late, grows the ledger on retry, or omits a completed healthy audit | Capacity-probe deviation |
| `QVW006` | New publication continues beyond 1,024 or state directory is replaced as recovery | Profile-lifetime violation |
| `QVW007` | 1,024 is reported as the generic ledger cap or the configured 1,000,000-record/192-MiB capacity is used to widen the profile workload | Capacity semantic conflation |
| `QVW008` | Configured-cap engineering result is classified as ordinary profile workload or production qualification | Evidence-class violation |
| `QVW009` | Thresholded resource is missing, wrong unit, wrong node/scenario, or outside limit | Resource rejection |
| `QVW010` | Energy has a pass/fail threshold or state growth invents a threshold | Invented profile value |
| `QVW011` | 480 projected Event items or 240 separate operation records are presented as complete audited composition, ledger rows are charged to the aggregate store, or plaintext bytes are used as physical growth | Projection substituted for measurement |
| `QVW012` | Initial state-path free space is taken from unbound root-filesystem inventory observation | Unbound storage preflight |
| `QVW013` | Exact retry changes durable result or ledger count, a retired exact retry is not classified missing-durable-object, changed retired intent does not conflict, or an operation key is rebound | Retry/changed-intent violation |
| `QVW014` | Crash/restart/reinstall/rollback/uninstall uses a replaced or snapshot-restored state directory, loses durable Events/ledger records or fences/subscriptions/deliveries/acks/controls, or uses another artifact | State-preservation violation |

### 8.5 Results, blockers, evidence classes, and gate order

| Code | Mutation | Required rejection |
|---|---|---|
| `QVG001` | Executed result lacks pass/fail, receipt reference, or digest | Unsupported executed result |
| `QVG002` | Warning/checkpoint date is used as pass | Invalid result token |
| `QVG003` | Untyped not-run/not-produced, invalid gate, or malformed blocker digest | Invalid blocker grammar |
| `QVG004` | Blocker points to a later gate or inconsistent failure digest | Invalid blocker causality |
| `QVG005` | Downstream result executes after an earlier blocking fail | Gate-order violation |
| `QVG006` | G6 issue with any prior gate absent/fail/not-run or any G3 output absent | Invalid issue decision |
| `QVG007` | Refuse/defer erases actual partial output/result/approval | Loss of failure evidence |
| `QVG008` | Component/generated-client/engineering/same-host/VM/namespace evidence presented as physical profile qualification | Evidence promotion |
| `QVG009` | Evidence type is used as environment class or vice versa | Classification mismatch |
| `QVG010` | Receipt exact claim lacks candidate binding or non-claims | Overbroad receipt |
| `QVG011` | Go client is labeled independent-server evidence | Generated-client overclaim |
| `QVG012` | Post-retirement component evidence is labeled black-box v0.1 behavior | Retirement overclaim |
| `QVG013` | Rust/Go process gate omits publish, query, create/poll/stream/ack/delete subscription, gaps, or recovery evidence | Required API evidence missing |
| `QVG014` | Scenario set omits or drifts authority, scope, topic, durable subscription, state-directory commitment, participant, artifact, config, peer/device, or network binding | Scenario binding incomplete |
| `QVG015` | Gate key omits or mismatches its predecessor key/exit digest, or an earlier receipt is required to bind a later fact | Gate-chain binding violation |
| `QVG016` | Receipt index omits producer identity/role, producer tool/version digest, production time, exact claim, non-claims, environment digest, or verification/replay reference | Receipt provenance incomplete |
| `QVG017` | Acceptance-condition-12 record is missing/duplicated, is `fail` or untyped when `issue` is claimed, or drifts in candidate, G3 artifact, provider, configuration, inventory, scenario/workload, inspected-surface manifest, procedure/tool, metadata-budget, or receipt binding | Packet/log/error inspection evidence missing or unbound |
| `QVG018` | Acceptance-condition-12 record claims an uninspected surface, omits material surface exclusions, or generalizes its bounded result to all traffic/logs/errors, production, or another candidate | Packet/log/error inspection overclaim |

### 8.6 Approval and signature references

| Code | Mutation | Required rejection |
|---|---|---|
| `QVS001` | G3 is marked `pass`, or `issue` is claimed, while either E01 Security or Deployment record is missing; mutate each role independently | Open E01 candidate gate |
| `QVS002` | E01 role, D06 digest, amendment digest, provider, timing, limitation, or package boundary differs | E01 binding mismatch |
| `QVS003` | D15 tuple/digest/graph drift or production resolution claimed | D15 scope violation |
| `QVS004` | Section 15 approval bound to another body/candidate/schema/G3 binding | Detached approval mismatch |
| `QVS005` | Approval/decision embedded in signable body | Signature cycle |
| `QVS006` | Final decision approval digests unsorted, missing, duplicated, or include prerequisite approvals | Final-decision binding error |
| `QVS007` | Release decision absent, ambiguous, unsigned-reference absent, or uses another token | Invalid final decision reference |
| `QVS008` | Archive digest used as signature input | Invalid archive role |
| `QVS009` | Validator reports cryptographic verification from reference metadata alone | Unsupported verification claim |
| `QVS010` | Signature substitutes for a missing fact, gate, receipt, or blocker | Missing substantive evidence |
| `QVS011` | Supplied detached approval/decision bytes, size, or digest disagree with their reference metadata | Detached-record byte binding failure |
| `QVS012` | Either E01 Security or Deployment approval timestamp is later than production of the bound G3 artifact; mutate each role independently | Late E01 approval cannot support G3 pass |

### 8.7 Mutation coverage rule

Every normative equality, enum member, cardinality, minimum, maximum, timing
boundary, required binding edge, and conditional branch implemented in code must
have at least one falsification test that first fails for the intended reason.
Boundary tests include value-minus-one, exact value, and value-plus-one where the
source defines a numeric threshold. The test manifest maps every check code to:

- source section and exact validator field path;
- synthetic fixture and single mutation;
- expected disposition and finding code;
- whether the check is structural, profile-specific, binding, classification,
  or unresolved/external; and
- the implementation test name.

Generic-schema acceptance and v0.1 rejection must be tested together for broader
values that are legal generically but outside v0.1. This proves profile overlay
separation without narrowing the generic schema.

## 9. Frozen inputs and approved implementation decisions

No implementation may invent candidate facts or treat this contract as candidate
approval. The following profile and integration decisions are frozen for the
initial validator. They authorize code behavior but produce no qualification
evidence and do not close E01 or E06.

### 9.1 Frozen operation-ledger semantics

The profile defines 512 as the actionable-warning boundary and 1,024 distinct
accepted operation keys as the operator/harness stop boundary. The latter is
not a generic runtime rejection. The candidate separately configures 1,000,000
permanent records, 201,326,592 logical bytes, and a 10,000-record emergency
reserve. Active records charge at most 162 logical bytes including their
reverse-index key and compact only to permanent 67-byte retirement fences.

The machine schema must bind those exact configured values, active/retired/
reverse accounting, ordinary/emergency headroom, audit state/progress, exact
retry and changed-intent behavior, and the distinct profile stop. A configured
record or byte ceiling may reject new keys with the terminal operation-capacity
reason; reaching 1,024 only ends the v0.1 workload. No implementation decision
remains open for this distinction, and neither the candidate ceiling nor
engineering saturation evidence may widen the successful profile workload.

### 9.2 E01 approval representation

`P0-1-E01` is open. Security and Deployment must each approve the exact D06 v2
design digest, systemd 257 presentation-amendment digest, provider contract,
trust/presentation boundary, administration artifact, lifecycle procedure,
limitations, and acceptance plan before G3 can pass or a candidate can issue.

Approved initial boundary: detached E01, candidate-approval, and release-decision
records use the canonical JSON formats in the machine schema. Each record binds
its sanitized signer identifier and role, time, candidate/body/schema/G3 facts,
and an immutable signature reference. The validator checks record bytes,
digests, roles, times, ordering, and binding metadata only. Signature format,
trust-store authority, and cryptographic verification remain outside this tool;
every report says signature authenticity is `not-assessed`. Required reference
metadata may therefore be structurally `conformant` without implying signature
authenticity or closing E01.

### 9.3 Device and peer binding

The prepared inventory selects sanitized `cm4-a`/`rpi4-1` and
`cm4-b`/`rpi4-2`; `cm4-spare`/`rpi4-3` is spare only. Exact host-access identity,
device serial, carrier coordinates, and peer identities are intentionally held
in an owner-controlled binding outside the repository.

Approved initial boundary: the candidate carries only ordered aliases, declared
roles, sanitized public commitments, and the immutable owner-controlled
device/peer-binding record digest. The record itself stays under owner control.
The validator checks bundle-local alias/role/commitment consistency and digest
handoff only. It never retrieves, prints, or infers serials, addresses, host
keys, private identity, or credentials.

### 9.4 Network/relay candidate choice

The inventory inspection used an inspection-only path and did not approve G4/G5
carrier conditions. The candidate must freeze a sanitized direct-path
network-condition record and either one exact relay bundle or a detached signed
`relay not used` statement.

Approved initial boundary: each candidate explicitly selects exactly
`direct_only` or `direct_plus_one_pinned_relay`. The latter binds one
customer-controlled, pinned-DER, `direct_preferred` relay bundle; the former
binds the detached `relay not used` statement. Direct coverage remains required
in both cases. The validator never infers this choice from historical inspection
evidence.

### 9.5 Deployment memory interpretation

The profile says deployment memory is at least 1 GiB. Prepared inventory reports
949,702,656 bytes of installed/kernel-visible RAM, and those quantities have not
been declared equivalent.

Approved initial boundary: the threshold is nominal installed hardware capacity
in bytes and passes at or above `1,073,741,824` bytes (1 GiB). The candidate also
records kernel-visible memory bytes as a separate measurement; that value does
not replace or fail the nominal-capacity check.

### 9.6 Machine schema and canonicalization

The initial machine contract is
[`aster-linux-event-mvp-qualification-machine-schema/v0.1`](schemas/linux-event-mvp-qualification-v0.1.json).
Canonical values are compact, key-sorted, ASCII-safe UTF-8 JSON with integer
numbers only and exactly one trailing LF; duplicate keys and noncanonical bytes
are rejected. `KiB`, `MiB`, and `GiB` are powers of 1024. The report schema is
`aster-linux-event-mvp-qualification-validation-report/v0.1`, with public exit
codes 0/2/3/70 as defined in §2.2 and stable finding codes from §8.

Frozen safety limits are 4 MiB for the candidate body, 8 MiB for the receipt
index, 256 KiB for each detached record, 128 MiB for each referenced artifact,
4,096 receipt-index entries, 64 detached candidate approvals, and 512 MiB total
declared or actually read referenced bytes. Every receipt-index entry required
by the selected outcome must have its exact bytes locally under the explicit
bundle or artifact root. Missing required bytes are `indeterminate`; present unsafe, malformed,
changed, or mismatched bytes are `nonconformant`.

### 9.7 Workload labels and node assignment

The profile calls the 10-Event row `Two-node topology`; the annex calls it
`Small topology`. Neither document defines canonical machine identifiers for
the four rows. The API-boundary row does not assign each of its three Events to
a publishing node, and the capacity-warning row does not say whether 512 local
operations and the exact retry occur on one named node, on each node, or under
another fixed distribution.

Approved machine labels are `api_boundary`, `two_node_topology`, `offline_soak`,
and `capacity_warning_probe`; `Small topology` and `Two-node topology` both map
only to `two_node_topology`. For `api_boundary`, `cm4-a` publishes the 0-,
4,096-, and 65,536-byte Events and `cm4-b` receives. For
`capacity_warning_probe`, `cm4-a` publishes 512 distinct operations plus one
exact retry and `cm4-b` receives; the retry adds zero ledger growth. The soak
publishes exactly 240 operations per node.

### 9.8 Candidate-ID uniqueness scope

The declared validator inputs contain one bundle and no trusted registry of
previous candidates. The validator can reject conflicting uses of a candidate ID
inside that bundle but cannot prove global non-reuse across prior bundles.

Approved initial boundary: no candidate registry is an input. The validator
enforces bundle-local candidate-ID consistency only and reports
`global candidate-ID uniqueness not assessed`. Global non-reuse remains a
release-review responsibility.

## 10. Implementation and CI acceptance plan

After the decisions above are approved, implementation proceeds test-first in
vertical slices:

1. parser and canonical scalar grammar;
2. candidate/G3 binding graph and typed blockers;
3. exact profile/configuration and four-workload overlay;
4. inventory/device/scenario bindings and evidence classification;
5. resource/capacity checks;
6. approval/signature-reference graph; and
7. deterministic sanitized report.

For each slice, add one failing mutation test, observe the expected failure,
implement the smallest check, then run the focused and full suites. The supported
CI entry point must run:

- all validator unit and falsification tests;
- a side-effect test that denies network, subprocess, listener, provider, and
  out-of-root writes;
- generic-schema versus exact-v0.1 overlay separation tests;
- deterministic repeated-report byte comparison;
- repository formatting/linting;
- `python3 tools/check-implementation-requirements.py` only if a later change
  updates trace/evidence; and
- `mise run check` before handoff.

Synthetic fixtures must be generated inside the test workspace, remain clearly
marked, and never be committed as apparent qualification evidence. No test may
produce a plausible signed `issue` bundle or qualification PASS receipt.

## 11. Definition of done for the implementation follow-up

A later implementation increment is complete only when:

- the annex schema and decisions in §9 are frozen by their owners;
- every matrix row in §5 maps to a machine field path and validator rule;
- every meaningful profile deviation and binding failure in §8 has a test that
  was observed failing before its implementation;
- all required positive structural, negative, boundary, side-effect, and
  determinism tests pass;
- the validator is wired into a supported CI entry point;
- a clean checkout passes `mise run check`;
- the validation report states its non-qualification and non-signature-verification
  boundary;
- no credential, private identity, raw device binding, or synthetic qualification
  claim is emitted; and
- `P0-1-E06` is changed only after owner review of actual implementation evidence.

The initial implementation and its synthetic falsification suite advance
preparation for E06. They change no register or requirement evidence status,
candidate gate, package, qualification receipt, approval, or release decision.
E06 remains Open until the named owners review the actual implementation and
the remaining mutation-coverage boundary.
