#

# Linux Event MVP Evaluation Profile v0.1 candidate-annex schema

- Schema version: `0.1-proposed`
- Profile ID: `aster-linux-event-mvp-evaluation-v0.1`
- Status: provisional and revisionable; never qualification evidence by itself
- Freeze gate: OS/artifact, integration/device, deterministic-gate, security,
  dependency/legal, and release owners approve the schema interfaces

A candidate cannot qualify before this schema is reviewed and frozen and G2,
G3, G4, and G5 pass in order. A completed annex contains concrete immutable
identifiers, digests, results, and approvals for every applicable required
field. An omitted, unfilled, ambiguous, mutable, or unsigned required field
makes that annex non-qualifying.

No secret, credential, private key, bearer token, unsanitized customer identity,
or mission plaintext enters this schema or a repository copy of an annex.
Completed customer annexes may require controlled storage; any public copy must
be sanitized without removing facts required to substantiate its public claim.

## Completion conventions

- `Required` means every completed base-qualification annex supplies the field.
  `Conditional` means the stated condition decides whether the field is supplied;
  it never permits silent omission.
- `<...>` marks a value to be completed. Placeholder text is not a value.
- Unless a row states otherwise, `digest` means lowercase, 64-character SHA-256
  over immutable bytes, written as `sha256:<hex>`. An immutable record reference
  is a stable content-addressed location plus that digest.
- An executed result uses `pass` or `fail` and carries its actual immutable
  receipt digest. A downstream result that did not run because an earlier gate
  stopped the candidate uses exactly
  `not-run:blocked-at-G<N>:sha256:<receipt-digest>`, where `G<N>` is `G1`
  through `G6` and the digest binds the blocking failure or exit receipt. An
  untyped `not-run` is invalid. Actual result and receipt digests remain
  mandatory whenever execution occurred and for every result supporting
  `issue`.
- The global G3 artifact binding is exactly one of
  `produced:sha256:<G3-attempt-manifest-digest>` whenever any G3 output exists,
  including a partial attempt, or
  `not-produced:blocked-at-G<N>:sha256:<failure-or-exit-receipt-digest>`. The
  global no-output form is valid only when no G3 output exists. The immutable
  G3 attempt manifest enumerates every
  required output: the `arm64` package and its package-authentication,
  package-manifest, SBOM, notices, and provenance outputs, plus the dependency
  graph and complete artifact-set manifest. Each entry is exactly
  `produced:sha256:<actual-output-digest>` when that output exists or
  `not-produced:blocked-at-G3:sha256:<failure-receipt-digest>` when it does not.
  Actual digests are mandatory for every output that exists.
- A global `produced` G3 binding is not sufficient for `issue`. Issue requires
  every required per-output entry to be `produced`, the `arm64` package
  to be present and authenticated successfully, and the complete artifact-set
  manifest and digest to verify. Any per-output `not-produced` entry requires
  `refuse` or `defer`.
- When `not-produced` is used, every artifact-specific field and every
  downstream result/receipt field is completed with the applicable exact typed
  `not-produced` or `not-run` value rather than left blank. These typed blockers
  are valid only for a `refuse` or `defer` record.
- A decision uses exactly `issue`, `refuse`, or `defer`. A warning, target date,
  scheduled run, or incomplete review is never `pass`.
- An owner is the named accountable role. A producer may populate a field, but
  the owner reviews it and the release owner verifies every digest before issue.
- Rejection means the annex cannot support an `issue` decision. A completed
  `refuse` or `defer` annex preserves the failure or missing-gate facts and its
  immutable receipts.
- Times use RFC 3339 UTC. Durations use integer milliseconds or seconds as named.
  Sizes and counts use decimal integers in the units stated by the field.

## 1. Profile, candidate, and decision identity

| Field | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Schema identity | Required | Reviewed schema version and `sha256:<hex>`; starts from `0.1-proposed` but a candidate uses only its later frozen revision | Profile + integration | Reject if the schema is still proposed/unfrozen, mutable, or its digest does not verify |
| Profile identity | Required | Exact ID `aster-linux-event-mvp-evaluation-v0.1`, profile version `0.1`, and immutable profile digest | Profile owner | Reject any different, missing, or mutable identity |
| Candidate identity | Required | Unique sanitized candidate ID and candidate-annex revision | Release owner | Reject reuse across different source, artifacts, provider, configuration, or environments |
| Decision checkpoint | Required | Exact date `2026-09-13` and RFC 3339 UTC review time | Release owner | Reject if the date is treated as approval or if the review time is absent |
| G3 artifact binding | Required | Exact global `produced:sha256:<G3-attempt-manifest-digest>` when any output exists, otherwise exact global `not-produced:blocked-at-G<N>:sha256:<hex>` | Deployment + release | Reject an untyped/missing binding, global `not-produced` after any output exists, a missing actual output digest, or disagreement with any artifact/result/decision record; reject issue unless every attempt-manifest output is produced |
| Complete G3 artifact-set binding | Required for issue and whenever a complete set exists; otherwise a per-output `not-produced:blocked-at-G3:sha256:<hex>` entry in a produced attempt manifest, or the global no-output binding | Immutable complete artifact-set manifest reference/digest binding the `arm64` package, successful authentication outputs, package manifest, SBOM, notices, provenance, and dependency graph | Deployment + release | Reject issue if absent, incomplete, unverifiable, or different from the attempt manifest; preserve the actual digest whenever a complete set exists |
| Final outcome | Required as a detached record; excluded from the signable annex body | Exactly one signed `issue`, `refuse`, or `defer` release-decision record with a concise reason and the exact typed global G3 artifact binding | Release owner | Reject an `issue` unless every required gate passed in order, every G3 per-output entry is produced, the `arm64` package authenticates, and the complete artifact-set manifest verifies; reject an absent, ambiguous, or unsigned outcome; reject refusal/defer if a partial attempt or missing downstream work lacks its typed blocker |
| Claim and non-claims | Required | Immutable text identifying the time-bounded, non-production Linux/Event v0.1 claim and its exclusions | Profile + release | Reject if it broadens the profile, claims production, or describes implementation or component evidence as qualification |

## 2. Source, inputs, configuration, harness, and deterministic gate

| Field | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Source commit | Required | Full 40-character lowercase Git object ID | Deterministic-gate owner | Reject abbreviated, missing, mutable, or different source across dependent gates without a new candidate |
| Dependency lock | Required | Lockfile format/version, path, byte size, and `sha256:<hex>` | Dependency/license + deterministic-gate | Reject an unlocked build, an unverifiable digest, or dependency drift |
| Toolchain | Required | Exact compiler/build-tool versions and immutable toolchain-manifest digest | Deterministic-gate owner | Reject floating versions, incomplete tool identity, or drift between build and replay |
| Sanitized strict configuration | Required | Configuration schema/version, immutable bundle reference, byte size, and `sha256:<hex>`; no secrets | Profile + integration | Reject plaintext secrets, omitted effective values, mutable references, or any profile deviation |
| Qualification harness | Required | Version or full source commit plus harness/configuration digest | Integration + deterministic-gate | Reject an unversioned harness or a harness/config mismatch between dependent gates |
| G3 dependency graph and SBOM/provenance binding | Required per-output entries when the global G3 binding is `produced`; otherwise required as a typed downstream `not-run` value | Attempt-manifest entries and immutable references/digests for dependency graph, SBOM, and provenance, each tied to the global G3 binding and actual package-output digests; absent G3 output uses `not-run:blocked-at-G<N>:sha256:<hex>` | Dependency/license + deployment/release | Reject graph, package, SBOM, provenance, or G3-binding drift; reject a missing actual digest for any output that exists; reject issue if any entry is `not-produced` |
| Clean locked checkout | Required | `pass`/`fail`, RFC 3339 UTC, command digest, receipt reference, and receipt digest | Deterministic-gate owner | Reject unless `pass` proves a clean locked checkout for the full source commit |
| Deterministic gate | Required | Exact `mise run check` result, command/environment digest, receipt reference, and receipt digest | Deterministic-gate owner | Reject unless the exact final source passes deterministically; a retry without retained failure disposition is insufficient |
| Event/Go process gates | Required | Results and immutable receipts for Event-service process acceptance and checked-in Go generation/black-box acceptance | Event-service + API + deterministic-gate | Reject a missing/failing result or a claim that Go is an independent server implementation |
| Generic and profile validation | Required | Results and immutable receipts for side-effect-free generic validation and v0.1 deviation rejection | Integration + profile | Reject side effects, acceptance of a tested profile deviation, or conflation of broader generic values with v0.1 |

Signed Git metadata is not a v0.1 qualification field. The full source commit
is required, but this schema does not silently promote Git signature state into
a gate.

## 3. ARM64 artifact and procedures

Record one required artifact row. The architecture name and Debian package
architecture remain paired exactly as shown. When the global G3 binding is
`produced`, each package, authentication, package-manifest, SBOM, notices, and
provenance cell is a G3 attempt-manifest per-output binding. It preserves
`produced:sha256:<actual-output-digest>` for every existing output and uses
`not-produced:blocked-at-G3:sha256:<failure-receipt-digest>` only for an absent
output. If no G3 output exists, every row carries the exact global no-output
binding. No partial row can support issue.

| Architecture | Applicability | `.deb` per-output binding, file, and exact byte size | Provider-composed stripped executable size/digest | Authentication per-output binding, method, and result/receipt | Package manifest binding | SBOM binding | notices binding | provenance binding | Owner | Rejection rule |
|---|---|---|---|---|---|---|---|---|---|---|
| `aarch64` / `arm64` | Required | `<per-output binding>`; `<immutable name>`; `<decimal bytes>` | `<decimal bytes>` / `<sha256:hex>` when produced | `<per-output binding>`; `<exact detached-signature or signed-repository method>`; `<pass/fail>`; `<receipt + digest>` | `<per-output binding>` | `<per-output binding>` | `<per-output binding>` | `<per-output binding>` | Deployment/release owner | Reject wrong architecture, size/digest mismatch, failed/missing authentication, non-native package, output not built from G2, or any missing actual digest; reject issue for any `not-produced` entry |

| Procedure field | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Install/start/health procedure | Required | Immutable procedure reference, version, and digest; exact command sequence contains no secret | Deployment/OS owner | Reject if missing, mutable, secret-bearing, or not exercised by retained target receipts |
| Controlled restart/upgrade/permitted rollback procedure | Required | Immutable procedure reference, version, and digest; rollback is exact qualified-artifact reinstall against unchanged current state | Deployment/OS + release | Reject downgrade, snapshot restore, unknown state provenance, or any different rollback meaning |
| Uninstall/state-preservation procedure | Required | Immutable procedure reference, version, and digest, plus result receipt | Deployment/OS owner | Reject if uninstall/state behavior is absent, unverifiable, or differs between the mandatory CM4 nodes without an annexed distinction |
| Packaged supporting material | Required | Digests for hardened `systemd` unit, strict example config, Rust client source/build instructions, generated Go client/acceptance source, profile, frozen annex schema/blank template, evidence index, limitations, and escalation procedure | Deployment/release owner | Reject a missing required artifact, a subsequently completed candidate annex packaged before qualification, bundled credential/mission data/state/test secret, or digest mismatch |

## 4. Protected provider and lifecycle

| Field | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Approved initial D06 profile design | Required | Immutable reference to [`docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md`](../superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md); exact digest `sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f`; provider contract `aster-systemd-credential-store/v2`; Raspberry Pi reference `2026-06-18`, Debian 13 `trixie`, systemd `257.13-1~deb13u1`, physical CM4 Rev 1.1 `aarch64` scope | Profile/product owner | Reject a missing/mutable record, digest or contract mismatch, v1, Ubuntu, generic Debian, mismatched-systemd evidence, or a claim that profile approval closes E01 |
| systemd 257 presentation amendment | Required | Immutable reference to [`docs/superpowers/specs/2026-09-09-systemd-257-credential-presentation-amendment.md`](../superpowers/specs/2026-09-09-systemd-257-credential-presentation-amendment.md); exact digest `sha256:549ea3fd5bdfd62c01bab5a8f1adac4b84a2710ab406ea006119c9048e28d4cd`; exact file/directory ACL and read-only-`tmpfs`/`noswap` predicates | Profile/product owner | Reject a missing/mutable record, digest mismatch, widened ACL/mount acceptance, generic `tmpfs`/Debian claim, or a claim that product approval closes E01 |
| E01 Security approval | Required before G3 can pass or a candidate can issue | Immutable reviewer identity, Security role, `approve`/`refuse`, RFC 3339 UTC, exact D06 v2 design and presentation-amendment digests, provider contract/version, trust boundary, limitations, acceptance plan, and signed approval-record reference/digest | Security owner | Reject a missing/refusing/unsigned approval, either digest/provider mismatch, omitted limitation, approval after the bound G3 artifact was produced, or v1, Ubuntu, generic Debian, or mismatched-systemd evidence |
| E01 Deployment approval | Required before G3 can pass or a candidate can issue | Immutable reviewer identity, Deployment role, `approve`/`refuse`, RFC 3339 UTC, exact D06 v2 design and presentation-amendment digests, administration artifact/contract, package/runtime boundary, lifecycle procedure, limitations, acceptance plan, and signed approval-record reference/digest | Deployment owner | Reject a missing/refusing/unsigned approval, either digest/provider/package mismatch, omitted limitation, approval after the bound G3 artifact was produced, or v1, Ubuntu, generic Debian, or mismatched-systemd evidence |
| Protected provider identity | Required | Exact implementation name, version, source/build identity, `aarch64` architecture, trust/storage boundary, and immutable contract digest | Security + deployment | Reject an unapproved provider, an incomplete boundary, an unprotected fixture/engineering adapter, or provider drift |
| Administration artifact | Required | Exact immutable artifact identity, version, digest, and sanitized command-set digest | Security + deployment | Reject a mutable/missing artifact or a command set that exposes mission secret bytes |
| Install protected reference | Required | `pass`/`fail`, exact procedure digest, receipt reference, and receipt digest | Security + deployment + integration | Reject unless a protected node/mission reference is installed without repository or ordinary-config secret material |
| Startup load | Required | `pass`/`fail`, load-operation identifier digest, receipt reference, and receipt digest | Security + integration | Reject plaintext exposure, fallback to plaintext parsing, extra provider loads, or failure to reach the expected readiness state |
| Bearer rotation | Required | `pass`/`fail` for atomic `SIGHUP` reload, receipt reference, and digest | Event-service + security + integration | Reject non-atomic reload, process restart substituted for this case, or disclosure of either bearer value |
| Provider/reference rotation | Required | `pass`/`fail` for controlled restart, receipt reference, and digest | Security + deployment + integration | Reject live mutation, stale reference/provider use, or a different artifact/config candidate |
| Backup/recovery | Required | `pass`/`fail` using the provider's protected procedure, receipt reference, and digest | Security + deployment + integration | Reject ordinary-file plaintext backup, unbound restore, unknown state provenance, or unverifiable recovery |
| Revoke/rekey | Required | `pass`/`fail`; exact stopped-node administration procedure digest; new roster/key-generation identifier digest; receipt reference/digest | Security + integration | Reject live-membership claims, retained removed-node authentication, omission of explicit rekey behavior, or secret disclosure |
| Logical destroy/fail-closed startup | Required | `pass`/`fail`; provider destroy receipt digest and subsequent startup-failure receipt digest | Security + deployment + integration | Reject if provider-backed logical destruction is not followed by fail-closed startup, or if physical erasure is inferred |

## 5. Sanitized mission and policy identity

| Field | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Mission authority identifier | Required | Sanitized stable identifier or one-way commitment; no identity-bearing customer text | Security owner | Reject absence, ambiguity, unsanitized identity, or reuse as relay trust authority |
| Offline mission-root identifier | Required | Sanitized certificate/key identifier or public-material digest only | Security owner | Reject private material, missing offline-root identity, or more than one root for the profile |
| Delegated mission-signer identifier | Required | Sanitized signer identifier/public-material digest and delegation-record digest | Security owner | Reject private material, absent delegation, or more than one signer for the profile |
| Node roster identity set | Required | Digest of the exact sanitized distinct-node roster plus count | Security + integration | Reject duplicate identities, roster drift, or disagreement with participant inventories |
| Scope and topic identifiers | Required | Sanitized identifiers or commitments for exactly one scope and one topic per scenario | Security + profile | Reject unsanitized customer identity, more than one of either in a scenario, or inventory/config mismatch |
| Protocol/profile/suite | Required | Semantic protocol `6`, Aster security profile `0x0001`, hybrid suite `0x0001`, unordered profile-ID rule, and no-fallback result | Security + integration | Reject any different negotiated value, fallback, partial hybrid composition, or pre-inventory mismatch acceptance |
| Mission-policy identity | Required | Immutable authenticated policy digest, generation identifier, and exact permitted profile/suite pair | Security owner | Reject mutable/unsigned policy, rollback, or policy that permits another profile/suite |
| Mission versus relay authority separation | Required | Signed statement and receipt digest that mission root/signer authority is independent of optional relay DER TLS trust roots | Security + release | Reject conflation of carrier authentication with mission membership, scope/topic access, Event acceptance, or application authority |

## 6. Conditional pinned relay

Exactly one of the two rows below is completed. No private trust material is
ever recorded. DER trust-root certificates are public trust material; only
their exact public certificate digests belong here.

| Field | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Pinned relay used | Conditional: required when any relay claim is made | Exact sanitized relay ID/origin commitment, `direct_preferred`, customer-control attestation, explicit DER trust-root certificate digests, relay configuration digest, relay placement, loss/recovery receipt references and digests | Integration/physical-carrier + security | Reject WebPKI, `relay_only`, public/default fallback, hosted lookup, more than one relay, TLS bypass, private trust material, or missing relay-specific retained acceptance |
| Relay not used | Conditional: required when no relay claim is made | Exact signed statement `relay not used`, signer role/identity, RFC 3339 UTC, statement digest | Integration + release | Reject silence about relay use, an unsigned statement, or any relay result/claim elsewhere in the annex |

The relay remains carrier infrastructure, not an Aster durable store,
application authority, Aster bridge, or payload-blind custody node.

## 7. Participant inventory

The annex binds one mandatory inventory to exactly two physical CM4 Event
participants, with sanitized distinct node IDs, scenario IDs, and an immutable
inventory digest. Record the exact kernel `6.18.39+rpt-rpi-v8` build and systemd
`257.13-1~deb13u1` package on each node. Both nodes run the same G3 artifact.
A third CM4 is optional support only; declare its role and affected scenarios.
A replacement or other inventory change requires a new candidate and retained
receipts for that inventory; receipts from changed inventories cannot be pooled.

### 7.1 Mandatory two-node CM4 inventory and receipt set

| Field/group | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| CM4 node A | Required | Sanitized node ID; physical; Compute Module 4 Rev 1.1; `aarch64`; Raspberry Pi reference `2026-06-18`; Debian 13 `trixie`; exact kernel/systemd; local `ext4`; CPU/RAM/state allocation; peer role; path; network conditions | Integration/physical-carrier owner | Reject a VM, wrong platform, missing fact, non-profile allocation, or failure to exchange Events with node B |
| CM4 node B | Required | Same exact field set as node A with a distinct node identity | Integration/physical-carrier owner | Reject a VM, wrong platform, duplicate identity, missing fact, non-profile allocation, or failure to exchange Events with node A |
| Third CM4 support node | Conditional | Exact same identity fields plus `spare`, `replacement`, `failure-test`, or `relay` role and affected scenario IDs | Integration/physical-carrier owner | Reject undeclared traffic participation, ambiguous role, or evidence combined across changed inventories |
| Two-node receipt set | Required | Immutable index/digest of direct exchange, both ReceiveOnly identity orderings, restart/reopen, capacity, resource, workload, and applicable lifecycle/conditional-relay receipt references/digests | Integration + release | Reject a missing receipt, mutable index, digest mismatch, changed inventory, or broader node-tier claim |

## 8. Topology, configuration, emission, and harness limits

| Field/group | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Scenario authority/content shape | Required per scenario | Exactly one mission authority, one scope, one topic, and one durable application subscription for the scenario; record sanitized IDs and configuration digest | Profile + integration | Reject zero/multiple values, one-subscription-per-node reinterpretation, or mismatch with mission identity fields |
| Manual peers | Required per node | Zero to 19 exact operator-provided carrier-address/peer-identity bindings, serialized in canonical order with digest | Integration/physical-carrier | Reject more than 19, an arbitrary address replacement, an identity-free address, or a binding different from the run |
| Discovery | Required | Exact value `off` plus effective-configuration receipt | Integration owner | Reject automatic discovery or missing effective-state proof |
| Carrier paths | Required | Direct IP enabled; optional pinned relay state consistent with section 6; exact network-condition record digest | Integration/physical-carrier | Reject an unapproved carrier, public fallback, universal NAT claim, or unrecorded condition |
| Store limits | Required per node | `storage.max_items = 10_000`; `storage.max_payload_bytes = 67_108_864`; initial free local state at least 256 MiB; effective-status receipt | Lifecycle/capacity + integration | Reject any larger value, missing effective proof, insufficient free space, or description as Event-only/physical-file limits |
| Application connection limit | Required per node | `limits.max_connections = 1`, explicitly total application connections | Event-service + integration | Reject a larger value or reinterpretation as a per-client/identity limit |
| In-flight application operations | Required per node | Maximum 8 node-global in-flight operations | Event-service + integration | Reject a larger value or per-connection accounting |
| Emission mode | Required per node/run | Configured/effective `normal` or `receive_only`, startup timestamp, controlled-restart receipt for any change | Event-service + node + integration | Reject another mode, live mutation, configured/effective mismatch, or a radio-silence/zero-byte claim |
| Local application clients | Required per node/run | Maximum one harness client | Integration owner | Reject more than one or promotion to a general runtime identity limit |
| Page/scan limits | Required per run | Query page 16; gap page 16; delivery page 16; delivery scan 128; gap scan 128 | Integration + Event-service | Reject any deviation or the incorrect use of a 1,024-row delivery limit |
| Unacknowledged deliveries | Required per node/run | Maximum 256 simultaneously unacknowledged deliveries | Integration + Event-service | Reject a larger or unmeasured maximum |
| Payload boundary | Required per applicable run | Plaintext Event payloads 0 through 65,536 bytes | Integration owner | Reject a larger payload claim or characterization as an independently enforced server ceiling |
| Operation boundary | Required per state-directory lifetime | Maximum 1,024 distinct accepted publish-operation keys; warning no later than 512; keys 1–256 bytes; exact retries add zero mappings | Lifecycle/capacity + integration | Reject new publication beyond 1,024, warning after 512, key reuse for changed intent, directory replacement as recovery, or claim of a generic store admission limit |
| Mission timing | Required per soak | At most 48 continuous hours: exactly 24-hour disconnected publication followed by no more than 24 hours for reconnection/convergence/query/delivery/evidence | Integration owner | Reject a shorter substitute for a failed soak, publication beyond 24 hours, a reset calendar/state directory, or timing drift |

## 9. Four-row workload matrix and thirteen acceptance conditions

Each executed workload row records `pass`/`fail`, exact start/end times,
inventory/configuration/artifact digests, actual counts and bounds, network
conditions, and immutable receipt references/digests. A downstream row not
executed for `refuse` or `defer` records its exact typed
`not-run:blocked-at-G<N>:sha256:<receipt-digest>` value. The integration owner
owns every row; the release owner rejects an absent or failing required row for
`issue`, any untyped omission, any different workload, any receipt mismatch, or
a summary without its receipt.
The relay portion of applicable rows is conditional on section 6; direct
coverage remains required.

| Workload | Applicability | Format: nodes/payload/rate | Purpose and mandatory boundary | Owner | Rejection rule |
|---|---|---|---|---|---|
| API boundary | Required | 2 nodes; 0, 4 KiB, and 64 KiB; one exact Event at each boundary | Encoding, durable acceptance, transfer, query, delivery, and acknowledgement | Integration owner | Reject a missing payload boundary, more/fewer Events, changed node count, or unsupported receipt |
| Small topology | Required | 2 nodes; 4 KiB; 10 Events total at 1 Event/s | Direct and conditional pinned-relay recovery | Integration/physical-carrier owner | Reject per-node reinterpretation, changed count/rate, missing direct coverage, or a missing conditional-relay disposition |
| Offline soak | Required | 2 nodes; 4 KiB; 10 Events/hour/node for 24 hours | Disconnected publication, restart, later convergence, gaps, and capacity/resource behavior | Integration/device + Event-service owner | Reject a changed node count, shortened/restarted window, changed rate/payload, state replacement, or missing convergence/gap/resource receipt |
| Capacity-warning probe | Required | 2 nodes; 4 KiB; 512 distinct local operations plus one exact retry | Audited operation usage, warning no later than 50%, and retry without growth | Lifecycle/capacity + integration owner | Reject a missing/late warning, retry growth, changed operation count, or hard-cap saturation substituted for this probe |

The 64-KiB boundary is a payload boundary and bounded burst; sustained
publication uses the two-node 4-KiB soak. Every run starts from a fresh
zero-workload state directory while retaining provisioning controls, and records
final logical and physical headroom.

For each executed acceptance row, record `pass`/`fail`, the exact claim,
applicable workload/inventory IDs, producer, evidence type, execution
environment class, receipt reference, and receipt digest. A downstream row not
executed for `refuse` or `defer` records its exact typed `not-run` value. The
named owner reviews the row. Reject an `issue` if any row is absent, `fail`,
typed `not-run`, based on changed inputs, or unsupported by its immutable
receipt; reject any record containing an untyped omission.

| Acceptance condition | Applicability | Format / exact required result | Owner | Additional rejection rule |
|---:|---|---|---|---|
| 1 | Required | Clean locked source reproduces the one `arm64` package and its SBOM, notices, provenance, and checksums through the approved build path | Deterministic-gate + deployment/release | Reject any non-reproducible or unbound output |
| 2 | Required | `mise run check` passes deterministically; Event-service process acceptance and checked-in Go generation checks pass for the exact artifacts | Deterministic-gate + Event-service/API | Reject flaky/unretained reruns or different artifacts |
| 3 | Required | Generic configuration validation has no state, provider-load, or listener side effects; the annex validator rejects every tested v0.1 deviation | Integration + profile | Reject side effects or silent promotion of broader generic values |
| 4 | Required | Protected install/load, bearer rotation, provider/reference rotation, backup/recovery, revoke/rekey, and logical destroy pass without secret disclosure | Security + deployment + integration | Reject any missing lifecycle operation or privacy violation |
| 5 | Required | Both mandatory physical CM4 nodes pass install, readiness, normal stop, forced process loss, same-version restart, upgrade, permitted rollback, and uninstall/state preservation on the exact declared platform | Deployment/OS + integration/device | Reject a missing CM4 node, changed target, or VM evidence cited as physical evidence |
| 6 | Required | Rust publishes/consumes through the normative API; Go performs the same black-box wire/API recovery path against the Rust server | API + Event-service + integration | Reject calling Go an independent server or omitting either client |
| 7 | Required; relay subclaim conditional | The exact two-node four-row workload matrix passes in the retained environment; optional relay includes relay-loss/direct-path recovery, or the annex explicitly says relay not used | Integration/physical-carrier | Reject generic loss/latency/bandwidth brackets, changed node count, or silent relay omission |
| 8 | Required | Twenty-four-hour disconnected publication, intervening restart, later authenticated convergence, exact gaps, at-least-once redelivery, acknowledgement, and peerless reopen retain expected data | Integration + Event-service | Reject a shortened substitute, data loss, missing gap/replay evidence, or changed state |
| 9 | Required | `receive_only` passes both carrier-identity orderings without identity manipulation; initiates no contact, discloses no local Event/control inventory, accepts inbound Events, exposes effective mode, and records mandatory response traffic as non-silence | Event-service + node + integration/physical-carrier | Reject one ordering, favorable regenerated identities, local disclosure/initiation, failure to ingest, or radio-silence wording |
| 10 | Required | Operation/storage headroom, exact retry, changed-intent conflict, implementation-cap saturation, crash/reopen, and warning behavior are retained; post-retirement `ExpiredOrRetired` remains component-only evidence | Lifecycle/capacity + Event-service + integration | Reject black-box retirement claims, mapping reuse/deletion, or hard-cap evidence used to expand the supported workload |
| 11 | Required | RSS, CPU, executable size, startup, stop, state growth, and energy are measured on each mandatory physical CM4 node; every thresholded target passes and energy has no pass/fail claim | Integration/device + profile/release | Reject missing target measurements, threshold failure, or an invented energy threshold |
| 12 | Required | Packet/log/error inspection finds no forbidden plaintext or credentials within the stated metadata budget | Security + integration/physical-carrier | Reject a secret/plaintext finding or a claim broader than the inspected surfaces |
| 13 | Required | Release owner verifies every artifact/evidence digest, open-gate disposition, exact dependency graph, and annex before the signed evaluation decision | Release owner | Reject missing verification, an open evaluation-blocking row, or an unsigned decision |

## 10. Evidence classification and claim isolation

| Field/group | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Profile-qualification evidence type | Required | Exact evidence type `profile-qualification`; separate immutable index of black-box results against the exact packaged G3 artifacts and declared target/environment | Integration + release | Reject component/same-host evidence substituted for package, physical, provider, or release qualification |
| Component evidence type | Required when cited; otherwise signed `not cited` statement | Exact evidence type `component`; separate immutable index with exact component claim/non-claims and execution environment | Component owner + release | Reject presentation as black-box profile qualification or omission of environment/non-claims |
| Post-payload-retirement behavior | Required as a classification statement | Exact statement: existing `ExpiredOrRetired` behavior is component evidence only; v0.1 has no black-box retirement trigger | Lifecycle/capacity + Event-service | Reject a black-box retirement claim or an inference of finite TTL/Event-content deletion |
| Isolated engineering evidence type | Required when cited; otherwise signed `not cited` statement | Exact evidence type `isolated-engineering`; separate immutable index with exact engineering claim/non-claims and execution environment | Engineering producer + lifecycle/capacity | Reject presentation as qualification or unsupported extrapolation |
| Operation-map hard-cap saturation | Required as a classification statement | Exact statement: 4,096-row/512-KiB hard-cap saturation is isolated engineering evidence (or uses a test-only lower cap on the production transaction path) and does not expand the 1,024-operation workload claim | Lifecycle/capacity + release | Reject inclusion in the ordinary workload, capacity expansion, reclamation claim, or missing isolation |
| Generated-client contract evidence type | Required | Exact evidence type `generated-client-contract`; immutable receipt for checked-in Go generation and Go black-box API recovery against the Rust server | API + Event-service + deterministic-gate | Reject omission, presentation as an execution environment or independent-server evidence, or a claim beyond the client/API contract |
| Independent-server evidence type | Required when cited; otherwise signed `not cited` statement | Exact evidence type `independent-server`; immutable receipt identifying the independently authored server boundary | Conformance/security + release | Reject presentation as an environment class, substitution by generated Go client evidence, or unsupported interoperability claim |

Evidence type and execution environment class are independent fields. A receipt
records exactly one evidence type and exactly one primary execution environment
class. Environment classes are `same-host-software`, `virtual-machine`,
`network-namespace`, and `physical-device`; generated-client checks and
independently implemented server evidence are evidence types, not environments.
No type or environment class silently inherits the claims of another.

## 11. Approved resource and capacity measurements

Record the measured value, unit, method/procedure digest, CM4 node identity,
workload/inventory ID, start/end state, result, receipt reference, and receipt
digest for every row. Integration/device owns collection; the named co-owner
reviews the result. Reject missing/unverifiable measurements, threshold failure,
environment drift, or any changed target presented as v0.1.

| Measurement | Applicability | Format / v0.1 threshold or treatment | Co-owner | Additional rejection rule |
|---|---|---|---|---|
| Stripped deployed executable | Required per mandatory CM4 node | No more than 16 MiB | Deployment/release | Reject non-provider-composed or nondeployed executable measurement |
| Steady-state RSS | Required per mandatory CM4 node/scenario after declared stabilization | No more than 64 MiB | Profile/release | Reject absent stabilization definition or threshold failure |
| Peak RSS | Required per mandatory CM4 node/scenario | No more than 128 MiB | Profile/release | Reject incomplete scenario observation or threshold failure |
| Idle CPU | Required per mandatory CM4 node | No more than 5% of one core with no active contact or client request | Profile/release | Reject busy conditions labeled idle or threshold failure |
| Readiness | Required per mandatory CM4 node for start/restart | Within 10 seconds | Deployment/OS | Reject readiness after threshold or detail-bearing unauthenticated health proof |
| Graceful stop | Required per mandatory CM4 node | Within 30 seconds | Deployment/OS | Reject stop after threshold or loss of required durable state |
| Initial state free space | Required per node/scenario | At least 256 MiB | Integration/device | Reject lower space or missing physical/filesystem measurement |
| State growth/final free space | Required per node/scenario | Measure physical database/filesystem growth and final free space; no added threshold beyond profile admission/headroom | Lifecycle/capacity + profile | Reject omission, plaintext-only arithmetic used as byte-fit evidence, or invented threshold |
| Logical item use | Required per node/scenario | Measured against 10,000 aggregate items and the 5,840 ordinary-slot budget; two-node soak projects 720 ordinary items per converged node (480 Events plus 240 local publish-operation mappings), leaving 5,120 projected slots before other aggregate-counted rows | Lifecycle/capacity | Reject Event-only accounting, omitted control/reserve rows, or projection substituted for audited composition |
| Logical byte use | Required per node/scenario | Measured against 67,108,864 aggregate logical bytes and 50,266,112 ordinary logical bytes after reserves | Lifecycle/capacity | Reject physical amplification conflation or unsupported byte-fit claim |
| Operation-map rows/bytes | Required per node/scenario | Actual rows/bytes; hard ceilings 4,096 rows/512 KiB; profile boundary 1,024 distinct operations | Lifecycle/capacity | Reject unaudited counts, hard-cap/profile-boundary conflation, or workload beyond 1,024 |
| Operation headroom/warning | Required per node/scenario | Remaining profile headroom; actionable warning no later than 512 operations | Lifecycle/capacity | Reject negative/missing headroom, late warning, or a warning treated as pass |
| Physical-target energy | Required for each mandatory physical CM4 node | Measured and reported with method/environment; no v0.1 pass/fail threshold | Integration/physical-carrier + profile | Reject omission or assignment of a qualification threshold |

Network/block-I/O metrics, extra runtime fingerprints, fleet fields, and SLOs
are not v0.1 qualification fields. They may appear only in a clearly separate
informational appendix that is outside the annex decision and cannot fail or
broaden this profile.

## 12. Immutable receipt index

Create one row per retained receipt. Summaries and aggregate tables never
replace this index.

| Field | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Receipt identity and digest | Required per receipt | Unique sanitized receipt ID, immutable reference, byte size, media type, and `sha256:<hex>` | Receipt producer | Reject a mutable/missing reference, digest/size mismatch, or duplicate identity |
| Producer | Required per receipt | Sanitized producer identity, accountable role, producer tool/version digest, and RFC 3339 production time | Receipt producer + relevant gate owner | Reject an unknown producer, missing role, or mutable/unversioned producer |
| Evidence type | Required per receipt | Exactly one primary type: `profile-qualification`, `component`, `isolated-engineering`, `generated-client-contract`, or `independent-server` | Relevant gate owner + release | Reject an ambiguous/missing type or use of a type as an execution environment |
| Execution environment class | Required per receipt | Exactly one primary class: `same-host-software`, `virtual-machine`, `network-namespace`, or `physical-device`; add exact environment/inventory digest | Integration + release | Reject ambiguous class, unrecorded virtualization/namespace use, or physical overclaim |
| Exact claim | Required per receipt | Bounded declarative claim tied to exact artifact/config/provider/inventory/workload IDs | Relevant gate owner | Reject a claim broader than recorded observations or detached from the exact candidate |
| Explicit non-claims | Required per receipt | Nonempty list of material exclusions, including inapplicable physical, independent, package, provider, or release claims | Relevant gate owner + release | Reject absent non-claims or silent inheritance from another evidence class |
| Verification/replay | Required per receipt | Exact verification command/procedure digest, result, and any controlled-storage dependency | Deterministic-gate + release | Reject if the receipt cannot be verified, required raw custody is unavailable, or secrets would enter the repository |

## 13. G1-G6 dependency and exit matrix

Each row records the gate status, owners, predecessor exit digests, immutable
exit-artifact references/digests, reviewed time, and signature/approval record.
The release owner rejects an `issue` if a required digest is absent, a gate is
not `pass`, an input changed, or the serial dependency was bypassed.

| Gate | Applicability | Dependency | Format / required exit | Primary owner | Rejection rule |
|---|---|---|---|---|---|
| G1 — Event baseline | Required antecedent record | None | Accepted Event-service baseline plus frozen emission/capacity contract; immutable exit digests | Event-service + node + lifecycle/capacity | Reject an unaccepted baseline or an unfrozen contract; G2 cannot start |
| G2 — Source/API freeze | Required | G1 pass | ReceiveOnly and capacity behavior merged; focused tests pass; one source/API commit and exit digest frozen | Event-service + node + deterministic-gate | Reject source/API drift or failed/missing focused tests; G3 cannot start |
| G3 — Artifact freeze | Required | G2 pass | If any output exists, immutable G3 attempt manifest with every required per-output produced/not-produced binding; for pass, one reproducibly built and authenticated provider-composed `arm64` package from G2 plus complete artifact-set manifest/digest and exit digest | Deployment + security + release | Reject unmanifested partial output, a missing actual digest, an absent `arm64` package, any per-output `not-produced`, nonreproducibility, failed authentication, incomplete artifact-set manifest, or any source other than G2; G4/G5 cannot use another artifact |
| G4 — Focused target tests | Required | G3 pass | Install, lifecycle, Rust/Go API, both ReceiveOnly identity orderings, direct and conditional-relay scenarios pass on both mandatory CM4 nodes using the unchanged G3 artifact; exit digests | Integration/physical-carrier + security | Reject any failed/missing required case, missing CM4 node, or artifact drift; G5 qualification cannot substitute for G4 |
| G5 — Workload qualification | Required | G3 and G4 pass | Two-node four-row workload matrix, including 24-hour disconnected publication, passes from G3 with the exact signed CM4 inventory and immutable exit digests | Integration/device + physical-carrier | Reject a missing workload row or mandatory CM4 node, altered artifact/environment, ambiguous participant, shortened soak, or missing receipt |
| G6 — Disposition | Required | G1–G5 pass in order for `issue`; refusal/defer may follow an earlier blocking gate | Receipt review, deterministic-gate rerun when reached, typed downstream `not-run` values when not reached, and detached signed `issue`/`refuse`/`defer` decision over the canonical signable-body digest, sorted Section 15 candidate-approval digests, candidate ID, schema digest, and exact typed global G3 artifact binding | Release owner with all final roles | Reject issue if any prior gate is absent/failing, any evaluation blocker remains, any G3 per-output entry is not produced, the `arm64` package/authentication is absent/failing, the complete artifact-set manifest is absent/invalid, a digest changed, or the decision is unsigned; reject refusal/defer if a no-output pre-G3 stop lacks global `not-produced`, a partial G3 attempt lacks actual/absent per-output bindings, or downstream omissions lack typed `not-run` bindings |

## 14. Exact `DM-8-05` proposal and approvals

The proposal is evaluation-only, adds no general license allowlist, and does not
close the formal production requirement. Dependency/license, Legal/compliance,
and Release approval closes P0-1 register row `P0-1-D15`. The consolidated
repository record binds all three reported internal role outcomes to the exact
coordinates/licenses and proposal digest. Its committed reference and digest
are included in the canonical signable candidate body; the record is not
replaced, re-signed against the candidate body, deferred to G6, or included
among Section 15 detached candidate approvals.

| Field | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Proposal identity | Required | `dm-8-05-linux-event-v0.1-disposition.md`; `sha256:a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53` | Dependency/license + release | Reject a mutable/missing proposal or digest mismatch |
| Exact coordinates | Required | `webpki-root-certs` `1.0.9` / `b96554aa2acc8ccdb7e1c9a58a7a68dd5d13bccc69cd124cb09406db612a1c9b` / `CDLA-Permissive-2.0`; `webpki-roots` `1.0.9` / `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a` / `CDLA-Permissive-2.0` | Dependency/license owner | Reject package, version, source, checksum, reachability, dependency-graph, license, SBOM, or notice drift |
| Dependency approval | Approved 2026-09-08 | [Consolidated internal role-approval record](dm-8-05-linux-event-v0.1-role-approvals.md), `sha256:4edda9457c78d0c1d177590c1583691071e708ccbbace078cc15a82dd9bcac85`, bound to the proposal digest and exact tuples | Dependency/license owner | Reject a missing record, coordinate/license/proposal mismatch, or omission of its committed reference/digest from the signable body |
| Legal approval | Approved 2026-09-08 | [Consolidated internal role-approval record](dm-8-05-linux-event-v0.1-role-approvals.md), `sha256:4edda9457c78d0c1d177590c1583691071e708ccbbace078cc15a82dd9bcac85`, bound to the proposal digest and exact tuples | Legal/compliance owner | Reject a missing record, coordinate/license/proposal mismatch, widened scope, or omission of its committed reference/digest from the signable body |
| Release approval | Approved 2026-09-08 | [Consolidated internal role-approval record](dm-8-05-linux-event-v0.1-role-approvals.md), `sha256:4edda9457c78d0c1d177590c1583691071e708ccbbace078cc15a82dd9bcac85`, bound to the proposal digest and exact tuples | Release owner | Reject a missing record, coordinate/license/proposal mismatch, candidate/production authorization claim, or omission of its committed reference/digest from the signable body |
| Production limitation | Required | Signed statement that `DM-8-05` remains formally open and production-blocking after any evaluation approval | Dependency/license + legal + release | Reject any production authorization, general allowlist, WebPKI/public-relay authorization, or claim that the requirement is closed |

Dependency/license, Legal/compliance, and Release status is **Approved**.
Repository lockfile, dependency-policy, notice, SBOM, or passing-gate facts do
not replace the committed approval record. Any mismatch in the later candidate
graph invalidates the bounded approval for that candidate.

## 15. Final role approvals and detached signatures

The completed annex is a bundle, not a self-signing byte string:

1. Canonicalize a signable annex body/manifest after every non-signature fact
   and receipt reference is final. It includes the candidate ID, frozen schema
   digest, exact typed global G3 artifact binding, every G3 per-output binding,
   facts and results from sections 1–14 other than the detached final outcome,
   the immutable Section 4 E01 and Section 14 prerequisite approval
   references/digests, and typed downstream `not-run` bindings. It excludes
   only Section 15 detached
   candidate approvals/signatures and the detached release-decision record.
2. Compute the canonical signable-body digest. Every Section 15 final role
   approval is a distinct later candidate attestation and a detached record that
   signs this same body digest. The Section 15 dependency, legal, and release
   attestations do not replace the earlier Section 14 P0-1 records. For
   `refuse` or `defer`, a candidate role not reached is represented by a typed
   downstream `not-run` binding; every approval actually produced retains its
   actual digest.
3. Sort only the Section 15 detached candidate-approval record digests bytewise
   by lowercase digest. The final detached release decision signs the body
   digest, that sorted list, candidate ID, frozen schema digest, and exact typed
   global G3 artifact binding.
4. Verify the Section 4 E01 and Section 14 prerequisite records and their
   references in the body, then the body digest, every Section 15 detached
   candidate approval against it, the sorted Section 15 approval list, and the
   final release decision. A final archival bundle digest may cover the body,
   Section 4 E01 records, Section 14 prerequisite records, Section 15 detached
   approvals, and detached release decision, but is not an input to any of
   those signatures and grants no additional qualification claim.

Every approval is required for `issue`. For `refuse` or `defer`, record the
approvals obtained and exact typed blockers for roles not reached.

| Approval | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| Canonical signable annex body | Required | Canonicalization identifier/version, immutable body reference, byte size, and digest; includes immutable Section 4 E01 and Section 14 prerequisite approval references/digests and excludes Section 15 candidate approvals plus the release decision | Profile + release | Reject nondeterministic canonicalization, a digest mismatch, missing Section 4 E01 or Section 14 references, or inclusion of a Section 15/release record that creates a digest/signature cycle |
| Profile/product | Required for issue; otherwise approval or typed `not-run` | Detached immutable approval record that signs the body digest; record digest | Profile/product owner | Reject issue if absent, refusing, unsigned, or bound to a different body/candidate/schema/G3 binding; reject an untyped omission |
| Security | Required for issue; otherwise approval or typed `not-run` | Detached immutable approval record that signs the body digest; record digest | Security owner | Reject issue if absent, refusing, unsigned, or bound to a different body/candidate/schema/G3 binding; reject an untyped omission |
| Deployment/OS and artifact | Required for issue; otherwise approval or typed `not-run` | Detached immutable approval record that signs the body digest; record digest | Deployment/OS/artifact owner | Reject issue if absent, refusing, unsigned, or bound to a different body/candidate/schema/G3 binding; reject an untyped omission |
| Integration/device/physical carrier | Required for issue; otherwise approval or typed `not-run` | Detached immutable approval record that signs the body digest; record digest | Integration/device/physical-carrier owner | Reject issue if absent, refusing, unsigned, or bound to a different body/candidate/schema/G3 binding; reject an untyped omission |
| Event-service/API/runtime | Required for issue; otherwise approval or typed `not-run` | Detached immutable approval record that signs the body digest; record digest | Event-service/API/runtime owner | Reject issue if absent, refusing, unsigned, or bound to a different body/candidate/schema/G3 binding; reject an untyped omission |
| Deterministic gate | Required for issue; otherwise approval or typed `not-run` | Detached immutable approval record that signs the body digest; record digest | Deterministic-gate owner | Reject issue if absent, refusing, unsigned, or bound to a different body/candidate/schema/G3 binding; reject an untyped omission |
| Dependency/license | Required for issue; otherwise approval or typed `not-run` | Detached immutable approval record that signs the body digest; record digest | Dependency/license owner | Reject issue if absent, refusing, unsigned, or bound to a different body/candidate/schema/G3 binding; reject an untyped omission |
| Legal/compliance | Required for issue; otherwise approval or typed `not-run` | Detached immutable approval record that signs the body digest; record digest | Legal/compliance owner | Reject issue if absent, refusing, unsigned, or bound to a different body/candidate/schema/G3 binding; reject an untyped omission |
| Release decision | Required | Detached signed immutable `issue`/`refuse`/`defer` record over body digest, bytewise-sorted Section 15 candidate-approval digests, candidate ID, schema digest, and exact typed global G3 artifact binding | Release owner | Reject an unsigned, ambiguous, cyclic, unsorted, or mismatched decision; issue is forbidden unless all approvals/gates pass, every G3 per-output entry is produced, the `arm64` package authenticates, and the complete artifact-set manifest verifies |
| Archival bundle | Conditional: when an archival bundle is formed | Immutable manifest/reference and digest covering body, Section 4 E01 records, Section 14 prerequisite records, Section 15 detached approvals, and detached release decision | Release owner | Reject if used as a signature input, substituted for verification of any contained record, or presented as an additional claim |

No signature may stand in for a missing fact, receipt, gate, approval, or typed
blocker.

## Annex rejection rules

Reject an annex as support for qualification if:

- a required value is absent, mutable, ambiguous, or unverifiable;
- a digest, artifact-authentication, approval, or signature check fails;
- source, artifacts, configuration, provider, or test environment differs
  across dependent gates without a new candidate;
- the `arm64` artifact or either mandatory physical CM4 node is missing;
- topology, workload, limit, or timing differs from the profile;
- an evaluation-blocking register row remains open;
- a summary lacks its immutable receipt;
- component or engineering evidence is presented as black-box qualification;
- a warning or the 2026-09-13 checkpoint is treated as a pass; or
- a secret, credential, private key, bearer token, mission plaintext, private
  trust material, or unsanitized customer identity is embedded.

A rejected `issue` claim may still be preserved as a signed `refuse` or `defer`
decision with the exact failures and receipts. It does not become qualification
evidence.

## Schema and annex lifecycle

After owner review, schema freeze gets a reviewed version and digest. Changing a
frozen required field or evidence boundary creates a new schema revision and
invalidates incomplete candidate annexes; it never rewrites an issued annex.

An issued annex, its v0.1 claim, and receipt bundle are immutable. An editorial
correction that changes no boundary produces v0.1.1. Any changed target,
behavior, gate, or evidence boundary produces v0.2, retains the prior annex for
audit, and requires a new candidate decision. Deleting or replacing a state
directory, restarting the mission calendar, or changing source, artifact,
provider, configuration, or environment never repairs an incomplete or failed
candidate.
