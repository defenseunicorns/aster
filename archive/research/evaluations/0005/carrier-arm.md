# Carrier arm: BTLE, tiny-MTU, broadcast, and offline media

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


Status: completed research arm; requirements-first recommendation and
deterministic evaluator evidence, not a production admission or implementation
decision.

## Outcome first

The cleanest delete-first architecture is **not** a monolithic “native versus
libp2p versus Iroh” choice. It is a narrow, carrier-neutral protocol boundary
with replaceable platform mechanisms beneath it:

1. Keep protected objects, synchronization, durable progress, difference
   discovery, retry/repair, deduplication, loop control, priority/expiry, and
   cross-transport identity above every carrier.
2. Put one common fragmentation and record envelope above thin adapters, so
   BTLE, IP, serial, and files do not each invent their own durable transfer
   state.
3. Prefer buying the platform mechanism once its exact graph is admitted:
   - **BlueR** is the smallest observed single-component Linux Tier-2 candidate for
     central/client plus peripheral/server GATT, advertising, and LE L2CAP.
   - **TrouBLE** is the best observed directly permissively declared future
     Tier-1/no-OS host-stack direction for both roles, GATT, and L2CAP CoC.
   - **btleplug** can buy cross-platform central/client mechanics, but it is
     explicitly central-only and cannot be the peer adapter by itself.
   - **Willow Drop**, subject to its own arm's full-graph admission limits, has
     the strongest observed bounded offline object-file behavior among directly
     permissively declared candidates.
   - **Trickle (RFC 6206)** buys broadcast-suppression semantics, not delivery,
     repair, security, or a radio adapter.
4. Keep a deliberately small custom residue: thin Apple/Android/Windows
   peripheral/server glue where no admissible complete wrapper exists, subject
   to an explicit legal decision on how literal `DM-8-05`/`DM-8-07` treat
   OS-supplied SDK/framework APIs; the
   common carrier envelope; persistent receive progress; and the offline
   bidirectional transcript/container that the final sync protocol requires.

No reviewed component is admitted for production in this arm. BlueR still
needs a file-level license disposition because its repository license includes
GPL-2 text for copied/adapted documentation in addition to the crate's
BSD-2-Clause declaration. Every candidate still needs an exact dependency
graph, security disposition, target build, and real OS/controller qualification
where applicable.
Native platform APIs are not silently exempted from the dependency policy.
Before using CoreBluetooth, Android Bluetooth, or WinRT as the residual
mechanism, the project must define and approve how OS-supplied SDK/framework
licenses are treated under the literal OSI-only and no-proprietary-dependency
requirements. If no compliant interpretation or explicit requirements change
is approved, those platform slices cannot be admitted.

The complete symmetric cross-platform candidates did not survive the admission
gate:

- `iroh-ble-transport` 0.3.1 and the reviewed `blew` documentation are
  AGPL-3.0-or-later. They are hard-excluded from reuse and remain research-only
  architecture observations.
- SimpleBLE 1.1.1 is BUSL-1.1, limits free use to non-commercial/non-production
  use, requires a commercial license for production/commercial use, and changes
  each version to GPL-3.0 after four years. It is not an admissible production
  FOSS buy.

This outcome has zero weight for current Aster compatibility. The sole
architecture authority is
[`data-mesh-requirements.md`](../../../data-mesh-requirements.md), version 0.1,
SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.

## Why this boundary follows from the requirements

The non-compensable carrier invariants are:

- transport diversity and mobility (`DM-1-06`, `DM-3-07`, `DM-3-08`);
- MVP IP and BTLE adapter scope (`DM-2-05`, `DM-5.8-11`, `DM-13-05`);
- direct and infrastructure-free peer synchronization (`DM-5.6-01`,
  `DM-5.6-02`);
- temporal store-and-forward and any-peer continuation (`DM-5.6-03`,
  `DM-5.2-19` through `DM-5.2-22`);
- a defined pluggable abstraction and protocol-independent transport addition
  (`DM-5.8-01`, `DM-5.8-02`);
- fragmentation/reassembly from tens of bytes through 1500+ with practical
  small-MTU overhead (`DM-5.8-03` through `DM-5.8-05`);
- an offline-serializable entire exchange even though file and serial carriers
  are Future (`DM-5.8-13` through `DM-5.8-15`);
- transport-independent security and protected forwarding metadata (`DM-6-01`
  through `DM-6-04`, `DM-6-09`, `DM-6-11`, `DM-6-12`); and
- fragmentation hidden from the public API (`DM-7-13`).

Broadcast is a real environmental invariant (`DM-3-09`), and one-to-many use is
a strong default (`DM-5.6-04`), but duplicate and loop propagation must remain
bounded (`DM-5.6-05`, `DM-5.6-06`). The carrier therefore cannot equate
“broadcast send” with a complete dissemination protocol.

The low-single-digit-kbps and 50% loss numbers are provisional decision points,
not hard elimination gates (`DM-9-19`, `DM-9-20`). The underlying capabilities
remain binding (`DM-3-04`, `DM-9-19A`, `DM-9-20A`). This arm records 3 kbps and
50% rows without treating either as a pass/fail definition. The same rule
applies to the provisional 30-day offline value: durable continuation is the
invariant; the accepted interval remains a stakeholder decision.

## Candidate freeze and responsibility coverage

Exact archives, locks, license-file hashes, and no-credit boundaries are in
archived `source-freeze.tsv`.

| Candidate | Central | Peripheral | GATT | LE L2CAP | Platforms in direct evidence | Admission result |
|---|---:|---:|---:|---:|---|---|
| btleplug 0.12.0 | Yes | **No** | client | No reviewed server/CoC surface | Windows, macOS, Linux, iOS, Android | Slash-delimited all-permissive manifest declaration; legal/full-graph admission pending; central mechanics only |
| BlueR 0.17.4 | Yes | Yes | client + server | Yes | Linux/BlueZ | Best Linux mechanism buy; legal/graph/hardware hold |
| TrouBLE host 0.8.0 | Yes | Yes | client + server | CoC with credits | embedded controllers; Linux HCI example | Best future Tier-1 host direction; qualification/graph/hardware hold |
| ble-peripheral-rust 0.2.0 | No | Yes | server | No | Linux, Windows, Apple in manifest | MIT but incomplete; Android cfg/dependency mismatch and audit hold |
| iroh-ble-transport 0.3.1 | Yes | Yes | bootstrap/fallback | opportunistic | iOS, macOS, Android, Linux | **Excluded: AGPL-3.0-or-later** |
| blew 0.1.0 docs | Yes | Yes | Yes | opportunistic | Apple, Linux, Android | **Excluded: AGPL-3.0-or-later; alpha docs only** |
| SimpleBLE 1.1.1 | claimed Yes | claimed Yes | cross-platform wrapper | not credited here | Windows, macOS, Linux, iOS, Android | **Excluded: BUSL now, GPL-3 later** |
| Native platform APIs | Yes through platform surfaces | Yes through platform surfaces | client + server mechanics | platform-specific and unqualified | Apple, Android, Windows | Small custom glue residue; not a FOSS component |

### Exact exclusion facts

`iroh-ble-transport` was frozen at commit
`c16f5ee6f53aa2c706753701e3565fe74aa0a04e`, crate 0.3.1, archive SHA-256
`53d848e1183ef52d518a2d4dd79b48fb8129d7acd849d761e277b556a34e3794`,
with manifest and full license declaring `AGPL-3.0-or-later`. Its manifest pins
`blew = "0.3"` and `iroh = "0.98.2"` with `unstable-custom-transports`. Its
README explicitly calls the component experimental and says not to rely on it
before sufficient field testing. The whole-workspace lock has 768 packages;
the frozen RustSec result reports 6 vulnerabilities, 18 unmaintained warnings,
and 4 unsound warnings. Reachability was not assessed. The license exclusion is
decisive before those technical risks.

The direct `blew` 0.1.0 README receipt has SHA-256
`4905647dadd6eeb3da845ca59aba0cead4404661a639f071447b5e0971ba6305`.
It calls itself alpha, advertises central and peripheral roles plus
opportunistic L2CAP on Apple/Linux/Android, and declares
AGPL-3.0-or-later with a commercial-license alternative. Because the frozen
Iroh adapter actually pins `blew` 0.3, the 0.1.0 documentation receives no
exact-current implementation or support credit.

SimpleBLE was frozen at commit
`10fe5852f69e8105a755692b7571113b439762a3`, version 1.1.1, archive SHA-256
`887239019bbe93910bf02073e2082858df4a57711d83528cfe046da5090a6d3e`.
Its exact `LICENSE.md`, SHA-256
`140664ee292a8b93200612a012cd585b3aeebb171d5aeb792acb271c9add2599`,
says production/commercial use requires a commercial license and each version
changes to GPL-3.0 four years after initial release. Its claimed all-platform
central/peripheral coverage does not override that exclusion.

### Permissive candidates and their smallest useful slice

**BlueR.** Frozen commit
`57ec704503417a6476bca5d3bb01122686583709`, crate 0.17.4, archive SHA-256
`c50c4e236e384878a8655e8cd4d6e80a2b4a991f6caa78a48cd5acccf48a5ad0`.
Direct source exposes local and remote GATT, advertising/monitoring, and LE
L2CAP stream, sequential-packet, and datagram sockets. This is the smallest
observed single Linux component that removes both role implementations and the
L2CAP socket surface. It remains Linux-only, depends on BlueZ/`bluetoothd` and
D-Bus for GATT, says it was tested with BlueZ 5.60, and warns that EATT can
reorder GATT commands/notifications. Its crate manifest says BSD-2-Clause, but
the repository license also embeds BSD-3 assigned-number terms and GPL-2 text
for copied/adapted API documentation. File-level legal disposition and an exact
graph are required before admission.

**TrouBLE.** Frozen commit
`4eea72088fdbb91326a3ac95160b3154fdff802a`, `trouble-host` 0.8.0,
archive SHA-256
`36f8eae90ebcd7b2cbc4720f2921fe505b1cc4bf828f6575b3eb430ca84eb72a`.
It is dual Apache-2.0/MIT, `no_std`, supports both roles, GATT server/client,
and L2CAP CoC credit management behind a controller trait. That is the best
observed way to avoid inventing a future Tier-1 BLE host. Upstream explicitly
describes qualification as a future goal, and there is no frozen repository
lock or observed security policy. It earns no qualification, controller,
target-size, power, or hardware credit.

**btleplug.** The exact 0.12.0 registry archive is SHA-256
`52c3264dbe2c8e29381e4e95aa2d2783ad0b9192b511240f3755b7e5e3cee87e`;
its 160-package lock is SHA-256
`338727342f258cf7597ad7a59b9597e33723a11352de5b4f2c1a1d4e7a9d9444`.
Its README explicitly says host/central mode only. It can delete central-side
platform code, but pairing it with a second peripheral library creates two
lifecycles, discovery surfaces, and platform integration paths. It must be
compared with a single thin native symmetric adapter before adoption.

**ble-peripheral-rust.** Frozen commit
`3135b029bd9f3e57c871039b087080bf511f6fe3`, crate 0.2.0, MIT, archive
SHA-256
`8b99c1dbda4f323aa141cc35db9cc1d9648d6a50c13968d188dd7d79a316539e`.
It is a 2,664-line Rust peripheral GATT wrapper with Linux, Windows, and Apple
dependencies. Static source inspection found that the BlueZ module is selected
for `linux` **or `android`**, while the `bluer` dependency is declared only for
Linux. It therefore does not supply a coherent Android backend as frozen. It
has no L2CAP surface, no observed repository CI/security policy, and only UUID
unit tests were observed. Its 113-package lock also carries one RustSec
vulnerability and one unsound warning; reachability was not assessed. It is not
the missing cross-platform half without additional work.

**Android native residue.** The directly reviewed
`BluetoothGattServer`/`BluetoothGattServerCallback` pages establish native
GATT-server service registration, request/response, notification, connection,
MTU-change, and lifecycle callbacks. They bound a thin Android peripheral
adapter residue; they are platform documentation, not FOSS or hardware proof.
The class/core server and read/write/connection surfaces date to API 18;
notification completion is API 21 and must be awaited before another
notification according to the page; MTU-change callback is API 22; and the
value-taking per-client notification API is API 33 with a documented 512-byte
maximum attribute value. The older API-18 notification overload is deprecated
at API 33 as not memory safe. These platform-level facts make queueing, usable
payload, and target-version behavior explicit adapter gates rather than common
protocol assumptions.
Registered Apple CoreBluetooth and Windows `GattServiceProvider` evidence gives
the same bounded conclusion for those platforms.

## Recommended carrier boundary

This is a responsibility boundary, not a frozen programming API.

### Carrier adapter owns

- open/close and local link lifecycle;
- automatic discovery and manual endpoint mechanics, including a hard
  “do not advertise/discover” switch;
- sending and receiving opaque bytes to a peer or, when real media supports it,
  a shared one-to-many target;
- the currently usable payload/SDU limit and whether the surface is datagram,
  ordered stream, or offline record log;
- observed ordering/reliability characteristics without making them correctness
  assumptions; and
- bandwidth, cost, and emission-footprint estimates for upper-layer policy
  (`DM-5.8-16` through `DM-5.8-18`).

### Common carrier envelope owns

- protocol version/extension handling for the envelope;
- bounded fragmentation, frame validation, reassembly, and stream/file record
  delimiting;
- persistent receive progress keyed to durable object/exchange identity rather
  than connection, OS handle, or original peer; and
- the offline bidirectional transcript representation.

### Synchronization/security layer owns

- source encryption, membership-layer metadata protection, mutual
  authentication, authenticated integrity, replay/freshness, and authorization;
- content identity and authenticated object digest;
- replica difference discovery and any-peer missing-set negotiation;
- retry/repair, application deduplication, loop suppression, relay custody,
  priority/expiry, quota, scheduling, and cross-transport continuation; and
- the public API, which never exposes fragments or transport selection.

This placement keeps adapters replaceable (`DM-5.8-01`, `DM-5.8-02`) and avoids
binding durable correctness to an ephemeral carrier (`DM-3-07`). It also makes
file transfer possible without pretending a removable drive is an interactive
socket (`DM-5.8-15`). Link-level acknowledgements or retries may still improve
performance, but the protocol cannot rely on them for correctness.

### Delete-first implications

- Do not put a second durable fragmentation/retry state machine inside every
  adapter. BPv7 offers useful delay-tolerant semantics, but adopting its bundle
  fragmentation beneath another resumable sync protocol would duplicate
  identity, custody, retry, and expiry responsibilities unless BPv7 becomes the
  one authoritative envelope.
- Do not expose “BLE peer,” “IP peer,” and “file peer” as different durable
  replica identities.
- Do not make `connected` the precondition for serializing sync messages.
- Do not infer confidentiality from BLE pairing, QUIC/TLS, a filesystem, or any
  other transport. Clear input bytes remain clear through the evaluator.
- Do not mistake BLE advertising/discovery for bulk one-to-many dissemination.
  Actual advertising payload, scheduling, background, and repair behavior must
  be measured on hardware.

## Executable carrier-envelope evidence

The dependency-free evaluator is
archived `carrier_matrix.py`,
SHA-256
`d503530f4d91e44a1b19f30da40c88c779f6a6c7cc11f73258bde51b35a68280`.
The frozen result is
archived `summary.json`,
SHA-256
`0737e3d3f8c0f74100e8746a7dd3944b444a2a135af889588d8657956f2c3928`.
Two separate clean run directories produced byte-identical summaries.

The input is the 471-byte carrier-neutral fixture at SHA-256
`bbeb061ba784f6c481420e59603b06b807d60e93ab2c493f6568f3136e3265ac`.
Its use grants no production security-profile credit.
Every byte total below counts only the common evaluator envelope. It excludes
physical, link, OS, feedback, scheduling, and repair-control overhead and is
therefore not an over-the-air byte count.

### Provisional layouts

The evaluator compares only two deliberately small, non-normative layouts:

- `compact32`: 9-byte header = one version/kind/flags byte, four-byte opaque
  transfer token, and four-byte offset;
- `wide64`: 13-byte header with an eight-byte token and four-byte offset.

Neither has an accepted collision policy, authenticated context binding,
extension registry, negotiation profile, or independent implementation.
For deterministic reproduction the evaluator derives the token from the
leftmost bytes of the full-input SHA-256 digest. That creates a linkable,
known-input-testable outer value and is **not** a production privacy mechanism.
A production profile must select an authenticated collision policy and a
randomized or blinded outer token/mapping consistent with restart and any-peer
continuation.
`compact32` reduces tiny-MTU cost but makes token-collision policy more urgent;
`wide64` materially increases the smallest-MTU cost. The arm recommends the
boundary and measurements, not either wire layout.

### MTU/overhead result for the 471-byte fixture

| Payload MTU | compact frames | compact bytes | compact header share | wide frames | wide bytes | wide header share |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 43 | 858 | 45.10% | 68 | 1,355 | 65.24% |
| 23 | 34 | 777 | 39.38% | 48 | 1,095 | 56.99% |
| 27 | 27 | 714 | 34.03% | 34 | 913 | 48.41% |
| 40 | 16 | 615 | 23.41% | 18 | 705 | 33.19% |
| 64 | 9 | 552 | 14.67% | 10 | 601 | 21.63% |
| 128 | 4 | 507 | 7.10% | 5 | 536 | 12.13% |
| 247 | 2 | 489 | 3.68% | 3 | 510 | 7.65% |
| 512+ | 1 | 480 | 1.88% | 1 | 484 | 2.69% |

The full curve covers MTUs 20, 23, 27, 40, 64, 128, 247, 512, 1280,
1500, and 2048 and formula payload sizes 16, 64, 471, 4096, 65,536,
1 MiB, and 100 MiB. The 100 MiB rows are arithmetic only and deliberately give
no Blob-streaming or bounded-RAM credit (`DM-9-13`, `DM-9-14`).

At a diagnostic decimal 3000 bit/s, the compact 471-byte transfer is 2.288
seconds of data bytes at MTU 20 before feedback/control/link overhead and 1.304
seconds at MTU 247. These timings are decision data, not a claimed useful-work
threshold.

This makes `DM-5.8-05` a real open selection criterion rather than a box to
check: 45% header at a 20-byte usable payload may or may not be practical once
authentication, repair, link headers, energy, and latency are included.

### Loss, duplication, ordering, and validation

Every deterministic 0/10/30/50% independent-loss trace converged for both
layouts at MTUs 20, 64, 247, and 1500. For compact MTU 20 at the 50% diagnostic
point, the one frozen trace took 86 transmissions, 1,716 data bytes, and five
rounds and verified the exact object. That is **one deterministic trace**, not a
statistical loss result, burst-loss model, RF result, or acceptance pass.
It also has perfect evaluator-internal knowledge of the receiver's missing set
and counts no feedback or repair-control bytes, so it is an oracle-aided
envelope lower bound rather than an implemented repair protocol.

The evaluator passed exact duplicate/reverse-order reassembly and rejected or
failed verification for digest corruption, truncated headers, unknown versions,
configured-bound violation, overlapping fragments, a late FIN that contradicted
already-buffered range, and duplicate payloads with contradictory FIN flags.
The expected digest and persisted JSON are supplied evaluator state, not
authenticated or tamper-evident, so this earns no `DM-6-02` integrity pass.
These are mechanism
checks for `DM-5.8-03`, not independent conformance.

### Restart and any-peer seam

At compact MTU 20, the first process persisted 16 of 43 unique frames and did
not verify the object. After process exit, a second process consumed 28 frames,
including a duplicate crossing the restart, and verified the exact object. The
persisted evaluator state was 3,087 bytes.

The second contact is labelled as a different sender and the state is not bound
to a process or sender, but no on-wire any-peer negotiation exists. This is a
useful seam for `DM-5.2-19` through `DM-5.2-22`, not an any-peer pass.

### One-to-many accounting

For eight receivers and compact MTU 20:

| Diagnostic loss | shared data bytes | independent-unicast data bytes | ratio | shared rounds |
|---:|---:|---:|---:|---:|
| 0% | 858 | 6,864 | 0.125 | 1 |
| 10% | 1,478 | 7,602 | 0.194 | 4 |
| 30% | 2,292 | 9,602 | 0.239 | 5 |
| 50% | 4,012 | 14,050 | 0.286 | 9 |

This isolates why one-to-many can matter. It assumes perfect
evaluator-internal knowledge of each receiver's missing set and counts no
feedback, ACK/NACK, suppression, scheduling, or repair-control bytes. It is
generic shared-send accounting, not BLE, advertising, RF, or Trickle evidence.
Implementing suppression/repair and counting its control traffic is the next
required step for `DM-5.6-04` through `DM-5.6-06`.

### Offline file/serial transcript

Three arbitrary bidirectional messages totaling 735 content bytes became 15
direction-tagged records and 915 serialized bytes. A separate process parsed
the same transcript at stream read sizes 1, 3, 7, and 64 bytes and reconstructed
all three exact messages. The 19.67% serialized overhead includes the
provisional frame and per-record headers.

This demonstrates that the carrier boundary can be byte-stream and
file-record friendly. It is not the complete selected sync protocol, removable
media workflow, serial disconnect/reconnect test, or adversarial container and
therefore does not pass `DM-5.8-15`. Willow's separately frozen three-process
Drop exercise supplies stronger bounded FOSS evidence for offline object
export/import, but likewise does not serialize a complete interactive exchange.

### Metadata exposure

The provisional frame adds only version/kind/flags, an opaque transfer token,
offset, and observable boundary/length. It does not add topic, scope, priority,
or route fields. A clear `topic/scope/priority/route` probe remained visible in
the framed capture, and all input bytes were available after normal carrier
reassembly. Length, timing, and linkability also remain visible.

“Opaque” here means the carrier assigns the token no topic/routing semantics;
it does not mean private. The evaluator's deterministic digest-prefix token is
linkable and receives no production-token or privacy credit.

Therefore the security composition must make payload and protected forwarding
metadata opaque **before** carrier fragmentation. The carrier cannot earn
`DM-6-01`, `DM-6-04`, `DM-6-09`, `DM-6-11`, `DM-6-12`, or `DM-12-10`
by being field-neutral. The provisional header's small size is decision data,
not proof that on-wire plaintext has been minimized to transport necessities.

## Smallest build-versus-buy recommendation

| Responsibility | Candidate/pilot | Residual build | Reason |
|---|---|---|---|
| Linux BLE roles, GATT, advertising, LE L2CAP | BlueR, after legal/graph admission | Thin adapter and platform policy | One component covers both roles and data surfaces |
| Future MCU BLE host | TrouBLE pilot | Controller wiring and platform qualification | Avoids inventing a BLE host; qualification is still open |
| Apple/Android/Windows BLE | Compare btleplug-central + native peripheral against one thin native symmetric adapter | Small OS glue either way | No permissible complete cross-platform symmetric wrapper survived |
| Common tiny-MTU framing/reassembly | No matching admitted component from this arm | Small common envelope with conformance tests | Must span every carrier and durable restart without duplicate state machines |
| Broadcast suppression | Trickle semantics | Missing-set/repair/control integration | Standard buys suppression, not reliable dissemination |
| Offline object file | Willow Drop pilot under Arm E limits | Complete bidirectional sync transcript and media workflow | Current Drop evidence is bounded object transfer, not a whole exchange |
| General DTN bundle semantics | BPv7 only if selected as the authoritative envelope | Otherwise none beneath sync | Avoid competing fragmentation, retry, identity, custody, and expiry state |
| Security and metadata protection | Selected security arm composition | Carrier binding only | Never delegate end-to-end security to transport |

This is the smallest observed responsibility-candidate set, not an instruction
to combine every row or an admission result. In particular, using btleplug plus
a peripheral library may cost more than
a thin native symmetric adapter because two wrappers must coordinate adapter
power, simultaneous roles, discovery, permissions, background behavior, and
connection lifecycle. A short measured spike should decide that platform by
platform.

## Required next gates

### Boundary/conformance gate

Implement two deliberately different carrier adapters—one datagram/tiny-MTU
adapter and one offline file/stream adapter—against the same proposed boundary.
Without changing the protocol fixture or durable state machine, demonstrate:

- negotiation/version rejection and ignorable extensions;
- bounded fragmentation/reassembly and crash-safe persistence;
- a complete selected sync exchange serialized offline;
- any-peer continuation using two independently provisioned senders;
- clear ownership of retry, repair, application deduplication, loop control,
  priority, expiry, and quota; and
- public APIs with no fragment or transport internals.

### BLE hardware/OS gate

Test at least Linux/BlueZ, Android, iOS/macOS, and Windows as applicable, using
exact OS versions and controller/firmware identities. For each target measure:

- simultaneous central and peripheral operation;
- advertising/scanning and manual peering, including true silent mode;
- local GATT server and remote GATT client interoperability;
- L2CAP CoC where available and exact GATT fallback behavior;
- negotiated usable payload sizes rather than configured guesses;
- partial writes, reordering, duplicates, reconnect, process restart, and
  device reboot;
- screen-off/background/suspend transitions and permission revocation;
- one-to-many behavior, actual repair/control bytes, and interference;
- idle CPU/wakeups/power, duty cycle, emissions, and sustained throughput; and
- packet capture proving no payload or protected mesh metadata is clear.

Simulation must not be promoted to hardware evidence when this gate runs.

### Broadcast gate

Replace the perfect missing-set oracle with an explicit, bounded feedback and
repair protocol. Compare per-peer unicast, unsuppressed broadcast, and
Trickle-like suppression over seeded independent and burst-loss distributions.
Count all data and control bytes, receiver work, latency, fairness, and duplicate
forwarding. Then repeat on actual media capable of one-to-many delivery.

### Offline/serial gate

Serialize every message in the selected synchronization protocol, including
both directions and continuation state. Exercise multi-file/media handoff,
duplicate import, tamper, truncation, wrong-recipient/wrong-scope content,
partial import, restart, and later continuation. For serial, add arbitrary
partial reads/writes, flow control, unplug/replug, corruption, and peer reset.

## Requirements accounting and no-credit boundary

Selected requirement atoms materially evaluated by this arm, with result and
next gate, are in
[`requirements-map.csv`](../../../../docs/evaluations/0005/requirement-maps/carrier.csv).
The arm supplies material decision data for `DM-3-04`, `DM-3-09`,
`DM-5.6-04`, `DM-5.8-03` through `DM-5.8-05`, `DM-5.8-15`, `DM-9-19`,
and `DM-9-20`; an architecture seam for `DM-3-07`, `DM-3-08`,
`DM-5.2-19` through `DM-5.2-22`, `DM-5.8-01`, `DM-5.8-02`, and
`DM-7-13`; and bounded candidate evidence for `DM-2-05`, `DM-5.6-01`,
`DM-5.6-02`, `DM-5.7-01`, `DM-5.8-11`, `DM-9-05`, and `DM-13-05`.
The license exclusions and remaining supply-chain gates are atomized under
`DM-8-03` through `DM-8-16` as applicable.

It does **not** pass physical BTLE, real broadcast, complete synchronization,
temporal relay, any-peer negotiation, security, packet-capture privacy,
cross-transport acceptance, production framing, independent interoperability,
large-Blob streaming/RAM independence, scheduler priority/expiry, loop
suppression, background operation, energy, emissions, or the BTLE deliverable.
It also supplies no authenticated integrity, tamper-evident persisted state, or
implemented public-API evidence.

## Provenance and project receipt

- Requirements authority SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
- Derived requirements matrix SHA-256:
  `57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2`.
- Harness SHA-256:
  `d503530f4d91e44a1b19f30da40c88c779f6a6c7cc11f73258bde51b35a68280`.
- Summary SHA-256:
  `0737e3d3f8c0f74100e8746a7dd3944b444a2a135af889588d8657956f2c3928`.
- Fixture SHA-256:
  `bbeb061ba784f6c481420e59603b06b807d60e93ab2c493f6568f3136e3265ac`.
- RustSec advisory database commit:
  `bf5c0d245a92671908518d7e765914d437954ed6`.
- Iroh transport raw audit SHA-256:
  `57c0296922608264ca9d302c79168313a5ea6f99caadbea80ee40e97d34f0a0a`.
- ble-peripheral-rust raw audit SHA-256:
  `99604e4cba85200bbf59a9462db6b65663de8ca631c0090ae9d3b31e097ccaca`.

Direct primary sources were preregistered as `DEP-012`, `STD-020`, `STD-021`,
`BVB-160` through `BVB-171`, `BVB-465`, `BVB-466`, `BVB-738`,
`BVB-741` through `BVB-744`, and `BVB-754`/`BVB-755` as applicable. The
four new BLE component sources and two Android API pages were registered before
direct opening. Current Aster implementation and excluded project material were
not consulted. Raw checkouts, archives, audit output, and execution products
remain local and ignored; only the lightweight harness, freeze, mapping,
summary, and this report are visible.
