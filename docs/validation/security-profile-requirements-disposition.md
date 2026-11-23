# Security-profile requirements disposition


- Status: accepted applicability overlay; initial classical evaluation implementation present; release gates open
- Date: 2026-08-28
- Decision authority:
  [Decision 0033](../decisions/0033-policy-selected-security-profiles.md)
- Preserved requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Preserved atomic-matrix SHA-256:
  `57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2`

## Purpose and precedence

The hash-bound requirements and atomic matrix remain unchanged as provenance
and historical product intent. The source was a draft, and atomization was not
stakeholder ratification. The capability roadmap permits a reviewed decision
to affirm, revise, defer, or reject a row without rewriting that baseline.

This record supplies that reviewed applicability for metadata protection and
post-quantum cryptography. Where the baseline's universal wording conflicts
with this record, this disposition controls current planning, profile design,
and release review. It does not erase the original text or manufacture
implementation evidence.

## Binding interpretation

| Requirement IDs | Current disposition |
|---|---|
| `DM-6-01` | Transport-independent confidentiality remains mandatory for source payload/content and persistent protected objects. Ephemeral contact metadata may instead rely on the declared authenticated encrypted carrier profile. |
| `DM-6-02`, `DM-6-03` | Source/control integrity and authenticity remain independent of the carrier. Mission authority derives from an Aster credential/proof, not carrier identity; the proof may be channel-bound and carried under carrier AEAD, and subsequent adjacency-frame integrity/authenticity may be carrier-native. Offline/file exchange binds equivalent authority to its exact serialized context. These rows receive a policy disposition but no evidence or status change. |
| `DM-6-04` through `DM-6-08`, `DM-11-21` | Unchanged hard requirements: source encryption, source authentication, verification at consumption, payload-blind relay/bridge behavior, and MVP payload end-to-end cryptography. |
| `DM-6-09`, `DM-6-11`, `DM-11-22` | Universal zero-plaintext/outsider-opacity is replaced by best-effort protection within a declared profile. Use carrier protection when available, protect persistent metadata independently where practical, minimize exposure, and document every permitted field and observer. A second mesh encryption layer is not universally required. |
| `DM-6-10` | Unchanged: an authenticated and authorized forwarding participant receives the protected forwarding fields needed for its role. This does not require disclosure to every member or authorize payload access. |
| `DM-6-12` | Unchanged hard guardrail: minimize plaintext to the exact necessities of each declared carrier/profile and verify the exposure. |
| `DM-6-24`, `DM-6-27`, `DM-6-28` | Existing NIST/FIPS algorithm and module obligations remain applicable to the exact algorithms and release profile selected. |
| `DM-6-25`, `DM-6-26` | The product must support a complete hybrid classical/post-quantum profile; hybrid key establishment and signatures are not mandatory on every contact or object. Mission policy decides whether hybrid-PQ is permitted or required. |
| `DM-6-29`, `DM-6-30` | Unchanged hard guardrails, now applied to complete security-profile selection: bind offers, selection, and the policy minimum; fail on stripping, mismatch, unsupported required PQ, failure-triggered fallback, or unauthorized rollback. |
| `DM-6-31` through `DM-6-34` | Amortization remains optional. Whenever a profile amortizes cryptographic work, end-to-end authenticity, end-to-end encryption, and the evaluated link-rate overhead obligation remain mandatory. |
| `DM-12-10` | Packet capture must reveal no payload plaintext and no metadata beyond the declared profile's exposure budget. It is not an absolute zero-metadata requirement across every carrier. |
| `DM-14-23` | Validated-module availability for the hybrid-PQ composition is a gate only for production profiles that select, permit, or require that hybrid composition. It is not a gate for a profile that excludes PQ. |

## Metadata classes

| Metadata class | Protection policy |
|---|---|
| Source-stable or store-and-forward metadata | Protect independently when required for durable payload-blind custody and where practical; expose only the fields an authorized forwarding role needs. |
| Ephemeral contact and synchronization metadata | Protect through the admitted carrier channel or an Aster adjacency layer; explicit policy may permit a minimized exposure. |
| Persistent local indexes and operational metadata | Minimize and protect through storage, key-custody, and platform controls where practical; do not claim universal at-rest encryption without evidence. |
| Carrier-observable data | Declare endpoint, address, timing, direction, size, and RF-energy leakage unless a named mechanism demonstrably hides it. |

## Current implementation versus target policy

| Boundary | Current selected lane | Target direction |
|---|---|---|
| Mission contact | The stock selected lane uses Iroh endpoint authentication followed by hybrid profile `0x0001`, four-flight `ASTRHS01`, and `ASTRFR01`. An additive two-node profile-`0x0002` path uses a distinct Iroh ALPN, exact TLS exporter binding, P-256 mission authorization, and raw QUIC application frames. | Integrate authenticated profile selection into a named runtime/release profile and retain representative downgrade/resource evidence. |
| Source objects | Profile `0x0001` retains fixed hybrid forms. Profile `0x0002` adds separately encrypted/P-256-authenticated semantic-v1 Events and controls under exact suite identifiers; other data classes and advanced forms reject. | Preserve exact-suite objects without conversion and broaden only through separately specified profile forms. |
| PQ use | Mandatory inside profile `0x0001`; omitted by the explicitly provisioned profile-`0x0002` runtime path. Combined builds still retain hybrid code and PQ dependencies. | Required hybrid policies fail closed; measure and package each selected release profile without treating classical operation as fallback. |
| Metadata | Profile `0x0002` protects ephemeral frame bytes with QUIC, source routing fields with an independent wrapper, and source content independently, while declaring public envelope, local-index, carrier, timing, direction, size, relay, and RF exposure. | Retain packet-capture and local-at-rest evidence against each declared profile budget. |

The additive profile-`0x0002` implementation now supplies new exact wire forms,
same-implementation mismatch/fallback tests, and a local durable
profile-generation binding. It does not change the stock selected runtime,
generated atomic status, retained evidence credit, or release authorization.
Representative resource/energy, packet-capture, physical snapshot rollback,
mixed-implementation, and operational lifecycle results remain open.
