# Automerge 0.11.0 Record-CRDT component arm


## Result

Automerge is a credible FOSS buy for an opt-in, JSON-like Record merge policy.
The exact 0.11.0 Rust crate preserved two disconnected scalar edits, exposed
both conflicting values, converged symmetrically, retained nonconflicting
fields, made duplicate merge harmless, accepted one deterministic
application-selected resolution, survived complete process reload, and rejected
a corrupted serialized document.

It is not the generic mission Record envelope and it is not a mesh. The final
profile still needs a small wrapper that maps multiple Automerge values into an
application-visible conflict annotation and retains generic siblings for Record
types without a registered Automerge policy. Automerge's per-document sync
mechanism assumes a reliable ordered exchange with per-peer sync state; it does
not replace temporal dissemination, carrier sessions, or whole-dataset
anti-entropy.

## Exact freeze

| Surface | Freeze |
|---|---|
| Component | `automerge` 0.11.0, MIT, archive SHA-256 `c1b59cbd9e7685a1ac6bf6046ddcd8acb550fa5bf03c09f6c1056728a742b40d` (BVB-740) |
| Graph | manifest `6aa5b4d65bdd9a1f5ae40a151cab72d2fd591108ceef297921afcb06bc413015`; lock `1abe24aa3b0ab3c7d6ab6cd237550a4800d84c0e43ee26c547da7b6afe68774e`; 50 packages: 49 registry and one local, zero git (BVB-745) |
| Comparator | final source `b3fef072491a55f9ba9ab2f444d71792a38b5ad025768ce0e1095da4358ea871`; driver `636d50be45c1a8fac61bd189d583de1acf747ea2adab3ef6e0b439b9548b8f9f` (BVB-752) |
| Binary | aarch64-apple-darwin release SHA-256 `b6b94d993b0c87a3a369a541db01526bdf6e884b794040d047884bc2187bbe70`; 2,088,032 bytes |
| Advisory scan | frozen RustSec commit `bf5c0d245a92671908518d7e765914d437954ed6`, 1,225 advisories; zero full-lock vulnerability findings or warnings |

The root license and exact graph are research evidence, not complete production
admission. Target coverage, complete transitive license review, governance,
security response, reachability, and resource bounds remain open.

## Executed corpus

Run `record-002` used five distinct invocations and serialized files:

1. `seed` created the common `record-001` base with title `base`.
2. `edit-a` reloaded the base under actor A, wrote title `alpha`, and added an
   A-only field.
3. `edit-b` independently reloaded the same base under actor B, wrote title
   `bravo`, and added a B-only field.
4. `merge` merged in both directions. Both documents exposed exactly the two
   title siblings `alpha` and `bravo`, retained both unique fields, and had
   identical heads. Repeating the same merge changed no heads. A deterministic
   resolver sorted the siblings, wrote `resolved:alpha+bravo` under the same
   resolver actor and causal frontier, and produced identical resolved heads.
5. `verify` loaded both resolved documents in a new process, confirmed the
   same resolution and heads, and rejected a document with a corrupted first
   byte.

The two resolved serializations were 322 and 321 bytes despite identical heads
and semantics. Canonical byte identity is therefore not claimed or required by
this result. The base was 150 bytes and each branch was 216 bytes. These are
single-document observations, not size curves.

## Requirements classification

| Requirement surface | Result | Boundary |
|---|---|---|
| DM-5.1-08/09 mutable Record and disconnected concurrency | met, bounded | one document, one concurrent scalar plus two nonconflicting fields |
| DM-5.2-09 causal distinction | met, bounded | shared causal base plus distinct actors produced two concurrent siblings |
| DM-5.2-10/14 clock-independent conflict behavior | met, bounded | no wall clock participated in merge or resolution |
| DM-5.2-07/08 duplicate and idempotent effect | partial | repeated document merge was idempotent; application delivery was not exercised |
| DM-5.3-05 registered merge policy | partial | Automerge merges its supported JSON-like operations; scalar conflict used an explicit deterministic resolver |
| DM-5.3-06/09 sibling preservation and no silent loss | met, bounded | both scalar values were exposed by `get_all` after both merge directions |
| DM-5.3-07/08 conflict annotation/API | partial | conflict values are exposed, but the mission annotation type and high-level API wrapper remain ours |
| DM-5.3-10 superseded recovery | partial | causal history is serialized; policy-bound retention and application recovery API were not tested |
| DM-5.3-11/12 application merge registration/determinism | met, bounded | identical sibling set and resolver actor produced identical resolved heads |
| DM-12-04 disconnected Record acceptance | partial | preservation and deterministic resolution passed locally; no mesh carrier or independent implementation |

## Responsibility decision

Buy Automerge only where a topic/class explicitly registers its JSON-like
merge policy. Let Automerge own causal document operations and merge for those
records. Keep one generic immutable version/sibling envelope outside it so an
unknown or non-Automerge Record still preserves every conflicting version and
surfaces an annotation. This avoids forcing every Record payload into one CRDT
while deleting the hardest custom merge machinery for suitable documents.

Do not let Automerge own State, Event, Blob, propagation, retry, delivery,
security, membership, or carrier state. If its sync protocol is later used, it
must justify a distinct durable progress owner rather than duplicating the
selected replica/dissemination layer.

## No-credit boundaries

No result proves large or deeply nested documents, many actors, long histories,
compaction and garbage collection, hostile cardinality/allocation bounds,
document-sync interruption, network reordering, independent interoperability,
RAM/CPU/storage amplification, production licensing/governance, or any
non-Record mesh requirement. Raw archives, build output, serialized documents,
and logs remain locally preserved and ignored.
