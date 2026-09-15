# Candidate-neutral conformance profile seed

Status: **PARTIAL / local demo / research only**  
Authority: `data-mesh-requirements.md`, SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`  
Registered inputs: BVB-782, BVB-783, BVB-785

## Decision

Buy CBOR and CDDL mechanics. Do not invent a serialization codec, parser, or
schema language. The exact mission wire profile remains ours to specify because
none of the evaluated replication, dissemination, or carrier candidates owns
the requirements' combined item semantics, protected metadata, evolution, and
independent interoperability contract.

This arm establishes a candidate-neutral **evaluation profile v0**, not a
product protocol. It deliberately contains no Aster identifiers or compatibility
constraints. It is useful now as a stable differential corpus for candidate
compositions and later as seed material for the normative protocol conformance
suite.

## Profile shape

The outer object is deterministic CBOR with ascending integer keys. It is the
semantic object visible to an authorized mesh member. A real wire construction
must still protect topic, scope, priority, and forwarding data at the membership
layer and carry the source-protected object opaquely.

| Key | Field | Evaluation bound |
|---:|---|---|
| 0 | profile version | exactly `0` |
| 1 | item identifier | 32-byte string |
| 2 | data class | `0..3`: State, Event, Record, Blob |
| 3 | topic | 1–128 UTF-8 bytes |
| 4 | scope | 1–128 UTF-8 bytes |
| 5 | priority | `0..3`, explicitly provisional |
| 6 | TTL | unsigned seconds; orthogonal to priority |
| 7 | publisher identifier | 32-byte string |
| 8 | causal parents | at most 64 unique 32-byte identifiers |
| 9 | extensions | at most 32 `id → [critical, bytes]` entries |
| 10 | protected source object | 1–65,536 opaque bytes in this small-object profile |

The profile has no wall-clock timestamp. Unknown noncritical extension `99` is
accepted; the same extension marked critical is rejected. Unknown top-level
keys are rejected because they lack a criticality signal. The full encoded input
is capped at 128 KiB, extension values at 4 KiB, and definite-length containers
are required.

## Executed evidence

Exact locked/offline build used `minicbor 2.3.0` and independently implemented
`ciborium 0.2.2` parsing paths. Five positive and thirteen negative vectors all
matched their expected disposition in both decoders: **18/18 per decoder and
18/18 agreement**. A second execution emitted byte-identical vectors.

Positive coverage includes all four data-class tags, a Record with two causal
parents, a 4 KiB Blob chunk, and an unknown ignorable extension. Negative
coverage includes unknown critical extension, unknown class, provisional
priority overflow, required-field omission, duplicate map key, duplicate causal
parent, text and parent-count bounds, truncation, trailing data, non-minimal
integer encoding, noncanonical map order, and empty protected object.

Formatting, locked/offline test compilation, and Clippy with warnings denied all
pass. The release binary SHA-256 is
`4f629e4f2a21b2ab54318b2587b2e162c67175f438ed89a0213547b101acc2bf`.

## Requirements result

- DM-5.1-17 through DM-5.1-22 receive only field-shape evidence.
- DM-5.2-09 receives causal-parent encoding evidence; no convergence semantics.
- DM-5.2-10 receives partial field-shape evidence because the profile contains
  no wall-clock correctness field. The arm did not execute convergence or
  conflict semantics, so it cannot establish clock-independent correctness.
- DM-10-01 receives only a version field; highest-common-version negotiation is
  still unimplemented and DM-10-02 remains unknown.
- DM-10-03 passes for the one exercised noncritical extension rule.
- DM-2-07 and DM-13-08 receive a reusable seed corpus, not a finished suite.
- DM-8-18 and DM-12-11 remain **unknown**: two libraries inside one evaluator are
  not two independently spec-built implementations.

## Residual work

The normative profile must still bind cryptographic suites, membership-layer
metadata protection, source-object semantics, replay and deletion rules, class
merge behavior, sync frames, Blob manifests and resume, version negotiation,
error codes, resource limits per tier, and a deprecation policy. The release
gate remains an implementation built independently from that specification and
interoperating with the reference framework across both positive and hostile
negative cases.

## Append-only correction: profile v0-r2

The initial execution above is historical. Phase 5's independently written
Python parser later agreed on only 13 of 18 outcomes because the Rust generator
privately treated critical extension ID 1 as known and injected it into every
positive vector. Neither this prose nor the frozen CDDL defined ID 1 or any
known-extension registry. That also masked the intended reasons for the empty
protected-object, truncated, and trailing-byte negatives and made the ID 99
critical-extension attribution ambiguous.

The v0-r2 correction preserves the old corpus and creates revisioned artifacts:

- the known-extension registry is explicitly empty;
- base positives contain no extension;
- ID 99 noncritical is accepted and ID 99 critical is rejected;
- three Rust tests verify all outcomes and the reason-specific structural
  failures; and
- the unchanged independent Python parser agrees on **18/18** revised vectors.

The corrected runner passed locked/offline tests (3/3), warning-denied Clippy,
and locked/offline release build. The independent parser reports the intended
`byte_string_bound`, `truncated`, `trailing_data`, and
`unknown_critical_extension` reasons. Exact artifact identities:

| Artifact | SHA-256 |
|---|---|
| Historical v0-r1 preservation manifest | `c8a1ab948bfd719f099d2c588a99ab6c21a780524ce919ac7d73c2fb30e3e6e0` |
| Revised runner source | `a7ac74d7a06204bae7baab4d428f596169923de8d459825d6456f577f3217c24` |
| Revised profile CDDL | `349d6be07bdf710c42c28f93d4d7f88254c3009fad0607ecb28eab75eda337d9` |
| Release runner | `97fa31820d65923370a6feb36a78ed02d8230e557f1465e4afb0c79301d88d27` |
| Rust summary | `d440ff3c32275e586264f26c9a3f6fc389dfb10e7e9c51f514e606da39533c88` |
| Independent result | `c0081c730e3d71302a8af0a4b24fa9b1240ea2bfd1b71f3dc77a0e13568e85f2` |
| Unchanged independent parser | `c482e60218eae7de42c6823f0aeca15c5c669470e8307501b1dc5f9652eafe63` |
| 25-entry v0-r2 manifest | `dfb4c5584123f52178ae19becf55b288a68c3c75bcd2c49967a5d1f151afaa96` |

This repair closes the evaluator's hidden-extension discrepancy only. The
profile is still explicitly non-product, its CDDL is not a complete normative
specification, and the Python oracle is not a second full implementation.
DM-8-18 and DM-12-11 therefore remain open release gates.
