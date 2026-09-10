# Aster hostile-input fuzzing

This is an isolated test workspace. It is not a release dependency and does not
change the protocol or application API. The pinned nightly is used only because
`cargo-fuzz` requires unstable compiler instrumentation.

Install the exact tool and run bounded smoke campaigns:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
mise run fuzz-smoke
```

The task selects `nightly-2026-08-18` explicitly and runs all targets from the
isolated `fuzz/` workspace. `wire_decode`, `fragment_decode`, and
`selected_frame_decode` require accepted input bytes to equal their deterministic
canonical encoding. The selected-frame target reaches the exact production
decoder through an opt-in, doc-hidden fuzz seam that is absent from normal
`aster-node` builds; each case exercises both the raw hostile input and one
structured candidate distributed across all 30 current mechanics-frame variants,
including both protected Event-interest variants and the object-class-distinct
Event and Flash control lanes.
`selected_negentropy` drives both arbitrary hostile frames and valid stateful
exchanges while asserting the selected wrapper's byte, cardinality, and round
limits. These mechanics-only targets earn no mission semantics or security
credit.

`envelope_inspect` uses only the public `adapter-sdk` provisioning and
reference-envelope APIs. It tests arbitrary hostile bytes and structured
mutations of a freshly sealed valid envelope carrying exactly 4,096 causal
predecessors. Its retained `M` seed is a nonsecret mutation recipe; credentials
and generated envelope bytes are never written to the retained corpus.

`classical_profile_decode` uses the public profile-`0x0002` APIs to exercise
exact provisioning dispatch, source Event route/content verification, and
first-flight mission parsing. Its retained `B`, `E`, and `H` files are nonsecret
mutation recipes; canonical credentials, envelopes, and handshake bytes are
created in memory and are not retained in the corpus.

`systemd_credential_decode` reaches the exact D06 provider-envelope decoder
through a doc-hidden fuzz seam that is absent from normal provider builds. It
tests arbitrary hostile bytes and structured mutations of a valid envelope;
the retained `M` file is only a nonsecret mutation recipe, while the reference,
operation identity, and non-production provisioning bytes are created in
memory.

`systemd_admin_record_decode` reaches both D06 durable-state decoders through a
doc-hidden fuzz seam that is absent from normal provider builds. Every case
tests arbitrary hostile bytes plus structured mutations of valid ledger and
generation-manifest records assembled in memory from nonsecret fixed values.

Each smoke campaign runs 10,000 cases with a fixed seed and a 262,144-byte
maximum input. Retained corpora are copied to a temporary directory before each
campaign, so libFuzzer cannot mutate the checked-in seed corpus. Targets without
a retained corpus start from an empty temporary directory. The root release
workspace excludes this package, so neither libFuzzer nor its compiler
instrumentation enters shipped artifacts.

Release assurance should run longer campaigns on Linux and macOS, retain each
minimized crashing input and seed corpus, and record toolchain, target, command,
elapsed time, corpus hash, and result in the release test report.
