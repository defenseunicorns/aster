# p2panda v0.7.1 executable candidate freeze

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

>
> Requirements-first research evidence only. This freeze neither admits a
> dependency nor selects an architecture. Existing Aster implementation and API
> boundaries had no input or compatibility weight.

- Evaluation date: 2026-08-22
- Requirements authority: `data-mesh-requirements.md` version 0.1
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Candidate: p2panda `v0.7.1`
- Overall result: **partial**
- Production admission: **not admitted**
- Forbidden or excluded material encountered: **no**

## Outcome first

The candidate-native high-level API passed the smallest useful local-first
sequence on the evaluation host:

1. one Event-like string was published and processed locally with no peers,
   mDNS disabled, and no relay or bootstrap configured;
2. that process exited;
3. a separate process reopened the same SQLite database and signing identity and
   replayed the exact operation; and
4. a fresh in-memory peer discovered it over local mDNS and received the same
   operation ID, author, and payload through direct synchronization with no relay
   or bootstrap.

This is executable credit for bounded offline publish, restart persistence,
later local synchronization, LAN discovery, and relay-independent local
operation. It is not credit for the final mesh, four-class model, temporal relay,
fault recovery, security profile, BTLE/NAT coverage, FFI, bindings, or independent
interoperability.

## Source and release freeze

Only the requirements, newly produced work, and these registered public sources
informed this evaluation:

| ID | Registered source | Use in this freeze |
|---|---|---|
| BVB-177 | Official p2panda repository | Exact tag source and candidate-native API |
| BVB-178 | Official `p2panda-sync` documentation | Previously registered sync surface; no executable credit |
| BVB-179 | Official sync-protocol documentation | Previously registered protocol surface; no executable credit |
| BVB-619 | Official high-level/network/discovery documentation | Previously registered architectural screening only |
| BVB-644 | Official p2panda release page | Release identity |
| BVB-645 | Official Spaces API page | Retained prior no-content result; no claim used |
| BVB-332 | Official crates.io sparse index | Index-only lock resolution |
| BVB-696 | Exact pre-access p2panda runner graph | Authorized acquisition of the frozen registry archives |

Release identity:

| Field | Frozen value |
|---|---|
| Tag | `v0.7.1` |
| Full commit | `083b48215964e92a564f3c83a1c607b00e94aa64` |
| Commit author/committer time | `2026-08-21T12:58:46+02:00` |
| Commit subject | `v0.7.1` |
| Tag object | Lightweight tag: `git cat-file -t v0.7.1` returned `commit`; no annotated or signed tag object was available |
| Official tag archive | `p2panda-v0.7.1.tar.gz` |
| Archive SHA-256 | `1f0f25be7c209d4042b0e84ad07d1e089951f1780762fe8696e27c8524376db4` |
| Upstream release lock | None: the tag contains no `Cargo.lock` |
| Upstream package license | `MIT OR Apache-2.0` |
| Apache-2.0 text SHA-256 | `49d293a231c8951dcc973e6fc3ce3e4365ea4e1d9b0b9ad0e6730b66c26be6bd` |
| MIT text SHA-256 | `517c475e603ff7e67852c1f5b4c01721c546f3d3f96386b6f5e048233543cc5a` |
| Declared Rust floor | `1.96` for the selected p2panda crates |

The GitHub-generated archive digest is the retrieval identity for this freeze;
the full Git commit is the source identity. The local clone and archive are
retained under the isolated candidate directory but ignored from repository
tracking.

## Composition and dependency lock

The evaluator created a standalone runner around the unmodified high-level
`p2panda` path package. The runner does not import product crates.

| Field | Value |
|---|---|
| Runner manifest | `Cargo.toml` (archived) |
| Runner manifest SHA-256 | `3ce3dcb3c59cfb67a11df44360f7cca81385f80457b66957fc0d9b9cb97e38da` |
| Runner source SHA-256 | `4de9b561d0a24d6ff0b93926aeed9560c953c0508cba9a537e870baf2ccea971` |
| Generated lock SHA-256 | `7b901b0142329b28f5912f90a5884401a4a616043aaab05e6cfb085eb18c3652` |
| Lock packages | 533 total: 522 crates.io registry, 11 path, 0 git |
| Build command | `cargo build --locked --offline` |
| Build host | `aarch64-apple-darwin` |
| Compiler | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Final debug binary SHA-256 | `6928a660724ab2b98f16e5aaf405aaf69d7173e1488a991e7f9c40e0615b75cd` |
| Build result | Pass; lock digest unchanged |

The 11 path packages are the runner plus ten p2panda `0.7.1` crates. Exact
activated p2panda feature surface:

| Crate | Activated features |
|---|---|
| `p2panda` | none on the crate itself; its manifest explicitly enables defaults on internal dependencies |
| `p2panda-core` | `default` |
| `p2panda-net` | `address_book`, `default`, `discovery`, `gossip`, `iroh_endpoint`, `iroh_mdns`, `sync` |
| `p2panda-discovery` | `default`, `random_walk` |
| `p2panda-store` | `default`, `encryption`, `groups`, `macros`, `spaces`, `sqlite` |
| `p2panda-stream` | `default`, `groups`, `ingest`, `log_prune`, `orderer`, `p2panda-auth`, `p2panda-spaces`, `spaces` |
| `p2panda-sync` | `default` |
| `p2panda-auth` | `serde` |
| `p2panda-encryption` | `data_scheme`, `default` |
| `p2panda-spaces` | none |

`p2panda-blobs` is not in the selected graph. This run therefore provides no
Blob evidence. The high-level default composition pulls auth, encryption, and
Spaces packages into the graph, but their presence is not proof that the tested
string stream applied the requirements security profile.

## License, SBOM, and advisory surface

The p2panda path crates are dual licensed `MIT OR Apache-2.0`; Apache-2.0 is a
permitted selectable option for this evaluation. The runner is also declared
`MIT OR Apache-2.0` and is not published.

- Feature-aware `cargo-deny 0.20.2` gathered 494 crates without a target filter.
  Bans, licenses, and sources passed with zero errors; two configured allow-list
  entries were unused warnings. No strong-copyleft, proprietary, or git source
  was accepted by that check.
- The Apple ARM host graph contained 368 packages and likewise passed bans,
  licenses, sources, and advisories under upstream policy.
- CycloneDX 1.5 generation with `cargo-cyclonedx 0.5.9` produced 393 dependency
  components plus the runner root; SBOM SHA-256 is
  `2c1c59e122c5143e26febadc4253f281d0892451a0c9898164795d3c4031dac4`.
- SBOM generation reported 15 legacy slash-form license strings such as
  `MIT/Apache-2.0` as named licenses. The independent cargo-deny content check
  still passed. These warnings prevent representing SBOM generation alone as a
  complete license disposition.

The exact lock has a materially qualified security result:

1. `cargo-audit 0.22.2 --no-fetch` against RustSec snapshot commit
   `bf5c0d245a92671908518d7e765914d437954ed6` (1,225 advisories) failed the
   full lock scan for `RUSTSEC-2023-0071` on `rsa 0.9.10`.
2. `rsa 0.9.10` is retained in the lock through inactive optional
   `sqlx-mysql`; it is absent from the selected feature-aware build graph. This
   is a lock-level finding, not evidence that RSA code was linked into the
   runner. It still makes an unqualified “audit clean” claim false.
3. The feature-aware graph reaches two unmaintained packages that upstream
   explicitly ignores as informational in `deny.toml`:
   `RUSTSEC-2024-0436` (`paste 1.0.15`, through Iroh/netwatch on applicable
   targets) and `RUSTSEC-2026-0173` (`proc-macro-error2 2.0.1`, through
   HPKE/libcrux macros). Neither has a safe upgrade in the scanned advisory
   snapshot.
4. The tag contains no `SECURITY.md` or other repository vulnerability-reporting
   policy file. CI definitions do run tests, check, formatting, Clippy,
   feature-power-set checks, and a scheduled cargo-deny job, but those source
   definitions were not rerun as an upstream release pipeline.
5. The selected source contains one explicit `unsafe` block in
   `p2panda-core` for zero-initializing a type asserted to be zero-sized. This is
   a narrow reviewed surface observation, not a whole-graph unsafe audit.
6. Upstream's own `p2panda-encryption` README says the crate has not received a
   security audit, does not recommend it for high-risk use when devices and
   transports cannot be controlled, states that group control messages are
   unencrypted, and states it is not post-quantum secure.

Consequently, this freeze gives **no requirements security credit** and does
not satisfy the dependency-security admission gate. It also does not test FIPS,
hybrid PQ, source payload encryption, protected mesh metadata, revocation,
rekey, or zeroization.

## Executable experiment

The final evidence is `run-004`. It used a fixed public test signing key, fixed
topic and network IDs, and payload `offline-before-restart-v0.7.1`. These are
fixtures, not credentials.

Commands, from the runner directory:

```text
cargo build --locked --offline
mkdir -p runs/run-004/state
target/debug/p2panda-freeze-runner offline-publish runs/run-004/state/peer-a.sqlite
target/debug/p2panda-freeze-runner restart-two-peer-sync runs/run-004/state/peer-a.sqlite
```

The commands were separate operating-system processes. Final observations:

| Observation | Value |
|---|---|
| Offline phase connectivity | no peers; mDNS disabled; relay and bootstrap unset |
| Offline publish | pass |
| Durable replay after restart | pass |
| Topic | `4242424242424242424242424242424242424242424242424242424242424242` |
| Publisher/restarted node | `d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737` |
| Fresh peer | `a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0` |
| Operation before and after restart/sync | `6d4be307552dc5cccd23489d5375a4bbe5ddbbcbbc25362cf97222565acf1428` |
| Sync-start metrics at fresh peer | 1 incoming operation, 217 incoming bytes, 0 outgoing operations/bytes |
| Fresh-peer content match | operation ID, authenticated author field, and payload matched |
| Relay/bootstrap | unset throughout |
| Final sync-phase elapsed time | 2,070 ms |
| Offline log SHA-256 | `b91c1bcffc5003d04102b22200504eff1b8fa612e531abb9861fa79ae276b426` |
| Restart/sync log SHA-256 | `e33748aa49977c610fe0554e535a38cfd65412d3eeb9f0fee2104e4ded463a09` |

An initial sandboxed attempt (`run-001`) could not start the candidate gossip
actor because local networking was restricted. It is retained as an
environment-blocked attempt and receives no candidate result. `run-002` passed
the sequence but used an imprecise output label for the no-peer phase; it is
retained and superseded by the corrected `run-003`. No earlier evidence was
deleted or rewritten. `run-003` passed the corrected sequence before final source
formatting; it is retained and superseded by the byte-frozen `run-004` binary.

## Requirement-cell result

“Met” below means only that the named candidate mechanism met this bounded
scenario. It is not a final-stack acceptance claim.

| Requirement | Result | Executable boundary |
|---|---|---|
| DM-7-16 offline publish success | **met** | One Event-like string processed locally with no peers |
| DM-7-17 later synchronization | **met** | Same durable operation synchronized after a separate-process restart |
| DM-1-05 disconnected reconciliation | **partial** | Short controlled disconnection/restart only |
| DM-5.2-02 reachable-subscriber convergence | **partial** | One peer and one operation; no scope or fault sweep |
| DM-5.2-03 offline resynchronization | **partial** | Immediate restart, not the provisional extended interval |
| DM-5.2-04 durable-data preservation | **partial** | One operation; TTL and eviction were not varied |
| DM-5.6-01 direct peer sync | **partial** | Two identical p2panda nodes over local IP; no independent implementation |
| DM-5.6-02 infrastructure-free direct sync | **met** | No server, relay, or bootstrap |
| DM-5.7-01 automatic discovery | **met** | Local mDNS only |
| DM-5.8-10 local operation without relay | **met** | Direct local synchronization completed without relay |

No credit is assigned for at-least-once behavior merely because one operation
arrived, for difference proportionality merely because the sync reported 217
bytes, or for security merely because an author field survived processing.
Those properties need adversarial or comparative execution.

## Explicitly not run

- forced crash, kill-point, torn-write, and corrupted-store recovery;
- partition/reconnect sweeps and the provisional extended offline interval;
- causal forks, State tie-breaks, Record conflict preservation, or merge policy;
- difference-proportional cost, duplicate delivery, idempotence, and gap tests;
- resumable partial sync, persistent progress, and any-peer continuation;
- pruning, tombstone retention, replay, TTL, priority, quota, eviction, and
  emission policy;
- Blob chunking, content addressing, deduplication, and resume;
- intermediate temporal relay, multi-hop store-and-forward, loops, and
  one-to-many broadcast;
- scopes, bridge filters, nested scopes, and relay read-access restrictions;
- BTLE, NAT topologies, relay fallback, transport changes, and smallest-MTU
  framing;
- packet capture, source payload encryption, metadata protection, mutual-auth
  downgrade, replay attack, revocation, rekey, zeroization, PQ hybrid, and FIPS;
- C ABI, bindings, agent/IPC, binary/RAM/CPU/power bounds, protocol specification,
  second implementation, and conformance.

Upstream documentation and source comments may identify intended mechanisms for
some of these areas, but documentation is not executable credit.

## Disposition

Keep p2panda as a primary **research arm** for the narrow high-level local-first
mechanism. The run materially establishes that v0.7.1 can persist an offline
publish across restart and later synchronize it to a fresh local peer without a
relay. It does not establish a requirements-complete data mesh, and the security,
advisory, release-signing, exact-policy, and untested capability gaps block
production admission.

Lightweight reproducible artifacts are retained in
archived `p2panda` (archived).
The candidate `summary.json` is explicitly non-normalized and non-selection
evidence; the shared schema envelope and mutable control/source-register hashes
are left to final evaluation normalization after post-run receipts are appended.
Raw source, archive, binary, SBOM, audits, run logs, and SQLite state remain
locally preserved under that isolated candidate root and are intentionally
gitignored.
