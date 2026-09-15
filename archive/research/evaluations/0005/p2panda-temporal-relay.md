# p2panda v0.7.1 three-node temporal-relay experiment

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

>
> Requirements-first research evidence only. This experiment does not admit or
> select p2panda, does not import product code, and does not grant credit to
> unexecuted documentation.

- Evaluation date: 2026-08-22 (America/Chicago)
- Requirements authority: `data-mesh-requirements.md` version 0.1
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Candidate: p2panda `v0.7.1`
- Frozen commit: `083b48215964e92a564f3c83a1c607b00e94aa64`
- Core run: `temporal-003`
- Overall result: **partial**
- Production admission: **not admitted**
- Web access or new source consultation: **none**
- Forbidden or excluded material encountered: **no**

## Outcome first

The candidate-native p2panda API passed the bounded functional temporal chain:

1. A published one operation before B joined and while C did not exist.
2. A and fresh B synchronized directly over the local IP carrier. B's processed
   event named A as the sync-session remote and retained A as the operation
   author.
3. Both A and B processes exited. The outer driver reaped them and verified that
   neither PID remained.
4. A new B process reopened the identical B SQLite path with the identical B
   signing identity. Before C started, B replayed exactly one operation from
   `Source::LocalStore`, matching the original topic, operation ID, A author, and
   payload bytes.
5. Fresh C then started while A remained absent. C's processed event named B as
   the sync-session remote while the operation author remained A. C received the
   identical topic, operation ID, and 65 payload bytes.

This is bounded executable credit for DM-5.6-03: one full p2panda replica carried
one replicated operation across sequential A-B and B-C contacts with a real B
process restart. It is not proof of a general DTN routing layer, arbitrary
multi-hop behavior, or a distinct payload-blind relay role.

The security half failed. B's application event exposed the plaintext payload,
and the exact fixed canary occurred in B's SQLite WAL both after phase one and in
the post-core snapshot. DM-6-07 is therefore **not met**, DM-12-05 is only
**partial**, and this run grants **no security credit**.

## Frozen composition and preservation

The experiment reused the already frozen v0.7.1 source, package graph, and lock.
No dependency was added or updated.

| Field | Exact value |
|---|---|
| Runner manifest | `Cargo.toml` (archived) |
| Manifest SHA-256 | `3ce3dcb3c59cfb67a11df44360f7cca81385f80457b66957fc0d9b9cb97e38da` |
| Frozen lock SHA-256 | `7b901b0142329b28f5912f90a5884401a4a616043aaab05e6cfb085eb18c3652` |
| Lock graph | 533 packages: 522 registry, 11 path, 0 git |
| Temporal source | `runner/src/bin/p2panda-temporal-relay.rs` |
| Temporal source SHA-256 | `91946254694d66801c1b7f2a93e2e547188151b5de0055e39e1952671e9bc314` |
| Temporal debug binary SHA-256 | `aa363a096484b80a7c57345fe4165023e41bcddddecf02dc05e9a4687fb99ea2` |
| Temporal target directory | `runner/artifacts/temporal-target` (ignored raw evidence) |
| Format/check/test | Pass; Clippy passed with warnings denied; harness has zero unit tests |

The temporal harness is a separate Cargo auto-discovered binary. It did not edit
the original direct-run source, lock, or manifest and was built into a separate
target directory. Direct run-004 preservation checks:

| Preserved direct artifact | SHA-256 |
|---|---|
| `runner/src/main.rs` | `4de9b561d0a24d6ff0b93926aeed9560c953c0508cba9a537e870baf2ccea971` |
| `runner/receipts/direct-run-004-main.rs` | `4de9b561d0a24d6ff0b93926aeed9560c953c0508cba9a537e870baf2ccea971` |
| `runner/target/debug/p2panda-freeze-runner` | `6928a660724ab2b98f16e5aaf405aaf69d7173e1488a991e7f9c40e0615b75cd` |

The old source receipt was established before temporal work. Run-004 logs and
database evidence were neither removed nor overwritten.

## Harness assertions

Three fixed public test-only signing keys produce three distinct node identities.
They are fixtures, not credentials. All nodes use one fixed topic and network ID,
no relay URL, and no bootstrap node. Each node has a disjoint SQLite path.

The decisive checks do not infer causality from adjacent metrics:

- B phase one requires `Source::SyncSession` with remote exactly A and phase
  `Sync`; it then verifies the processed topic, operation ID, verified author A,
  successful processing state, and exact payload bytes.
- Restarted B requires a one-operation replay bracketed by `ReplayStarted` and
  `ReplayEnded`; the operation source must be `Source::LocalStore`.
- C requires `Source::SyncSession` with remote exactly B while the operation's
  verified author remains A. The distinction between network sender B and
  operation author A rules out B merely publishing a copy.
- Each network leg requires both the processed operation and a successful
  same-session `SyncEnded`; `SyncStarted` alone receives no transfer credit.
- Unexpected peers, source kinds, topics, authors, IDs, payload bytes, replay
  ordering, processing failures, decode failures, acknowledgement failures, and
  failed sync sessions are fatal to that invocation.

## Exact commands

Build, from `runner` (archived):

```text
CARGO_TARGET_DIR=artifacts/temporal-target cargo build --locked --offline --bin p2panda-temporal-relay
```

The successful core used these exact resolved binary invocations. A and B1 ran
as separate child processes in the first approved outer driver. Only after both
were reaped did a second outer driver start B2 and then C.

```text
artifacts/temporal-target/debug/p2panda-temporal-relay a-publish runs/temporal-003/state/a.sqlite
artifacts/temporal-target/debug/p2panda-temporal-relay b-store runs/temporal-003/state/b.sqlite b1498bbdc252eeff0b8d0754f7d5dc996580c3594b4cee30b5795b165140ae84
artifacts/temporal-target/debug/p2panda-temporal-relay b-relay runs/temporal-003/state/b.sqlite b1498bbdc252eeff0b8d0754f7d5dc996580c3594b4cee30b5795b165140ae84
artifacts/temporal-target/debug/p2panda-temporal-relay c-receive runs/temporal-003/state/c.sqlite b1498bbdc252eeff0b8d0754f7d5dc996580c3594b4cee30b5795b165140ae84
```

The outer driver waited for A's flushed `READY` line before resolving the dynamic
operation ID and starting B1. It waited for B2's flushed, post-`ReplayEnded`
`READY` line before starting C. The exact resolved command list is retained at
`runner/runs/temporal-003/meta/commands.log`, SHA-256
`7dc749dc7858ab7f52ba894cdff260ce47df3c83c3dd3d84de07d46e93cec3ed`.

The fixed plaintext canary was scanned with `rg` in text-forced, fixed-string,
match-only mode. Phase-one targets were B's SQLite/WAL/SHM plus A and B1 output;
the post-restart targets were the frozen post-core B snapshot plus B2 and C
output. The commands intentionally emitted only the matching canary with its
file and line, not arbitrary binary database contents.

## Identities and content

| Observation | Exact value |
|---|---|
| A node and operation author | `bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5` |
| B node before and after restart | `55154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207` |
| C node | `d404bc44565aedbb899150e5b0b3b32b9441bf0cb7884c33130da8dbc27dd2cf` |
| Topic | `7474747474747474747474747474747474747474747474747474747474747474` |
| Operation ID at A, B1, B2 replay, and C | `b1498bbdc252eeff0b8d0754f7d5dc996580c3594b4cee30b5795b165140ae84` |
| Payload bytes | 65 |
| Payload SHA-256 | `f2211f0bc2f669ba67867016748bc12041344feb9e11c522ab27dc089d7e83bb` |
| A-to-B transfer | 1 operation, 253 bytes |
| B-to-C transfer | 1 operation, 253 bytes |
| Relay/bootstrap | unset throughout |

B was the sync source observed by C, but A remained the verified operation
author. No database was shared or copied into C; C received through its p2panda
stream subscription into its own initially fresh SQLite path.

## Process and contact non-overlap

Harness millisecond timestamps and the approved outer driver's UTC timeline show:

| Event | Value |
|---|---|
| A PID / start / local publish / finish | 42330 / `1787446533311` / `1787446533344` / `1787446577453` |
| B1 PID / start / finish | 42413 / `1787446533377` / `1787446577455` |
| B2 PID / start / durable replay / finish | 43168 / `1787446623706` / `1787446623725` / `1787446659721` |
| C PID / start / finish | 43176 / `1787446623779` / `1787446659723` |
| A publish to A-B sync end | 44,109 ms |
| B1 finish to B2 start | 46,251 ms |
| A finish to C start | 46,326 ms |
| B restart to durable replay | 19 ms |
| C process runtime through delivery | 35,944 ms |

Both phase-one PIDs were reaped with exit status zero. `ps` returned status 1 and
no rows for A and B1 after reaping, for A before B2, and again for A immediately
before C. Thus A and C did not overlap, and the A-B and B-C contacts did not
overlap. The process timeline SHA-256 is
`760c3614144ac251360464611ed242f74411fbde6f3f362e41f7b982e0a7f28b`.

## Durable state and plaintext inspection

The same path, `runs/temporal-003/state/b.sqlite`, appears in both B invocations.
The same fixed B signing key produced the identical B node ID. Restarted B then
replayed the A-authored operation from local store before C was created.

After the core B-C phase and before the optional duplicate attempt, the composite
SQLite states were copied into ignored append-only snapshots. SQLite main, WAL,
and SHM files must be treated together; the main database file alone does not
describe this live WAL-mode state.

| Snapshot component | SHA-256 |
|---|---|
| B `b.sqlite` | `1fe8f6113488865c546d2faa55b21482662ce4be19d4f505eeefa09bc3131489` |
| B `b.sqlite-wal` | `e12c5a6699b8c05cc99381fe9eb4f0dea6dd405ae246d8a2fc91c1e589bb8d73` |
| B `b.sqlite-shm` | `3d51e00d52755bfac5e83ee0640b07adc20673bd64d14ff7731f1233e551e63b` |
| C `c.sqlite` | `1fe8f6113488865c546d2faa55b21482662ce4be19d4f505eeefa09bc3131489` |
| C `c.sqlite-wal` | `923b06f3d9b09fc376c625931407a7c01ea2842f451dd0abaed90ab9c23002ed` |
| C `c.sqlite-shm` | `a0e343c4d333e1aa9c7071fa95df70b2e3b451a3d8aaf2d6f44ae0cd96c43599` |

The exact payload occurred at line 1208 of B's WAL in the phase-one scan and at
line 1208 of the frozen post-core B WAL snapshot. It also appeared in B's
`ProcessedOperation` output. Relevant scan hashes:

| Scan | SHA-256 | Result |
|---|---|---|
| Phase-one B database and process output | `0fff662bb9bb829d7c4f337698b70a9b7806abc301279222c3d757f5d721c62d` | plaintext found in B WAL and process output |
| Immediate post-restart/core live state | `24326a859a776cdd719bc9d8b71a1bfbb3b8795d54440aab2f0794a8cf0dbd45` | plaintext found |
| Frozen post-core snapshot and process output | `e7a16ca6e653eaa653f2092168f822516affd1225d8bd4bbfeb1d4898656b14e` | plaintext found in B WAL snapshot and process output |

This positive plaintext finding is sufficient for DM-6-07 **not met**. A signed,
stable author field does not imply payload blindness, source encryption, or the
requirements security profile.

## Optional duplicate resynchronization

After freezing the core state, B and C were each restarted from their durable
databases for an optional duplicate resync:

```text
artifacts/temporal-target/debug/p2panda-temporal-relay b-duplicate runs/temporal-003/state/b.sqlite b1498bbdc252eeff0b8d0754f7d5dc996580c3594b4cee30b5795b165140ae84
artifacts/temporal-target/debug/p2panda-temporal-relay c-duplicate runs/temporal-003/state/c.sqlite b1498bbdc252eeff0b8d0754f7d5dc996580c3594b4cee30b5795b165140ae84
```

B again replayed the one local operation, but the restarted pair emitted no
observed `SyncStarted` or `SyncEnded` before each 120-second bound expired. With
no established duplicate contact, the attempt is **inconclusive** rather than a
candidate pass or failure. It does not affect the already frozen core result and
does not credit DM-5.6-05. The B and C duplicate logs have SHA-256 values
`f9cf03d2bbf8e9a0abe880d8dad7b6f549beccc09642458fe2815633b87ab817`
and `236b27676fd6b5ceadb8bab6c930bc47d87f72c6518efb7b35e05c43d1e5b096`.

## Attempt history

Evidence was retained append-only:

1. `temporal-001`: sandboxed network actor startup failed before a candidate
   contact. Environment blocked; no candidate credit. A log SHA-256:
   `9ca491ae649664ad18a49be81750640282bd5e748e99b743c61cd6411c0fac56`.
2. `temporal-002`: two separately launched unrestricted processes formed no
   observed sync session during their shortened overlap. Mutual discovery was
   not established, so this is harness/environment inconclusive, not a candidate
   failure. A/B log SHA-256 values are
   `9a97c64a6097771eb467294b03292b2807e4b61086049ceeb6528b2a07fd8432`
   and `992dab7722433451d75732dfcd9f6b98d849e0f8cebaf61e8b361b7df26b6344`.
3. `temporal-003`: two approved outer drivers kept each phase's child processes
   in one execution environment and extended the bounded discovery window. Both
   core legs passed. No prior attempt was deleted or rewritten.

The first two attempts used the preserved pre-final temporal binary with SHA-256
`1d18978d352226c55d5e7a942694365c7dde47cba6a1246a65c1904a08e86ecf`.

## Core evidence hashes

| Artifact | SHA-256 |
|---|---|
| A log | `90ab5fdd6d5272b5e348f8bc6d7128558fefd112bc5ee3fae61595a7f51a1cc3` |
| B phase-one log | `4a73134ae29d6abd1c1ed001f9f8fbbda2096d3766cc016fe9d3e86fa0b4545b` |
| B restart/relay log | `fb2995be2fa554033c1908c4827a881b54fbcde298e8c5763f8b3f97ce583f1e` |
| C log | `433e7e783c355524c9abec14a81801703872b48d2fa1d109b7ade42e0f89a8dc` |
| Resolved commands | `7dc749dc7858ab7f52ba894cdff260ce47df3c83c3dd3d84de07d46e93cec3ed` |
| Process timeline | `760c3614144ac251360464611ed242f74411fbde6f3f362e41f7b982e0a7f28b` |
| Database hash manifest | `eeb4cd37ca5a4cb6ef4c2362d8489b9b7c45f4bc70f2c7c351ae85c864516135` |

Raw runs, databases, snapshots, binaries, and scan output remain locally
preserved under the candidate directory and ignored by its existing
`.gitignore`.

## Requirement cells

“Met” is restricted to this one bounded candidate-native experiment.

| Requirement | Result | Executable boundary |
|---|---|---|
| DM-5.6-03 temporal bridging | **met** | One A-authored operation survived full B process exit/restart and reached C through network sender B while A was absent |
| DM-12-05 payload-blind temporal acceptance | **partial** | Temporal chain passed, but B could read and durably stored plaintext |
| DM-6-07 payload blindness at relay | **not met** | Fixed canary found in B process output and SQLite WAL |
| DM-5.6-05 duplicate propagation bound | **unknown** | Optional restarted resync formed no observed contact; no retry/storage bound established |
| DM-5.6-06 loop propagation bound | **unknown** | No cyclic relay topology or declared numeric bound was exercised |

## Explicit non-credit

This run does not establish:

- payload blindness, source encryption, protected metadata, or any other
  security requirement;
- a general DTN protocol, queue ownership model, arbitrary multi-hop routing,
  any-peer continuation, or a specialized relay role;
- duplicate item/contact bounds, application-effect idempotence, at-least-once
  application semantics, or loop suppression;
- forced-crash, torn-write, corruption, or kill-point recovery;
- TTL, expiry, pruning, quota, priority, eviction, or emission policy;
- delay proportionality, bandwidth bounds, or resource targets;
- cross-implementation interoperability or conformance.

## Disposition

Retain p2panda v0.7.1 as a research arm for candidate-native replicated-operation
carry across sequential contacts. The experiment adds real temporal-relay
functional evidence beyond the earlier two-node run. Its full-replica plaintext
exposure prevents the payload-blind acceptance outcome, and the untested
duplicate, loop, failure, security, policy, and interoperability surfaces prevent
selection or admission.
