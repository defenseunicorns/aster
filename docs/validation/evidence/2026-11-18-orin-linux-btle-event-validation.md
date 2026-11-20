# Orin/Linux fixed BTLE Event validation — 2026-11-18

## Result

A fixed, exact-peer Linux BTLE contact transferred one authenticated Aster
Event from an NVIDIA Jetson Orin Nano to a Linux workstation. The receiver
durably inserted the Event once, printed the expected short text, shut down,
reopened through the normal agent, and returned exactly one matching Event from
its durable state.

This is bounded evaluation evidence for the Event data type. It is not a
production-readiness, automatic-selection, discovery, packaging, or broad
hardware-support claim.

## Evaluated artifacts and systems

- Source: `6c7d8b0d348c83df26a08c0757d2cea0ef0ad95c`.
- Linux receiver: Ubuntu `26.04`, `x86_64`, kernel `7.0.0-43-generic`, BlueZ
  `5.85`, Realtek USB `0bda:5852` with `btusb`, and `aster-btle-ring1`
  SHA-256
  `f0f432daec3d6543d01a3a1f090bfc0ba0a2c69304b60de46c143083750829cd`.
- Orin sender: Ubuntu `24.04`, `aarch64`, kernel `6.8.12-1021-tegra`, BlueZ
  `5.72`, IMC Networks USB `13d3:3549` with `rtk_btusb`, controller roles
  central and peripheral, and `aster-btle-event` SHA-256
  `d27d5f94c205b2c45869a0affc38f758bc4c8a62024db293af18e9d3b840af5d`.
- Orin state preparation used arm64 `aster-agent` SHA-256
  `2f55f1d58ecbd0b6f910df0c3eff8e8013747b5bd57caa1f862b0ffa2d8148dd`
  and `asterctl` SHA-256
  `5b37e107819e71d8efb037139a0deb9e891de4188e046c5d9866934533bc82cd`.
- The receiver reopen/query used `aster-agent` SHA-256
  `91445f5aa99977ae7bfc8597bdf10808146185d74188bbe318c99d0aa9fb2cd3`
  and `asterctl` SHA-256
  `4081bcf3d2f371ba9cfa8d95a18d5d2cb2461ce11eeee536f2a7d189d078bc86`.
- Controller firmware build/revision was not exposed by the retained commands
  on either endpoint and is unavailable in this record.
- Both nodes used distinct disposable members of one generated non-production
  mission. No IP Aster peer was configured.

The receiver and arm64 artifacts were operator-built from the named worktree
with Rust/Cargo `1.97.1`; the cross C compiler was GCC `15.2.0`. The receiver
used a targeted locked `-j2` build. Arm64 sender, agent, and CLI used targeted
release `-j2` builds for `aarch64-unknown-linux-gnu`; a temporary vendored D-Bus
feature and explicit target C compiler/linker were used for cross compilation
and then reverted. Artifact hashes were retained, but complete build logs and a
reproducible-build proof were not. The local query-side agent and CLI were
pre-existing operator builds from the same worktree; their exact build command
was not retained.

## Setup integrity finding

Copying an already-created Redb node state to Orin was rejected before radio
use because the persisted Blob depot owner binding no longer matched its exact
filesystem backing. The valid setup copied only the disposable mission and
carrier identity inputs. Orin then created its database locally on ext4,
published the Event through its loopback-only agent, and reopened that same
on-device state in the BTLE sender.

This is expected integrity enforcement. A live node database is not a portable
provisioning artifact.

## Contact evidence

The first bounded attempt used the workstation controller cold. The Orin
initiator reported transport-open failures and the Linux listener timed out
with zero contacts. No mission handshake or Event exchange occurred.

The known paired mouse was then connected to reproduce the previously retained
warm-controller condition for this Realtek/Linux stack. The clean retry passed:

- the Orin initiator completed one protected contact and offered one Event;
- the Linux listener fetched and inserted one Event with zero duplicates;
- semantic version was `9`;
- negotiated transfer profiles were `2,1,1,5,1` with matching profile digest;
- directional send and receive MTUs were both `672` bytes;
- the serialized Event page received `10,561` bytes and was larger than the
  directional MTU;
- the printed Event text was `Orin BTLE Event E2E 2026-11-18`;
- the receiver Event ID matched the Orin publication receipt; and
- after both BTLE processes exited, the receiver reopened through
  `aster-agent` and an exact topic, scope, and logical-key query returned one
  matching Event.

The UTF-8 payload was `30` bytes, below the `672`-byte directional MTU, and the
receiver ran with `--require-event-larger-than-mtu no`. Only the serialized page
was larger than the MTU. This run therefore does not satisfy the Ring-1 profile
requirement for an Event payload larger than the smaller directional MTU.

The sender, receiver, and query agent then stopped cleanly. The exact local and
Orin disposable lab directories were removed, including generated mission
inputs, credentials, journals, state, and copied binaries. Local build outputs
remain under `target/`. The retained record omits device addresses, mission
identifiers, raw logs, credentials, state, and payload artifacts beyond the
short non-sensitive validation text.

## Claim boundary

This establishes one operator-built, warm-controller, fixed-locator
Linux-to-Linux Event transfer between the Orin and the evaluated workstation.
It also confirms durable receipt across receiver state reopen in a new normal
agent process.

It does not resolve the workstation cold-controller race and does not establish
automatic transport selection, rostered discovery, controller hot-plug,
unattended restart, non-root packaged service operation, State/Record/Blob
transfer, performance or soak bounds, hostile-peer behavior, broad
interoperability, or production readiness. The mouse connection is a diagnostic
condition for this evidence, not an operational workaround or support policy.

## Signed-source 65,536-byte Event follow-up

At signed source `5ac6603ead4bc6ef64efc949921ee972bb43bda9`, the same endpoint
and controller stacks transferred one precommitted semantic-v9 Event from the
Orin to the subscribed Linux workstation. The payload contained 65,536 zero
bytes, the maximum accepted by `asterctl publish`; its SHA-256 was
`de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31`.

The artifact SHA-256 values for that source were:

- x86-64 `aster-btle-event`:
  `f2c2d5377ba27cc8390f321ee2511bc2d5e6111d8603d328e1941d9830705e09`;
- ARM64 `aster-btle-event`:
  `14a050a49502be97e65975be7d0007a6dd0d4a6170068b6336d8ccdf20ca8788`;
- x86-64 `aster-agent` and `asterctl`:
  `66165bfcdfa320126b009abbf3a3929d5f41b9ff70e89e658090e51d45d8b7e5`
  and `c5fe98f623b7ee193088b164a6141a1c47d4077eec250d7f9039a332d9a585b3`;
- ARM64 `aster-agent` and `asterctl`:
  `d658b8b4097709b32b0bd5a314c9d88b89305000f29e74b39b4fa9493ebc255c`
  and `7b45e650fad7db862b11bae39e0f6ea4f3c1e67181cc7fc0fd264a8a25e189f6`.

No build-only source change was retained. The lower complete 32-byte mission
`NodeId` was the Orin initiator and the higher `NodeId` was the Linux listener.
Both used exact public controller addresses, PSM `0x81`, and a two-second
evaluation cadence. The Orin reported `offered=1`; Linux reported `fetched=1
inserted=1`. A later contact on both hosts reported zero offered, fetched, and
inserted work. Both evaluators emitted `status=stopped` and exited zero.

After shutdown, a peerless receiver agent reopened the Linux state. An exact
topic-and-scope query returned one Event whose identifier matched the publisher
receipt observed during the run. Its decoded payload length and SHA-256 matched
the source payload. Final BlueZ reads on both hosts returned
`ActiveInstances = 0` and `Discovering = false`.

This is operator-attested, non-reproducible warm-controller point evidence. It
does not add Ring-1, physical-qualification, requirement, support-row, or
protocol-qualification credit. Negotiated MTUs, profile/digest parity,
mission-before-data ordering, timestamps, and a sanitized receipt were not
retained. Disconnect and reconnect, controller recovery, and process restart
were not exercised. The unrelated workstation mouse remained connected, so the
cold-controller race remains open. The other claim boundaries above continue
to apply.

The owner-only mission bundles, node credentials, tokens, journals, receipts,
payloads, binaries, state, and raw logs were disposable. Their exact local and
remote temporary roots were verified absent afterward.
