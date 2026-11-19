# Orin BTLE advertisement and scan restart — 2026-11-18

Status: **bounded engineering observation; not hardware qualification or an
end-to-end BTLE result**.

## Source, build, and device

- Signed source: `0b76393856eb7efa4b3d9d792b9e82b0f4b07a47`.
- Build: `cargo build -j 2 -p aster-ble-linux --bin aster-btle-event
  --target aarch64-unknown-linux-gnu` with
  `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc`.
- Toolchain: Rust/Cargo 1.97.1 and Ubuntu `aarch64-linux-gnu-gcc` 15.2.0.
- `libdbus-sys = { version = "=0.2.7", features = ["vendored"] }` was added
  only for this cross-build. The temporary manifest and lock-file changes were
  reverted.
- Stripped executable SHA-256:
  `ac29e7203827090ca33d556cc20968ed4ad30314cee4320d66ecbc68193334af`.
  The local and remote checksums matched.
- NVIDIA Jetson Orin Nano Engineering Reference Developer Kit; Ubuntu 24.04.5;
  Linux `6.8.12-1021-tegra`; BlueZ controller `hci0`, public address type.

## Scenario and observations

The repository non-production provisioning bundle, a disposable generated
`ASTRBD02` discovery credential, and a synthetic all-`ff` peer identifier were
used. The process shape was:

```text
aster-btle-event --transport rostered --adapter hci0 \
  --local-address <redacted-controller-address> --local-address-type public \
  --state /tmp/aster-orin-state-0b76393 \
  --mission-bundle /tmp/aster-orin-mission.bundle \
  --mission-peer ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --discovery-scope-id <synthetic-non-production-scope-id> \
  --discovery-credential-unprotected-reference /tmp/aster-orin-discovery.credential \
  --contact-cadence-seconds 60
```

Two consecutive runs remained alive after startup. During each run, independent
BlueZ property reads reported `ActiveInstances = 1` and `Discovering = true`.
Each process then handled `Ctrl-C`, exited with status zero, and left
`ActiveInstances = 0` and `Discovering = false`. The second run reused the same
state and controller; discovery became true after the slower state reopen.

The observed properties were read with `busctl get-property` from
`org.bluez.LEAdvertisingManager1.ActiveInstances` and
`org.bluez.Adapter1.Discovering`. Local and remote test binaries, state, and
disposable credentials were removed; exact `/tmp/aster-orin-*` searches were
empty afterward.

## Explicit-controller claim boundary

This shows that the executable produced from this signed source state, with the
recorded build-only adjustment, can register the production advertisement and
scanner twice on this device and cleanly release the two observed BlueZ
resources. This record does not preserve a capability-metadata query or
comparison.

It does not establish on-air packet contents, listener acceptance, peer contact,
authentication, Event transfer, automatic controller selection, CM4 behavior,
package or service operation, least-privilege policy, soak behavior, full-suite
status, hardware support, or production readiness. Start timestamps, raw
stdout/stderr, a pre-run property snapshot, and a reproducible-build attestation
were not retained.

## Automatic agent composition follow-up

Status: **operator-attested, non-reproducible source-composition observation**.
The disposable example source and raw logs were not retained.

At signed source `6cd44733e3dea4a53db99a786d5f3f2c817adb1f`, a disposable
ARM64 example invoked the real `BtleRuntimeStartup::automatic_linux` and
`run_customer_agent_with_btle` composition. It substituted
`prepare_discovery_credential_for_test`, a one-shot in-memory `ASTRBD02`
provider, a system-clock adapter, and an in-memory loader for the repository's
non-production mission bundle. Customer policy contained no controller name or
address.

The example was built with Rust/Cargo 1.97.1 and Ubuntu
`aarch64-linux-gnu-gcc` 15.2.0 using:

```text
CARGO_BUILD_JOBS=2 \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
cargo build --offline -p aster-agent --example orin_auto_harness \
  --target aarch64-unknown-linux-gnu
```

As in the explicit-controller build, `libdbus-sys = "=0.2.7"` temporarily
used its `vendored` feature; the manifest and lock-file changes were reverted.
The stripped executable SHA-256 was
`9f9b30c2f4140459bea5a6216ffe591c6d16c6121d11e3bb10d56ba05b0c6fe8`;
local and remote checksums matched. The two run arguments were:

```text
/tmp/aster-orin-auto-harness-6cd4473 \
  /tmp/aster-orin-auto-state-6cd4473 \
  /tmp/aster-orin-auto-mission.bundle
/tmp/aster-orin-auto-harness-6cd4473 \
  /tmp/aster-orin-auto-state2-6cd4473 \
  /tmp/aster-orin-auto-mission.bundle
```

Two independent 20-second clean-state runs reached agent readiness and then
reported one active BlueZ advertisement plus active discovery. Discovery later
became inactive while the advertisement remained active, consistent with the
configured bounded scan window. Both timed terminations logged clean shutdown,
exited successfully, and left `ActiveInstances = 0` and
`Discovering = false`. The same `busctl get-property` observations named above
were used.

This operator-attested follow-up exercises discovery, selection, and activation
of the one present controller through the source agent composition. It does not
exercise multiple-controller selection, the customer binary's systemd
credential presentation, packaged service identity, Event transfer, or
controller hotplug. The disposable example source, binary, state, logs, and
credentials were removed after the run.

### Same-state restart follow-up

At signed production source `433e0b1ab1ed1ec450e1fc02691eef2130ecaf3f`, a
corrected disposable example repeated the automatic composition against one
state root. The first validation attempt had used the earlier disposable
example, which called `mkdir` on its already-existing harness root and failed
with `EEXIST` before Aster startup. A GDB `mkdirat` catch confirmed that
harness-only cause. No production-code or durable-state failure was observed in
that attempt.

The corrected example used `create_dir_all` only for its disposable fixture
root. Host `cargo check --locked -p aster-agent --example
orin_restart_harness` passed. The ARM64 example was then built offline with the
temporary vendored `libdbus-sys` feature recorded above:

```text
CARGO_BUILD_JOBS=2 \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
cargo build --offline -p aster-agent --example orin_restart_harness \
  --target aarch64-unknown-linux-gnu
```

The build-only manifest and lock changes were reverted. Its stripped SHA-256 was
`57c55c4f58631d0f6d943e80ac1ef66831b686f5a67ba2a740c2cf2f6ca99c93`,
and the local and remote hashes matched.

Two successive 20-second runs used the identical
`/tmp/aster-orin-restart-state-433e0b1` state root. The harness owned the
20-second stop; an outer 30-second watchdog bounded each invocation:

```text
/tmp/orin_restart_harness /tmp/aster-orin-restart-state-433e0b1 \
  /tmp/mission.bundle
```

Each run reached agent readiness,
reported `ActiveInstances = 1` and `Discovering = true`, later ended its bounded
scan, logged clean drain and shutdown, returned `HARNESS exit=Clean`, and left
`ActiveInstances = 0` plus `Discovering = false`. The second run reopened the
first run's node and discovery-checkpoint state; the state root was not removed
or replaced between runs.

This is source-composition evidence that automatic single-controller
availability reconstructs across one clean same-state process restart. It is
not packaged-service, credential-presentation, Event-transfer, controller
hotplug, multiple-controller, soak, or hardware-qualification evidence. The
corrected example source, binaries, state, logs, mission fixture, and temporary
build-only changes were removed after the observation.

### Current evaluator follow-up

After merging official `main`, the ARM64 `aster-btle-event` artifact from signed
source `7a5f20d5007f3a45c83169a21cba367dda0bf36c` was replayed on the same Orin.
The merge checkpoint `a0b9faf2094c1808c86aa5f4e4ddfa5210207369` does not change
`aster-ble-linux` or `aster-agent`. The artifact SHA-256 was
`a774175629b3316699f95f51c22e6fc74543563ad919f8830825563ad41cef17`.

The repository non-production bundle and a disposable `ASTRBD02` credential
were copied into one owner-only temporary directory. A same-state rostered
repeat observed `ActiveInstances = 1` and `Discovering = true` at the second
one-second sample. Timed SIGINT produced exit status zero and the final external
read returned `ActiveInstances = 0` and `Discovering = false`. A preceding
observed run reached the same active properties and was later confirmed exited
with both properties released, although its exit status was not retained.

This follow-up validates current evaluator advertisement/scan ownership and one
successful same-state repeat after the preceding process exited and released
its BlueZ resources. The synthetic peer was intentionally unmatched, so it adds
no contact or Event-transfer evidence. The remote evaluator, mission fixture,
credential, state, and logs were removed; no controller address, mission
identifier, credential, or raw log is retained.

### Automatic peer-observation follow-up

At signed production source `1fa50a826c650c03fbad497c3c53a28e5072e13b`, a
disposable harness invoked the automatic Linux/customer composition on a Linux
workstation and this Orin. Both sides reached readiness and reported the BTLE
adapter available, but a durable 65,536-byte Event was not delivered within the
bounded 120-second observation. Temporary diagnostics categorized each Orin
contact attempt as `AdapterEpochEnded`: no candidate completed during an
advertisement epoch. This is an operator-attested source-composition
observation; no reproducible package identity is retained.

Peer-observation controls showed radio contact alongside the negative result.
A boundary sweep then exposed 128-bit UUID ServiceData with 13 payload bytes,
but not 14, 16, or the production 40 bytes. This exactly matches a BlueZ
receive-side defect: `btd_device` creates its discovered-device `bt_ad` cache
with the [legacy 31-byte default](https://github.com/bluez/bluez/blob/770ad5614e7e8074133e6f563495ce4822f63fe4/src/shared/ad.c#L46-L59),
and [`bt_ad_add_service_data`](https://github.com/bluez/bluez/blob/770ad5614e7e8074133e6f563495ce4822f63fe4/src/shared/ad.c#L967-L978)
rejects payloads larger than
`31 - 2 - 16 = 13` bytes. The [caller](https://github.com/bluez/bluez/blob/770ad5614e7e8074133e6f563495ce4822f63fe4/src/device.c#L2207-L2225)
then omits that entry and its property update.
This is the behavior of the evaluated BlueZ 5.72 stack, not an Orin radio
limit. Upstream fixed the default cache capacity in
[`f40c5857`](https://github.com/bluez/bluez/commit/f40c5857d70a91e417e22da9da20f4193414b8a3),
first released in BlueZ 5.76.

Automatic rostered discovery therefore remains blocked on the evaluated Orin
software stack until the corrected receive path is installed and the complete
bidirectional path is repeated. This does not invalidate the separate
fixed-locator 65,536-byte Event transfer evidence. No fallback or wire-protocol
change was introduced. The harness, fixtures, state, and logs were removed.

### Current-head installed-service follow-up

At signed source `7debe7357feb0846f7f9263062ebc213756e04fb`, checksum-pinned
ARM64 agent and credential-admin binaries were temporarily installed on the
Orin under the production systemd unit, service account, D-Bus policy, and
encrypted roster binding. The loaded unit had no drop-ins, no capabilities,
enabled `NoNewPrivileges` and `PrivateDevices`, and allowed `AF_BLUETOOTH` but
not `AF_PACKET`. Roster sequence 1 reached readiness and reported BTLE
`available` with support `unqualified`; clean stop released advertising and
discovery, same-state restart succeeded, and sequence 2 was accepted into the
durable discovery checkpoint. Representative BlueZ control calls were denied,
and journal visibility plus the bounded status-field schema passed.

This is installed-service evidence, not Debian-package, peer-transport,
Event-transfer, production, release, composite-profile, or hardware-
qualification evidence. Systemd also reported that the host credential key was
on unencrypted media and TPM2 sealing failed, so this Orin image does not meet
production credential-at-rest custody without an encrypted-media or working-
TPM remedy. After the run, an independent readback confirmed the Aster unit,
account, policy, configuration, credential bindings, and state were absent;
BlueZ reported zero advertisements and discovery false. The approved host-wide
systemd credential key remained on the unencrypted media, while every staged
Aster artifact was removed. The BlueZ 5.72 receive-path limitation above
continues to block automatic peer-discovery qualification on this image.
