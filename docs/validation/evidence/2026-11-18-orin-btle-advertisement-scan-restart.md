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
credential presentation, packaged service identity, same-state process restart,
Event transfer, or controller hotplug. The disposable example source, binary,
state, logs, and credentials were removed after the run.
