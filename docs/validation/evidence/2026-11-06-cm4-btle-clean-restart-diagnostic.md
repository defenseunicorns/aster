# CM4 BTLE clean-restart diagnostic — 2026-11-06

Status: **bounded pre-fix physical diagnostic; root cause identified, not a
support or production-readiness claim**.

## Outcome

Two ARM64 Compute Module 4 devices completed authenticated zero-work Event
contacts, stopped cleanly, and immediately restarted without controller
mutation. Both restarted evaluators reached `Available`, and the listener
successfully registered a new advertisement, but every new LE L2CAP CoC open
timed out while BlueZ continued to report the peer ACL as connected.

The failure was not stale state for one PSM. Repeating the restart with a
different dynamic PSM produced the same result. A bounded packet trace then
showed that each failed open transmitted an LE Credit-Based Connection Request
with signaling identifier `0`; the peer did not answer the invalid request.
Both kernels concurrently recorded `Bluetooth: Unable to allocate ident: -28`.

This exactly matches Linux
[CVE-2026-72333](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/ffaa1b4ec1ea8813a90a5a6f9f577958c848a33c/cve/published/2026/CVE-2026-72333.mbox):
LE flow-control credit commands leaked L2CAP signaling identifiers until the
1–255 space was exhausted, after which later commands used invalid identifier
zero. The devices ran affected Linux `6.18.39+rpt-rpi-v8`; the upstream stable
record identifies `6.18.40` as the first fixed 6.18 release. The upstream fix
is `6e1930ece855a4c256f1c7e6632d634cfb9888b5`, with the 6.18 stable backport
`0c602cb8f148a36bfb39c25ade400bdadc023c4f`.

This is a kernel resource leak below Aster framing, mission authentication,
BlueZ advertisement registration, and process ownership. A peer-wide
`Device1.Disconnect`, controller reset, or power cycle can create a new kernel
link epoch, but none is an acceptable general adapter recovery: it can disrupt
unrelated users and `Device1.Disconnect` can disable future inbound LE
connections for an untrusted device. The safe recovery selected by this
diagnostic is a kernel containing the upstream fix, not an Aster reset path.

## Source and artifact binding

| Field | Observation |
| --- | --- |
| Diagnostic source head | signed `5b41526074f4d86cbb6f0843b57f0080e94f9bc8` |
| Source tree | `fae7049f68436e770217861db5b73834a0527281` |
| ARM64 `aster-btle-event` SHA-256 | `b59774eba509507596182db27d6a624ad0b5016834e31ade0235a6fc3255b413` |
| Build target | `aarch64-unknown-linux-gnu`, release, locked dependencies |

The cross-build used Debian 13 ARM64 D-Bus/systemd development packages in a
temporary sysroot. The exact package SHA-256 values were:

- `libdbus-1-dev_1.16.2-2_arm64.deb`:
  `305788b468ae2daba9074e59906a26df34d3f6f347d3191f13043f5a9224f90b`;
- `libdbus-1-3_1.16.2-2_arm64.deb`:
  `ca6bb5f2047ad58d274cb7d14216035a07d8e5aae6f6a0122c4f6293c9c39515`;
- `libsystemd0_257.13-1~deb13u1_arm64.deb`:
  `d2f63c408549c29eaefb6f4c948393edce99f45ee8e43c991391bef63fb7d54b`.

Both devices reported the same deployed executable digest. Exact Bluetooth
addresses, mission identities, bundles, and state contents remained in
owner-only temporary storage and are intentionally absent from this record.

## Platform and procedure

Both devices reported Debian 13 ARM64, Linux `6.18.39+rpt-rpi-v8`, BlueZ 5.82,
Broadcom BCM4345C0, and `hci_uart_bcm`. The evaluators used one public-address
controller and one provisioned peer each, a five-second successful-contact
cadence, and dynamic PSM `0x81` unless stated otherwise.

The bounded sequence was:

1. Start the listener, then the initiator, and complete multiple authenticated
   zero-work contacts.
2. Observe `peer_acl=connected` after each drained contact on both sides.
3. Stop both processes with SIGTERM and require `status=stopped`.
4. Confirm both processes exited while BlueZ still reported the ACL connected
   and both controllers remained powered.
5. Immediately start fresh processes with the same configuration. Both sides
   timed out; the listener still had one active advertisement.
6. Stop both processes cleanly, then repeat with PSM `0x83`. Both sides timed
   out again while the same ACL and controller power epoch remained.
7. Capture one failed PSM `0x81` attempt. Each side observed two transmitted or
   received LE Connection Requests with identifier zero, and both kernel logs
   contained repeated identifier-allocation failures.
8. As a diagnostic comparator only, create a new controller power epoch and
   capture the same PSM `0x81` path. Three successive contacts used nonzero
   identifiers and completed; no identifier-zero request appeared.

The comparator power cycle was an operator diagnostic after the failure was
already reproduced. It is not implemented recovery, does not satisfy the clean
restart acceptance criterion, and does not broaden adapter authority.

## Bounded observations

Before the pre-fix restart, both sides completed zero-work contacts and then
stopped cleanly. After restart, the first and second attempts failed with the
closed `Timeout` category. At the failed PSM variation, the initiator used
15,404 KiB RSS, eight threads, and 19 file descriptors; the listener used
15,492 KiB RSS, eight threads, and 19 file descriptors. These are point
observations only.

The failed trace rules out all of the following as the immediate boundary:

- failure to restart either Aster node or BTLE supervisor;
- failure to derive complementary roles;
- failure to observe controller availability;
- failure to re-register the listener advertisement; and
- stale L2CAP state limited to one PSM.

The trace and kernel log positively bind the failure to exhausted Linux L2CAP
signaling identifiers. The kernel fix releases identifiers for commands with
no response and releases an outgoing LE connection-request identifier when its
response arrives.

## Claim boundary and next validation

No Aster production recovery code is justified by this pre-fix result. Clean
restart must be validated on a distribution kernel that contains the upstream
fix. Kernel version text alone is not a portable runtime capability check
because distributions may backport the fix; platform qualification must bind
the installed kernel package or source to the fix and then execute the restart
procedure.

The temporary traces contain link-layer locators and remain outside the
repository. They are diagnostic artifacts, not reusable fixtures. The later
[fixed-kernel validation](2026-11-06-cm4-btle-clean-restart-validation.md)
completed process-only restart on the same CM4 hardware with Linux 6.18.60.
This diagnostic record itself does not claim Android restart behavior,
multi-peer or multi-controller safety, crash recovery, or production support.
