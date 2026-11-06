# CM4 BTLE clean-restart validation — 2026-11-06

Status: **bounded fixed-kernel physical evidence; not hardware qualification,
requirement credit, or production authorization**.

## Outcome

Two ARM64 Compute Module 4 devices running the fixed Raspberry Pi Linux
6.18.60 package completed repeated authenticated zero-work BTLE contacts,
stopped cleanly, and started fresh evaluator processes over the retained ACL
without a controller power epoch change. The fresh evaluators completed more
contacts. Neither kernel emitted an L2CAP identifier-allocation failure.

This closes the specific process-restart blocker diagnosed on Linux 6.18.39.
It does not add an Aster disconnect/reset path: the fix is in the Linux L2CAP
implementation, below adapter ownership.

## Source, executable, and platform binding

| Field | Observation |
| --- | --- |
| Validation control head | signed `37da88fa83bc07cd05dcd13d652319bab5a0b4eb` |
| Last production-code head in the executable | signed `5b41526074f4d86cbb6f0843b57f0080e94f9bc8` |
| Production source tree | `fae7049f68436e770217861db5b73834a0527281` |
| ARM64 `aster-btle-event` SHA-256 | `b59774eba509507596182db27d6a624ad0b5016834e31ade0235a6fc3255b413` |
| Kernel package | `linux-image-6.18.60+rpt-rpi-v8` `1:6.18.60-1+rpt1` |
| Running kernel | `6.18.60+rpt-rpi-v8` on both devices |
| BlueZ/controller | BlueZ 5.82; Broadcom BCM4345C0; `hci_uart_bcm` |

The commits after the executable's production head changed documentation and
test-only code, not release behavior. Both devices verified the exact
executable digest before execution. The same owner-only two-node mission shape
and dynamic PSM `0x81` were used throughout. Exact Bluetooth addresses,
mission identities, bundles, and state contents are intentionally excluded.

Linux 6.18.60 is later than the first fixed 6.18 release identified by the
upstream [CVE-2026-72333 record](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/ffaa1b4ec1ea8813a90a5a6f9f577958c848a33c/cve/published/2026/CVE-2026-72333.mbox).
The prior pre-fix reproduction and component-boundary proof are retained in the
[clean-restart diagnostic](2026-11-06-cm4-btle-clean-restart-diagnostic.md).

## Procedure and observations

After installing the fixed distribution kernel and rebooting each device, the
operator deployed fresh owner-only mission/state roots and the identical signed
artifact. Controller power was then held constant for every contact and
process-restart observation.

The first fixed-kernel processes completed six contacts per side with zero
contact failures. Point resource observations were:

| Participant role | RSS (KiB) | Threads | File descriptors |
| --- | ---: | ---: | ---: |
| Initiator | 17,540 | 10 | 31 |
| Listener | 18,148 | 9 | 33 |

Both processes then emitted `status=stopped` and exited. BlueZ still reported
the peer ACL connected and both controllers powered. Fresh processes using the
same configuration completed three contacts per side with zero failures. A
temporary lab-network interruption delayed only the operator's SSH dispatch;
the devices did not reboot and their controllers remained powered.

A final restart removed that dispatch ambiguity. Each device executed its
local stop-and-start sequence as one command. The measured gap between confirmed
old-process exit and new-process creation was 3 ms on the initiator and 6 ms on
the listener. The processes started concurrently; the initiator observed one
expected `Unavailable` open before the listener registered, then both sides
completed 11 contacts. No timeout or transport failure occurred. Point
post-restart observations were approximately 17.4 MiB RSS, ten threads, and
22–23 file descriptors per process.

The bounded packet trace spanning the earlier fixed-kernel contact and restart
sequence reported, on each host:

- 16 observed LE Credit-Based Connection Request records;
- zero connection requests with signaling identifier zero;
- zero flow-control credit commands with signaling identifier zero; and
- zero `Bluetooth: Unable to allocate ident` kernel records in the current
  boot.

These counts are diagnostic trace records, not application throughput or
contact counters. The result demonstrates that the fixed kernel reuses the
retained ACL without the identifier exhaustion observed on 6.18.39.

## Cleanup and claim boundary

All evaluator processes stopped cleanly. Temporary binaries, mission bundles,
state roots, logs, and link-layer traces were deleted from both devices and the
local builder. Both controllers were returned to powered-off state. The fixed
kernel packages remain installed on the lab devices; the upgrade is part of
the validated platform state.

This record validates zero-work Linux/Linux clean process restart for exactly
the stated fixed-kernel CM4 stack. It does not repeat Event payload delivery or
application receipt on the fixed kernel; those remain separate earlier Ring-1
evidence. It does not establish crash recovery, multi-peer/controller safety,
State/Record/Blob execution, Android interoperability, broad Linux support,
resource thresholds, packaging, or production readiness.
