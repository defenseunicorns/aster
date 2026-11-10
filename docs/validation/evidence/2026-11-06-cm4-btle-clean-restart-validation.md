# CM4 BTLE clean-restart validation — 2026-11-06

Status: **bounded fixed-kernel physical evidence; no hardware qualification,
requirement credit, or production authorization**.

## Hardware and source

- Two ARM64 CM4 devices; Debian 13; BlueZ 5.82.
- Raspberry Pi Linux `6.18.60+rpt-rpi-v8`, package
  `linux-image-6.18.60+rpt-rpi-v8` `1:6.18.60-1+rpt1`.
- Broadcom BCM4345C0 with `hci_uart_bcm`.
- Signed control head `37da88fa83bc07cd05dcd13d652319bab5a0b4eb`;
  executable source head `5b41526074f4d86cbb6f0843b57f0080e94f9bc8`;
  `aster-btle-event` SHA-256
  `b59774eba509507596182db27d6a624ad0b5016834e31ade0235a6fc3255b413`.

## Scenario and result

The first processes completed six authenticated zero-work contacts per side,
stopped cleanly, and left controllers powered with the ACL retained. Fresh
processes using the same configuration completed further contacts without a
controller epoch change. A final local stop/start sequence used 3 ms and 6 ms
process gaps and completed 11 contacts after one expected startup-order
`Unavailable` observation.

Packet traces contained 16 LE Credit-Based Connection Requests per host, zero
identifier-zero requests or flow-credit commands, and no kernel
`Unable to allocate ident` record. Point resource observations were about
17–18 MiB RSS, 9–10 threads, and 22–33 file descriptors.

## Boundary

This closes only the Linux 6.18.39 restart blocker identified in the
[affected-kernel diagnostic](2026-11-06-cm4-btle-clean-restart-diagnostic.md).
It validates zero-work Linux/Linux process restart on the exact fixed CM4 stack.
It does not repeat Event delivery/application receipt or establish crash
recovery, other hardware, other data classes, support, or production readiness.
