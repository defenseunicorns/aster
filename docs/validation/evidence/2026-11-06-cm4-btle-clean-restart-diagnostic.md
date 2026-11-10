# CM4 BTLE clean-restart diagnostic — 2026-11-06

Status: **bounded affected-kernel diagnostic; no support or production claim**.

## Hardware and source

- Two ARM64 CM4 devices; Debian 13; Linux `6.18.39+rpt-rpi-v8`; BlueZ 5.82.
- Broadcom BCM4345C0 with `hci_uart_bcm`.
- Signed source head `5b41526074f4d86cbb6f0843b57f0080e94f9bc8`;
  `aster-btle-event` SHA-256
  `b59774eba509507596182db27d6a624ad0b5016834e31ade0235a6fc3255b413`.

## Scenario and result

Both nodes completed authenticated zero-work contacts, stopped cleanly, and
immediately restarted without controller mutation. Fresh evaluators became
available and re-registered the listener, but every CoC open timed out on PSM
`0x81` and `0x83` while the ACL remained connected.

A packet trace showed LE Credit-Based Connection Requests with signaling
identifier zero; both kernels logged `Bluetooth: Unable to allocate ident:
-28`. A controller power epoch restored nonzero identifiers and contacts.

This matches
[CVE-2026-72333](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/ffaa1b4ec1ea8813a90a5a6f9f577958c848a33c/cve/published/2026/CVE-2026-72333.mbox):
Linux leaked L2CAP signaling identifiers until the 1–255 space was exhausted.
Linux 6.18.40 is the first fixed 6.18 release.

## Consequence

The defect is below Aster framing, authentication, advertisement ownership, and
process lifecycle. Aster must not hide it with peer-wide disconnect, controller
reset, or power mutation. Clean restart requires a distribution kernel carrying
the fix and a physical restart run without controller mutation. The
[fixed-kernel record](2026-11-06-cm4-btle-clean-restart-validation.md) supplies
that bounded observation.
