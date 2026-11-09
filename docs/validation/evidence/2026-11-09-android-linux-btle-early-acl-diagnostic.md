# Android/Linux BTLE early-ACL diagnostic — 2026-11-09

Status: **host-stack defect isolated; no protocol, Aster implementation,
hardware-support, requirement-credit, or production-readiness claim**.

## Outcome

A cold Android-to-Linux LE L2CAP CoC attempt failed because the evaluated
Realtek USB controller path delivered inbound ACL data to Linux before the HCI
LE Enhanced Connection Complete event for the same connection handle. The
Pixel had sent both an ATT request and the PSM-128 LE Credit Based Connection
Request. Linux received those ACL packets approximately 1.3 ms before it
registered the connection handle and discarded them. The Android foreground
validator then reached its 30-second contact deadline.

After an unrelated Bluetooth mouse established an LE connection, the same
Pixel, application, Aster binaries, mission configuration, controller, kernel,
BlueZ process, and PSM completed the CoC handshake. In that trace, Linux
received Connection Complete approximately 68 ms before the Pixel's ATT and
L2CAP requests and replied to the CoC request within 0.1 ms. An earlier run in
the same investigation transferred and durably inserted one 65,536-byte Event
with the expected semantic-v9 profile digest.

This isolates the failed cold attempt below the Aster process. It is not an
Android omission of the CoC request, an Aster protocol or admission failure,
or a reason to add protocol fallback. Enabling a mouse is a diagnostic trigger,
not an operational workaround.

## Exact diagnostic boundary

| Field | Observation |
| --- | --- |
| Source head | signed `b3340b4920296737a4df73318dbe7a37673dcceb` |
| Android artifact | Pixel 9 Pro XL; APK SHA-256 `806af92a640547f21c1236436b0f2dd54e6d5f446f8255728c42535e441da7c1` |
| Linux host | x86-64; Ubuntu Linux `7.0.0-42-generic`; BlueZ 5.85 |
| Linux controller | Realtek USB Bluetooth Radio `0bda:5852`; `btusb` 0.8 |
| Carrier | LE L2CAP CoC; PSM 128 |
| Capture SHA-256 | `554ee6386bc37056f077811e5a0b19f34d99dd8cf7bd5fc9d24a852d901271eb` |

The raw `btmon` capture is deliberately not retained in the repository because
it contains transient device addresses and unrelated HID traffic. The table
hash identifies the local diagnostic artifact. Exact Bluetooth addresses,
mission identities, bundles, state, and device serial are excluded.

## Packet-order evidence

The single capture contains a cold failure followed by warmed attempts:

| Path | Sanitized observation |
| --- | --- |
| Cold | Inbound ATT request at 43.924884 s; inbound PSM-128 CoC request at 43.924886 s; Connection Complete at 43.926188 s; remote disconnect at 73.763165 s |
| Warm, rotated address | Connection Complete at 134.466573 s; inbound ATT and CoC requests at 134.534889/891 s; successful CoC response at 134.534923 s; Aster then rejected the rotated address as configured |
| Warm, exact address | Inbound CoC request at 164.880885 s; successful CoC response at 164.880921 s; protected semantic-v9 contact completed |

Linux normally looks up an HCI connection by handle before delivering ACL
data to L2CAP. The running kernel contains no early-ACL holding mechanism, so
the cold request cannot be recovered by the user-space listener after it has
been discarded.

The Linux Bluetooth mailing-list discussion describes the same USB transport
race: bulk-IN ACL completion can overtake the interrupt-IN connection event.
The proposed v2 briefly queued unknown-handle ACL packets; maintainer review
instead requested a temporary pending connection, followed by a v3 proposal.
Those proposals are diagnostic context, not a dependency admitted or shipped
by Aster:

- <https://lkml.iu.edu/hypermail/linux/kernel/2607.3/14640.html>
- <https://lkml.iu.edu/hypermail/linux/kernel/2607.3/16347.html>
- <https://lore-kernel.gnuweeb.org/linux-bluetooth/CAEzAHR-7LQak12o_Xt7QrvLHRw3GSLDgco6o7Fru-wVXyBW7mQ%40mail.gmail.com/T/>

## Qualification consequence

The earlier successful Pixel/Linux record remains valid for the exact observed
run, but this controller/kernel combination is not qualified for unattended
cold Android initiation. Aster should not reset a shared controller, keep a
dummy connection open, or change the wire protocol to conceal a host-kernel
ordering defect.

Qualification can resume on a kernel that contains an accepted early-ACL fix
or on another controller/kernel combination that does not reproduce the race.
The minimum rerun starts with the controller power-cycled and no unrelated
Bluetooth connection, then repeats multiple cold contacts, transfers an Event
larger than the negotiated transmit packet bound, verifies the exact durable
application receipt, and repeats after process and controller restart.
