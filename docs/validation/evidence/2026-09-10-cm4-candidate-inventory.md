#

# CM4 candidate inventory input — 2026-09-10

## Disposition

Status: **accepted and frozen for bounded MVP validation by Decision 0043**.

This record selects the two mandatory physical participants for the Linux Event
MVP evaluation profile and declares the third available device as a
non-participating spare. It is a sanitized repository record, not a signed
candidate annex, G4/G5 receipt, or release authorization.

The mandatory pair is:

- `cm4-a` — operator label `rpi4-1`;
- `cm4-b` — operator label `rpi4-2`.

`cm4-spare` — operator label `rpi4-3` — is available only as a spare. It must
not send, receive, store, or relay candidate traffic unless the candidate
inventory first assigns it an exact role. Only scenarios run after that
inventory revision can support the candidate.

## Common observed profile

Read-only inspection observed the following identical profile on all three
devices:

| Field | Observed value |
| --- | --- |
| Environment class | Physical device |
| Hardware | Raspberry Pi Compute Module 4 Rev 1.1 |
| CPU architecture | `aarch64`; Debian package architecture `arm64` |
| CPU allocation | 4 online processors |
| Installed RAM | 949,702,656 bytes |
| Image identity | Raspberry Pi reference `2026-06-18` |
| Image generator | `pi-gen` commit `ca8aeed0ae300c2a89f55ce9617d5f96a27e99e5`, `stage2` |
| Debian identity | Debian GNU/Linux 13.6 `trixie` |
| Kernel | `6.18.39+rpt-rpi-v8` |
| systemd package | `257.13-1~deb13u1` |
| systemd credential tool | `systemd 257 (257.13-1~deb13u1)` |
| Physical storage | 15,634,268,160-byte `mmcblk0` |
| Root filesystem | `/dev/mmcblk0p2`, local `ext4`, mounted `rw,noatime` |
| Access used for inspection | Operator-provided IPv4 over an inspection-only ZeroTier path; underlying device interface is WLAN |
| Aster relay | Not used for inventory inspection |

This matches the profile's hardware, image, operating-system, kernel, systemd,
and architecture boundary. The root filesystem is consistent with a possible
local-`ext4` state placement, but does not establish the candidate state path.
The observation does not qualify the package, provider presentation, Aster
carrier behavior, or resource thresholds.

## Sanitized participant bindings

### `cm4-a` — mandatory node A

- Operator label: `rpi4-1`.
- Host-access identity: required in an owner-controlled binding outside this
  sanitized repository record.
- Root filesystem: 14,788,661,248 bytes total; 10,640,924,672 bytes available
  at inspection.
- Candidate role: mandatory Event participant and direct peer of `cm4-b`.
- Candidate traffic: not started by this inventory activity.

### `cm4-b` — mandatory node B

- Operator label: `rpi4-2`.
- Host-access identity: required in an owner-controlled binding outside this
  sanitized repository record.
- Root filesystem: 14,788,661,248 bytes total; 10,640,969,728 bytes available
  at inspection.
- Candidate role: mandatory Event participant and direct peer of `cm4-a`.
- Candidate traffic: not started by this inventory activity.

### `cm4-spare` — declared support node

- Operator label: `rpi4-3`.
- Host-access identity: required in an owner-controlled binding outside this
  sanitized repository record.
- Root filesystem: 14,788,661,248 bytes total; 10,657,460,224 bytes available
  at inspection.
- Declared role: `spare` only.
- Affected scenario IDs: none.
- Candidate traffic: prohibited until the inventory first names its exact
  role; only scenario runs made after that revision may support the candidate.

The observed root-filesystem free space is numerically greater than 256 MiB on
all devices. This is not the profile's initial-free-local-state preflight: that
condition remains unassessed until the package is installed, the exact state
path is configured, and the unchanged G3 artifact is installed. G4 and G5 must
measure free state space on that bound path at scenario start.

## Network boundary

The inspection path was an operator-controlled ZeroTier IPv4 overlay. Each
node had a distinct overlay address and a direct route for the overlay subnet;
the underlying default route used WLAN. This observation does not approve or
bind the carrier conditions for a candidate run. Exact interface names,
interface addresses, WLAN addresses, gateway addresses, and device serials are
intentionally omitted from this repository record.

This inventory makes no minimum bandwidth, latency, packet-loss, NAT,
Internet-reachability, or relay claim. Intermittent SSH setup latency was
observed. G4 and G5 require a separately frozen sanitized network-condition
record and the canonical digest of the exact operator-provided carrier-address
and peer-identity bindings used by the candidate.

## Inspection method and exclusions

The producer inspected only read-only host facts using `hostnamectl`,
`/etc/os-release`, `/etc/rpi-issue`, `/boot/firmware/issue.txt`, `uname`,
`dpkg-query`, `systemd-creds --version`, `/proc/device-tree/model`,
`/proc/cpuinfo`, `findmnt`, `lsblk`, `df`, `free`, `nproc`, `ip address`, and
`ip route`. SSH host keys were verified locally with `ssh-keygen`.

No software, package, configuration, credential, service, firewall, route,
state directory, or device identity was changed. No password, bearer token,
private key, SSH host-key fingerprint, device serial, machine ID, boot ID,
interface name, carrier address, WLAN address, gateway address, mission
identity, or raw command log is retained here.

## Frozen boundary and limitations

[Decision 0043](../../decisions/0043-authorize-linux-event-mvp-validation.md)
accepts this sanitized two-node inventory and the non-participating spare for
the bounded MVP increment. No additional approval is required. Run-specific
artifact, peer, network, state-path, and result facts remain evidence rather
than inventory fields.

This freeze does not qualify the package, carrier, scenarios, resource
thresholds, or production use. Those claims remain limited to the observations
actually recorded for the installed CI package.
