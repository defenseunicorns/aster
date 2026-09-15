#

# systemd 257 credential-presentation amendment

- Date: 2026-09-09
- Provider contract: `aster-systemd-credential-store/v2`
- Scope: exact Raspberry Pi MVP evaluation profile only
- Product disposition: approved for implementation and device validation
- Candidate disposition: Security and Deployment role approval still required

## Problem

The approved D06 v2 design assumed that systemd would present an encrypted
service credential as a service-owned mode-`0400` file on `ramfs`. On the exact
profile target—Raspberry Pi reference 2026-06-18, Debian 13 `trixie`, systemd
`257.13-1~deb13u1`, physical CM4 Rev 1.1, `aarch64`—PID 1 instead presents the
credential as root-owned mode `0440` on a per-service read-only `tmpfs` mount.
Access for the non-root service UID is granted by an exact POSIX ACL, and the
tmpfs is mounted with `noswap`.

Rejecting that presentation prevents the otherwise approved provider from
starting on the selected MVP hardware. Accepting arbitrary root-readable files
or generic `tmpfs` would broaden the trust boundary beyond the profile.

## Selected compatibility boundary

The runtime loader retains the original presentation and additionally accepts
one pinned systemd 257 presentation.

The original presentation remains:

- regular, single-link credential file;
- owned by the effective service UID;
- exact mode `0400`; and
- Linux `ramfs`.

The additional presentation requires all of the following:

- the service runs as a non-root UID;
- `CREDENTIALS_DIRECTORY` is exactly one non-empty `*.service` child beneath
  `/run/credentials`, with no space or backslash in the child name;
- the credential directory is root-owned/root-group mode `0550` with the exact
  POSIX ACL: owner `r-x`, one named service-UID entry `r-x`, group none, mask
  `r-x`, other none;
- `aster-provisioning.bundle` is a regular, single-link, root-owned/root-group
  mode-`0440` file with the exact POSIX ACL: owner read, one named service-UID
  entry read, group none, mask read, other none;
- the descriptor reports Linux `tmpfs` and `fstatvfs` reports read-only,
  `nosuid`, `nodev`, and `noexec`;
- `/proc/self/mountinfo` contains exactly one record for that mount point, as
  `tmpfs`, with
  per-mount options `ro,nosuid,nodev,noexec,nosymfollow` and the `noswap`
  superblock option; and
- file metadata, filesystem identity, mount flags, and ACL are checked before
  and after the bounded read. Directory identity, directory ACL, and the exact
  mount record are checked before the credential is opened.

The underlying tmpfs superblock may report `rw`; the security property is the
read-only per-service mount plus `noswap`, not a read-only superblock.

Every mismatch fails closed through the existing sanitized provider error
taxonomy. There is no fallback to another credential directory, ordinary
file, arbitrary ACL, arbitrary `tmpfs`, plaintext provider, or runtime-selected
backend.

## Claim boundary

`systemd-creds list` labels the observed mode-`0440` credential `insecure`
because it does not match systemd's older mode-`0400` heuristic. Aster does not
rename or inherit that upstream classification. This amendment qualifies only
the exact independently checked access, mount, and no-swap properties above
for the named non-production MVP profile.

This is not generic Debian, Raspberry Pi OS, systemd, `tmpfs`, or production
support. Any image, systemd version, unit-name shape, ACL encoding, mount
presentation, service UID model, or broader platform requirement must fail
closed and reopen D06 for a redesigned and versioned provider boundary.

## Validation evidence required

Candidate evidence must bind the original approved D06 design and this
amendment, then demonstrate on both mandatory physical CM4 nodes:

- exact file, directory, ACL, filesystem, and mount predicates;
- successful encrypted-credential startup and restart as the non-root service
  UID;
- failure for missing, corrupt, widened, or mismatched presentations; and
- the existing install, rotate, backup, recover, and destroy lifecycle without
  plaintext exposure.

The 2026-09-09 engineering spike exercised the exact systemd 257 presentation
on three physical CM4 nodes and completed the provider lifecycle on the support
node. That is implementation evidence only. It is not the signed G3/G4 annex,
native-package evidence, or a substitute for Security and Deployment approval.

## Required approvals

Before E01 or candidate qualification can pass, the Security and Deployment
roles must approve the immutable digest of this amendment together with the
original D06 design. If either role rejects the systemd 257 ACL/tmpfs boundary
or requires support outside the exact profile, D06 must be reopened and the
provider redesigned; the implementation must not silently widen acceptance.
