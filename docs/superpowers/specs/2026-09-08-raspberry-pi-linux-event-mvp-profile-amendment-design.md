#

# Raspberry Pi Linux Event MVP profile amendment design

- Status: Approved for profile revision
- Approved: 2026-09-08
- Profile: `aster-linux-event-mvp-evaluation-v0.1`
- Decision: [Decision 0042](../../decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md)
- Original design: [Linux Event MVP Evaluation Profile design](2026-09-06-linux-event-mvp-evaluation-profile-design.md)
- Roadmap action: `P0-1 — define the claim boundary`

## Decision summary

Revise the unmerged Linux Event MVP Evaluation Profile v0.1 to qualify the
available Raspberry Pi fleet directly. The required base becomes two physical
Raspberry Pi Compute Module 4 nodes running the exact Raspberry Pi reference
image described below. The third available CM4 is a spare and may be used for
declared failure or recovery testing. `x86_64`, virtual participants, and the
8- and 20-node tiers move outside the v0.1 MVP boundary.

This is a pre-merge revision of v0.1 rather than a new v0.2 profile. No v0.1
candidate has been issued and the profile PR has not merged, so keeping one
version avoids parallel profile definitions and minimizes coordination work.
The original design remains unchanged as the historical record. This amendment
supersedes its conflicting platform, architecture, topology, artifact, D06,
and acceptance sections for v0.1.

The objective is the shortest evidence-backed path to a working,
non-production customer-evaluation MVP. The revision narrows claims; it does
not treat current hardware access or development runs as qualification
evidence.

## Verified starting environment

Read-only inspection on 2026-09-08 found the same environment on all three
available devices:

| Fact | Observed value |
|---|---|
| Image identity | `/etc/rpi-issue`: `Raspberry Pi reference 2026-06-18` |
| Distribution identity | `/etc/os-release`: `Debian GNU/Linux 13 (trixie)`, version `13`, codename `trixie` |
| Hardware | `Raspberry Pi Compute Module 4 Rev 1.1` |
| Architecture | `aarch64` |
| Kernel | `6.18.39+rpt-rpi-v8` |
| systemd package | `257.13-1~deb13u1` |
| Root filesystem | `ext4` |

The candidate annex must inspect and record these facts again from every
participating device. The current observations select the design boundary but
are not retained G4 or G5 receipts. A changed image, distribution release,
hardware model, architecture, systemd interface, filesystem, or kernel is a
candidate change and requires review before qualification continues.

The public profile names this exact image and hardware family. It does not
claim generic Debian 13, generic Raspberry Pi OS, CM5, other Raspberry Pi
models, or later image and kernel revisions.

## Required v0.1 platform boundary

| Dimension | Revised v0.1 requirement |
|---|---|
| Operating system | Raspberry Pi reference image `2026-06-18`, identifying as Debian 13 `trixie` |
| Hardware | Physical Raspberry Pi Compute Module 4 Rev 1.1 |
| Architecture | `aarch64` only |
| Kernel | Exact `6.18.39+rpt-rpi-v8` build, revalidated and frozen in the candidate annex |
| Service manager | systemd `257.13-1~deb13u1`, revalidated and frozen in G3/G4 records |
| Filesystem | Local `ext4` state |
| Package | Native `arm64` `.deb` |
| Isolation | The existing restricted service account, systemd hardening, and local API boundary remain required |

Ubuntu Server 24.04, `x86_64`/`amd64`, CM5, VMs, containers, generic Debian,
generic Raspberry Pi OS, and cross-distribution portability are excluded from
v0.1. They require a later profile revision with their own artifacts and
evidence.

## Topology and device roles

The mandatory qualification topology contains exactly two physical CM4 nodes.
Both run the same frozen G3 artifact and exact profile environment. They must
exchange Events directly over the declared ZeroTier/IP path and exercise both
identity orderings for restart-selected ReceiveOnly behavior.

The third CM4 is support capacity, not a third required participant. It may be
used as:

- a clean replacement or recovery-test target;
- a declared optional relay or path-failure aid when the scenario explicitly
  records it; or
- a spare when either mandatory node is unavailable.

If the third device sends, receives, stores, or relays candidate traffic, the
annex must list it as a participant for that run and record its exact role. Its
results cannot silently widen the required two-node claim. Replacement of a
mandatory node creates a new device inventory and reruns every affected
scenario.

The 8- and 20-node tiers and all virtual-node inventories are deferred. They do
not block this MVP candidate and cannot be claimed from the two-node evidence.

## D06 protected-provider redesign

The Ubuntu-specific `aster-systemd-credential-store/v1` selection is no longer
the v0.1 provider. D06 reopens because the approved v1 design explicitly
required redesign when Debian-family support became part of the profile.

The replacement contract is `aster-systemd-credential-store/v2`, bound only to
the exact Raspberry Pi reference image and systemd 257 interface. A separate
v2 provider design must preserve the useful v1 behavior:

- static provider composition with no runtime provider selection;
- `systemd-creds` plus `LoadCredentialEncrypted=`;
- host-key-backed encryption and explicit refusal of plaintext persistence;
- fixed credential names and paths;
- root-operated `aster-credential-admin` lifecycle operations;
- atomic replacement, restrictive ownership and modes, and fail-closed
  behavior; and
- no secret bytes in local APIs, logs, status, or retained receipts.

Preliminary inspection found `/usr/bin/systemd-creds` and an existing host
credential key on the representative device. G3/G4 must still verify the exact
package, commands, unit behavior, negative paths, and all participating nodes.
TPM2 remains excluded; no hardware-TPM, software-TPM, secure-element, or
production protected-provisioning claim is made.

D06 becomes Resolved only when the v2 design is approved for the revised
profile. Security and Deployment approvals of its exact digest remain candidate
gate E01, followed by unchanged-artifact provider acceptance in G3/G4.

## Artifact and evidence changes

G3 requires one reproducibly built, authenticated native `arm64` `.deb` from
the frozen G2 source. The package still includes the Event service, systemd
units and hardening, v2 provider composition, Rust reference client, generated
Go client plus its black-box acceptance executable/source, SBOM, third-party
notices, provenance, checksums, and signatures.

An `amd64` package is not required and cannot be claimed. Existing
cross-architecture build work remains useful post-MVP but does not block v0.1.

The serial gate meaning becomes:

1. **G1 — Event baseline:** accept the Event service and freeze the ReceiveOnly
   and capacity contract.
2. **G2 — Source/API freeze:** merge the required behavior and freeze one
   source/API commit.
3. **G3 — Artifact freeze:** reproduce and authenticate the one `arm64`
   package with the exact v2 provider and complete manifest.
4. **G4 — Focused target tests:** install the unchanged G3 package on the two
   mandatory CM4 devices and pass lifecycle, Rust/Go API, ReceiveOnly,
   capacity, direct-path, restart, and declared failure/recovery cases.
5. **G5 — Workload qualification:** pass the two-node workload and 24-hour
   disconnected-publication/reconnection scenario using unchanged G3
   artifacts and a frozen device/network inventory.
6. **G6 — Disposition:** issue, refuse, or defer the exact G3 artifact after
   verifying the completed annex, deterministic gate, receipts, approvals, and
   signatures.

All failure paths remain fail closed. Missing hardware, a changed image or
kernel, artifact drift, an undeclared third participant, a failed provider
case, incomplete client coverage, or a shortened soak results in a typed failed
or not-run gate rather than a broader claim.

## Acceptance boundary

The existing Event semantics, offline-first behavior, Rust and Go client
requirements, restart-selected ReceiveOnly contract, capacity/error contract,
resource ceilings, security profile, metadata budget, dependency disposition,
and production exclusions remain unchanged unless the profile revision names a
direct conflict.

For v0.1 issuance, the revised acceptance boundary requires:

- the exact two-node physical CM4 inventory;
- one unchanged, reproducible and authenticated `arm64` G3 artifact;
- the approved v2 protected-provider design and passed E01/G3/G4 checks;
- Rust reference and generated-Go qualification coverage;
- ReceiveOnly in both identity orderings;
- authenticated capacity/headroom and terminal exhaustion behavior;
- restart/reopen and declared failure/recovery behavior;
- the two-node workload and 24-hour disconnected/reconnection scenario;
- exact resource, metadata, dependency, configuration, and receipt checks; and
- final candidate approvals plus a signed G6 `issue` decision.

No `x86_64`, 8-node, 20-node, VM, Ubuntu, CM5, generic Debian, production, or
radio-silence claim follows from passing this boundary.

## Decision and requirement effects

The profile revision changes the resolution text for D02, D03, D06, D09, D12,
and D13 where their prior wording selected Ubuntu, dual architecture, or
2/8/20-node qualification. It updates E01, E02, G3, G4, and G5 exits to the new
provider, artifact, and device boundary.

Atomic requirement statuses and the hash-bound 348-requirement baseline do not
change. In particular, broader node-scale and portability requirements remain
open or out of profile rather than being inferred from the narrow evaluation.
The D15 role approvals remain valid because the exact dependency tuples and
evaluation-only limitation do not change; candidate graph drift still reopens
D15 for the affected candidate. Production `DM-8-05` remains open.

## Documentation implementation

The profile revision will update:

- Decision 0042, recording the accepted pre-merge amendment;
- the normative evaluation profile;
- the decision and gate register;
- the human coordination guide;
- the candidate-annex schema;
- the D06 provider design through a separate v2 design record; and
- PR #3 title/body and review focus.

The original 2026-09-06 profile design and Ubuntu v1 provider design remain
unchanged historical records. New documents link back to them and state the
precise superseded sections so reviewers can reconstruct the decision history.

## Schedule

The target remains an evidence-backed G6 decision before 2026-09-14:

| Date | Fast-path result |
|---:|---|
| 2026-09-08 | Approve this amendment and freeze the exact Raspberry Pi platform boundary |
| 2026-09-09 | Accept G1 and approve the v2 provider design for the profile; complete E01 review as early as possible |
| 2026-09-10 | Freeze G2 and produce the single `arm64` G3 artifact |
| 2026-09-11 | Pass G4 on the two CM4 devices and start the required G5 soak |
| 2026-09-12 | End disconnected publication, reconnect, and review bounded convergence evidence |
| 2026-09-13 | Complete G5 and record the signed G6 `issue`, `refuse`, or `defer` decision |

The dates do not waive gates. Narrowing the boundary removes unnecessary work;
it does not convert missing or failed evidence into a pass.
