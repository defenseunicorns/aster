# ARM64 package contract — revised for independent and owner review

****

**Disposition: PROPOSAL — NOT adopted, implemented, frozen, signed, or qualified.** This document grants no package implementation/build/install, protected operation, owner approval, qualification, or release authority. All PKG-D01–PKG-D12 selections remain pending.

> **Publication adaptation — independent review pending.** The reviewed research source has SHA-256 `82fe79cd51d5944d093881e4c3b3778ca430903b4d245d139c214680826e673b`; its independent review is a source PASS, not approval of these adapted bytes or owner adoption. The contract body and immutable citations retain the historical M/P/V snapshot below, not a current-main compatibility claim. References to “current main,” “open,” “P-only,” or unmerged #19/#21 in that historical body describe that snapshot only.
>
> At publication preparation, exact main was `814e549ddcbf5bc6288ec02d4bf72bca01d9692a`: [package PR #21](https://github.com/edgesoftops/astertech/pull/21) had merged as `96700b53732848327edfe7294396f47221348580`, and [validator PR #19](https://github.com/edgesoftops/astertech/pull/19) had merged as that main commit. Their later source changes have not been folded into the reviewed contract. Integration prerequisites mentioning these PRs are historical, not instructions to duplicate their implementations. Before adopting or implementing this proposal, reconcile the resulting source with the current accepted profile and accountable owners. Publication does not change requirements credit, E01/D15 status, G2/G3, or native Debian 13/physical-CM4 qualification.

## 1. Authority, exact sources, and changed checkpoint

The original contract (`MVP_ARM64_PACKAGE_CONTRACT_DRAFT.md`), independent review (`MVP_ARM64_PACKAGE_CONTRACT_REVIEW.md`), meeting baseline (`MVP_RELEASE_ACTION_PLAN.md`), and remaining-action audit (`MVP_RELEASE_REMAINING_ACTIONS.md`) are separately retained research records, not files shipped with this repository proposal, and remain unchanged. This document is a proposed overlay, not a replacement of their historical evidence or the requirements baseline. Current governing repository policy and accepted profile control; a branch document, author report, or recommendation is not owner approval.[1][2][9]

Source snapshot obtained **2026-09-14T14:07:07Z**:

| Alias | Exact identity | Meaning |
|---|---|---|
| M | `f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c` | Fresh remote main; PR #20 merged at this commit |
| P | `12089da69b5c18db63fdf48304c3a84522bcf038` | `feature/P0-3-deb-package`, open PR #21; 9 ahead / 2 behind M at snapshot |
| V | `51846f28c746c5719543f43d11a30f26d239a42a` | Open PR #19 initial qualification-receipt validator |

These supersede the supplied checkpoint `3ee3337a6bd78d62a9ed772d6651b4c41d378dc7` / `b3a8f68772c4bb8e20543716e2b946ba049c3db9` and the original draft's still older source identities. **There is now a package PR: #21.** Coordinate that owner, not a duplicate implementation. At the retained check readback, #21 CI run `34850765910` was in progress, not green; #19 returned successful checks from `34770451087`, but those do not establish compatibility with newly advanced M. PR #20 merged at `2026-09-14T13:48:29Z`; its head remains `5d39d9e44e7ba75aa708f905dc950bd36deb9ad3`, with successful checks from `34834555291`. Remote metadata receipts are retained in the evidence directory, not inferred from branch prose.

P still explicitly builds **Ubuntu 24.04**, not native Debian 13/CM4. Its `.deb` now excludes documentation, examples, SBOMs, and build metadata. Three binary SBOMs and post-strip binary checksums are external `target/deb-metadata` outputs. Its example now **includes** required `storage.operations`; the old omission finding is historical. It still omits tightened `limits`, so it is not the final profile configuration.[31][37][41]

P's new September 14 observation reports native Ubuntu ARM64 build/protected-service/Compose and same-runtime version-transition results, with source baseline `9760102` plus working-tree changes. This is **author-reported bounded evidence**, not independently replayed here, not exact-P final-byte attestation, and not Debian 13/physical CM4 qualification. The older amd64 receipt and removed-wrapper results are also historical. Do not say native ARM64 work is wholly absent, and do not transfer it to G3.[44][50]

The Compose controller installs a supplied package, requires matching Docker daemon/package architecture, and uses an unprotected reference test path without booted systemd. It is not the protected provider or package-unit acceptance lane. No emulated ARM64, amd64, container, or Ubuntu result can close the selected native Debian 13 G3 or both-CM4 G4/G5 gates.[46][51]

**Status vocabulary:** Established = current profile/code fact, not execution success. Branch-existing = P-only reusable source or explicitly attributed report. Proposed = concrete conditional clause awaiting the identified owners. Blocked = missing decision/integration/execution receipt, not a failed test. Every new normative package clause below is **conditional on owner adoption**; already accepted profile/provider requirements remain mandatory independently of this draft.

Repository work remains subject to the current `AGENTS.md` and `CONTRIBUTING.md`. Historical source citations below are not substitutes for the required fresh governing-source check.[1][2]

## 2. Target and source-integration contract

**Established target:** one native `arm64` `.deb`, `aarch64-unknown-linux-gnu`; physical Raspberry Pi Compute Module 4 Rev 1.1, Raspberry Pi reference image `2026-06-18`, Debian GNU/Linux 13 `trixie`, kernel `6.18.39+rpt-rpi-v8`, systemd package `257.13-1~deb13u1`, local ext4 and `/usr/bin/systemd-creds`, no TPM2. Bind exact installed OS package identity in the annex; the loader's metadata predicates are not an OS-version allowlist. The profile is the 48-hour, Event-only, one-scope non-production evaluation, not general Debian/Ubuntu support.[9][10][20]

**Proposed source route (PKG-D01/PKG-D08):** coordinate the package owner on #21, review/integrate its accepted work, then a separately scoped Debian-13-native increment from refreshed main. If a stack is chosen, explicitly approve its base/dependency and review split; it is not merge-independent. Preserve Ubuntu version/dependency/evidence claims separately. Do not copy P into a competing package PR, relabel an Ubuntu archive, edit another worker's worktree, or assume #21 is merged. Refresh branch/PR/head before implementation and after integration; rebind all candidate-affecting files to the resulting reviewed source.

Build environment selection is an unresolved owner prerequisite, not a discovered available service. The native route must provide a clean Debian 13 ARM64 build host/image, actual host/target architecture agreement, admitted input snapshot/cache, exact toolchain and OS packages, resource availability, and retained build/archive receipt. Cross-compilation/QEMU can be separately labeled development diagnostics but cannot silently replace the native selected route. No native environment was provisioned or verified in this task.

## 3. Payload and authenticated companion proposal — F01 resolved in wording

**F01 exact prohibition:** delivery MUST exclude `aster-agent-acceptance-fixture`, the `acceptance-test-provider` feature in delivered runtime artifacts, test provisioning, test tokens, generated acceptance secrets, mission material, operational state, and private credentials. Do **not** prohibit all acceptance executables. The required generated-Go **black-box client executable and source are permitted and mandatory** in the selected candidate handoff; they are not the provider-bypass fixture.[9][17][25]

The service uses `aster-agent --config`, statically composing `SystemdCredentialLoader`, never a runtime-selectable provider. This is static provider composition, not a promise of fully static ELF linkage. P builds explicit `aster`, `aster-agent`, and `aster-credential-admin` with package-default features, not `--all-features` or nearby discovery. Development CLI surfaces remain compiled in the current agent; selecting `--config` does not remove them. PKG-D07 must accept the permitted command surface or request a separately reviewed source change.[17][18][37]

### 3.1 Recommended concrete layout — not an approved choice

Recommendation: retain P's minimal service `.deb` and deliver a **mandatory authenticated same-candidate companion**, not optional web links. This minimizes churn while satisfying the profile's complete handoff requirement. Owners must explicitly accept this interpretation of “candidate contains”; otherwise choose the embedded alternative before G2.[9][34][45]

| Surface | Proposed contents and location | Verification / ownership |
|---|---|---|
| Native `.deb` | `/usr/bin/aster-agent`, `/usr/sbin/aster-credential-admin`, proposed retained `/usr/bin/aster`; package unit and maintainer scripts; empty agreed namespace directories | Deployment/Release; full archive manifest, actual ELF machine/loader/shared dependencies, modes/owner roles, no active config or private material |
| Companion `clients/rust/` | Rust reference-client source, exact build/run instructions and API examples from selected G2 | API owner; include manifests/locks and all required referenced source or digest-bound source archive, generator/tool inputs and notices |
| Companion `clients/go/` | Generated Go source, module locks/generation instructions and black-box client source; native ARM64 `bin/agent-smoke` built from `conformance/agent-go/cmd/agent-smoke` | API/Integration; source/executable/input hashes; prove client uses installed protected service, not fixture spawning; retain client dependencies/SBOM and notices |
| Companion `docs/` | Profile, completed annex references, exact install/maintenance/runbook, strict non-operational example, health/capacity/ReceiveOnly/retry/backup/recovery/escalation/limitations guides | Deployment/Profile; offline navigable, no dangling repository-relative links or unpublished path assumptions |
| Companion `metadata/` | Per-delivered-executable SBOMs/graphs, complete licenses/notices, source/recipe/unit/script/config-example hashes, environment/input manifests, provenance, `.buildinfo`, `.changes`, reproduction procedure and deterministic input/content manifests (not the actual comparison receipt) | Release/Dependency-license; actual completeness, not merely a valid Cargo schema |
| External two-build comparison receipt | Both builds' final unsigned `.deb` and complete companion digests, comparison results and difference disposition | Release; outside both compared archives; neither archive embeds the receipt or its digest; receipt contains no future release manifest, signature or their digests |
| External `release-manifest.json` and detached signature | Exact selected final `.deb`, companion and detached comparison receipt digests, source G2, profile/version and approved verification bindings | Release/Security; public trust method and fingerprint distribution selected by PKG-D08; no private key handling in this task |
| Later qualification evidence index | G4/G5 receipts and detached decisions referencing G2/G3 | Integration/Release; keep later receipts outside already immutable G3; append a new authenticated evidence index rather than rewriting the package/companion |

Proposed directory names above are candidate layout choices, not existing repository paths. The package name `aster` follows P; exact Debian version/profile discriminator, companion filename/version, packaging licenses and retention location require PKG-D08. If `aster` moves to a separate operator artifact under PKG-D07, it must be equally authenticated and manifest-bound, and absent from the `.deb` allowlist by design—not silently dropped.

**Alternative:** embed clients/docs/metadata in agreed package paths (for example a package-owned documentation tree and libexec client). This requires deliberately changing P's install rules and archive tests, proving distribution includes mandatory notices despite image doc-exclusion settings, and avoiding circular package hashing. It is not currently implemented. Both choices require the same client, source, provenance, and offline documentation completeness; “download it later from main” is not acceptable.

**Conditional payload acceptance:** validate the union of `.deb` + companion, including absent/extra/duplicate entries and unsafe archive paths/links. Reject the exact fixture/feature/material above; positively require the Go black-box executable/source and Rust handoff in the selected surface. Wrong/missing companion, foreign-source client, altered executable, incomplete notice set, or mismatched manifest must fail. The existing P archive checker only checks selected payload/ELF/modes plus external three-root SBOMs/checksums; it does not establish this complete allowlist, full license admission, authenticity, or native CM4 conformance.[49]

## 4. Fixed paths, identity, ownership, and current configuration

The two provider roots and runtime credential name are established; package account, handoff/config/state paths and modes below are **proposed for Debian** by reuse of P. Numeric UID/GID are allocated on the target and annexed, not imported from a VM. Validate existing identities and secure ancestry; reject unexplained trees instead of recursively chowning or repairing them.[13][22][35]

| Path / identity | Conditional contract | Retention / writer |
|---|---|---|
| `aster:aster` | Static non-root system account; disabled login; home `/var/lib/aster-agent`; validate UID/GID/name/home/shell/group membership and no unintended privilege | Preserve account/UID after remove/purge; no DynamicUser or UID recycling |
| `/etc/aster`, `/var/lib/aster` | `root:root`, `0755`, non-symlink protected ancestry | Package namespace; no recursive repair of unknown descendants |
| `/etc/aster/provisioning` | Established `root:root`, `0700`, local ext4 | Provider ciphertext/generation slots; not service traversable |
| `/var/lib/aster/provisioning-systemd` | Established `root:root`, `0700`, local ext4 | Provider bindings/ledger/intents/lock; never reset for install success |
| `/etc/aster/provisioning/active/credential.cred` | Root-only internal encrypted file; PID 1 load source | Never copy plaintext to work around loader checks |
| `/etc/aster/provisioning/active/reference` | Root-only provider-internal reference | Never configure as service `mission_secret_ref_file` |
| `/etc/aster/agent-credentials` | `root:aster`, `0750`; service cannot mutate directory entries | Operator-only atomic publication; service view read-only |
| `.../client-token`, `.../mission-reference` | At exact paths below that directory; `aster:aster`, `0600`; reference contains decoded canonical bytes, not hex text | Keep across same-artifact reinstall; no data in public evidence |
| `/etc/aster/agent.json` | `root:aster`, `0640`, strict schema v1, validated staged replacement | Operator supplied, not active package payload; keep unchanged on reinstall |
| `/var/lib/aster-agent` | `aster:aster`, `0700`; exclusively owned durable node state | Preserve carrier identity, Events, permanent active/retired/reverse operation records, subscription/delivery/ACK state, controls and peer bindings |
| `/run/credentials/aster-agent.service/aster-provisioning.bundle` | PID-1 runtime presentation; exact loader predicates in §5 | Not payload or persistent backup; never create/decrypt manually |
| Executables and unit | Root-owned, service non-writable; executables `0755`, no setuid/file capabilities; actual target unit path from archive | Package-managed; admin authorization remains root/code/procedure, not pathname alone |
| Logs | Sanitized journal categories; no service-writable log tree by default | Deployment defines retention/access; a requested file-log tree requires separate ownership/rotation decision |
| Backup/operation custody | Protected external operator storage, actual path/durability/custodian selected by PKG-D06 | No implicit host-key initialization/replacement/deletion; no private backup or operation IDs in companion |

P's `postinst` checks some account/ancestry properties and sets directory modes, but does not prove the entire proposed account/group/race-resistant traversal contract. `prerm` calls service stop, not full process/start-job exclusion. The package includes no operational config, and the new example remains in source rather than being installed.[31][35][36]

### 4.1 Required profile configuration and capacity policy

Current main requires an explicit `storage.operations` object with all three fields; `config.rs:339–353,534–544` deserializes it without defaults and passes it to `EventOperationLimits`. P's current example satisfies this particular requirement. Its missing `limits` object defaults to broader generic ceilings, so the final CM4 example/config must add the profile tightening rather than reuse P verbatim.[12][15][31]

| Setting | Established profile value / constraint |
|---|---|
| `storage.max_items` | `10000` aggregate logical tracked rows |
| `storage.max_payload_bytes` | `67108864` aggregate logical tracked bytes |
| `storage.operations.max_records` | `1000000` permanent ledger records |
| `storage.operations.max_logical_bytes` | `201326592` logical ledger/reverse-index bytes |
| `storage.operations.emergency_reserve` | `10000` records |
| `limits.max_connections` | Explicit `1` |
| `limits.max_in_flight_requests` | Explicit at most `8`, node-global |
| Peers/application/scenario | At most 19 configured peers, one intended local client; exact peer/mission/path commitments, no discovery |
| Harness bounds | Query/gap/delivery pages 16, scans 128, at most 256 unacknowledged deliveries, Event payload 0–65536 bytes |

These are profile constraints, not a new generic-schema patch. The harness owns bounds not already enforced by the API; generic `--check-config` alone does not attest profile conformance.[9][12]

**Capacity:** warning becomes actionable no later than **512** distinct operations. At **1,024** distinct accepted keys over the state lifetime, operator/harness stops new publication and ends the v0.1 claim. **1,024 is not runtime hard rejection.** Actual ledger admission ceilings and reserved headroom are separate; ledger exhaustion produces terminal `ResourceExhausted` / `PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED`, no key substitution. Exact active retry returns the original result without growth, retired retry remains `ExpiredOrRetired`/mapped missing-durable-object classification, changed intent conflicts. Permanent fences are never recycled. Aggregate store exhaustion is separately diagnosed.[9][12][23]

Status must retain total/active/retired/reverse counts, logical bytes, configured limits, ordinary/emergency headroom, profile headroom/warning/exhaustion, bounded rate estimate and audit state. A complete healthy ledger audit is required; its presence is not million-operation qualification. Physical amplification/RSS/free-space measurements remain required beyond logical quota arithmetic.[9][16][23]

The preserved meeting baseline line 81 still requests distinguishable hard rejection at 1,024. PKG-D10 asks the existing capacity/profile owner to record reconciliation with the accepted profile—not to invent another unresolved implementation limit or edit that baseline. Main's runbook correction has now merged through #20; do not redo it or the original register work.[10][14]

## 5. Unit, readiness, namespace, and protected presentation

Reuse P's unit as a **review input**, not an approved CM4 service: `Type=exec`, `User=aster`, `Group=aster`, `UMask=0077`, state directory, config check and config runtime, exact encrypted load, SIGHUP reload, `KillMode=control-group`, SIGTERM and no automatic package activation. `Type=exec` is executable launch, **not Ready**. Config validation does not load provider/open state/listeners; PID-1 load may fail even before `ExecStartPre`.[12][32]

Proposed retained controls: `NoNewPrivileges=yes`, empty capability/ambient sets, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, kernel/control-group protection, `LimitCORE=0`, `RestrictRealtime=yes`, `LockPersonality=yes`, address families `AF_UNIX AF_INET AF_INET6 AF_NETLINK`. Do not disable needed route-watch/syscall/mount inspection by checklist. P deliberately sets `RestrictSUIDSGID=no` because of its Ubuntu `openat2` finding; verify exact Debian/systemd filters rather than claiming that exception validated on CM4.[32][45]

**Established presentation, not to be weakened:** non-root effective service UID; `CREDENTIALS_DIRECTORY` exactly one nonempty `*.service` child of `/run/credentials`, no space/backslash/relative/symlink traversal. Directory root UID/GID, `0550`, exact owner/named-service-UID `r-x`, group none, mask `r-x`, other none. Fixed regular single-link root UID/GID credential file `0440`, owner/named-UID read, group none, mask read, other none. tmpfs descriptors, read-only `nosuid,nodev,noexec` flags; exactly matching mount record with per-mount `ro,nosuid,nodev,noexec,nosymfollow` and superblock `noswap`. Superblock `rw` alone does not negate per-service read-only mounting. Directory/mount presentation is classified before file open; bounded credential read checks file metadata/filesystem/flags/ACL before and after. Validate canonical provider/reference/generation/load binding before state/listeners. The separate original secure form remains a regular single-link effective-service-owned `0400` ramfs file. There is no generic tmpfs, plaintext-copy, age/TPM2, old-generation or selectable-provider fallback. Marker-only presentation checks are not protected load/lifecycle proof.[21][27]

**Proposed readiness contract:** record the monotonic service-start boundary, require `/livez` and HTTP 200 `/readyz` plus authenticated bounded `GetStatus` for the intended instance, within **10 seconds from start/restart**, not from a delayed probe loop. Verify expected package/config/generation binding without exposing operational values. On stop, readiness drops before bounded drain; confirm clean termination within **30 seconds**. Clean/terminal/forced exits are 0/1/2. P's 40-second supervisor kill timeout is only a proposed safety ceiling, not a passing 30-second graceful result. PKG-D04 must choose the final margin and total-start budget explicitly.[9][18][32]

Retain for decision P's restart proposal `on-failure`, `RestartSec=5s`, interval 60s, burst 3. Bound failure/restart behavior; do not clear limits repeatedly to manufacture acceptance. Invalid provisioning and failed maintenance must never enter an unattended repair/restart cycle. Distinguish expected refusal, start-limit hit and terminal failure in sanitized receipts.[32][50]

**Namespace remains blocked:** Deployment must supply a dedicated network namespace containing only the agent and intended trusted application, with approved mesh interfaces/routes and shared loopback health/client context. P's unit does not supply it. Host-loopback probes are not qualification; naive `PrivateNetwork=yes` may disconnect both intended application and mesh. Select namespace creation/teardown and start ordering before G2, with no root mesh runtime. Test unauthorized membership, boot/start races, namespace loss, routing and cleanup on the exact target.[12][32]

## 6. Installation, maintenance, exact retry, and durable retention

**Proposed package/operator state machine:** installed/unprovisioned → provisioned/stopped → Ready; any ambiguous administration → stopped/reconciliation required. These labels are not new provider commands. No wrapper or privileged daemon is presumed; prefer the existing human-first handoff unless PKG-D05 authorizes a reviewed helper.[13][43]

| Transition | Conditional requirement and observable acceptance |
|---|---|
| Fresh installation | Authenticate candidate set, verify target and safe account/ancestors; create only empty owned paths; no mission, test token, active config, host-key setup, automatic enable/start. Missing provisioning must fail before Ready. |
| Enter maintenance | Serialize operators and inhibit **every supported start path** (manual, boot, restart policy, package hooks). Stop, then confirm inactive/dead, MainPID=0, ControlPID=0, no pending start/control jobs and no residual unit cgroup processes. If absence/inhibition cannot be confirmed, no provider operation. |
| Install/rotate/backup/recover/destroy | All root-operated and stopped; token reload alone is live. The provider namespace lock does not coordinate a running service. Keep stopped after any nonzero/timeout/interruption until exact reconciliation. |
| Handoff | Privately capture exit+output; invalidate all output on nonzero even after commit. Successful install/rotate must have exactly one complete correct disposition/generation/reference record; reject extra, malformed, noncanonical or truncated output. Decode reference to canonical bytes. |
| Atomic publication | Validate destination ancestry and expected ownership; exclusive/no-follow private staging; reject symlink/hardlink/directory substitutions; set final UID/0600 before publication, fully write+sync, rename+sync parent. Stage matching complete config, validate as service UID, publish likewise. No blind replacement of unexpected existing objects. |
| Split handoff crash | Reference and config are individually atomic, not one transaction. Inhibit starts through both. After crash or ambiguous commit, retain exact IDs/inputs privately and reconcile, never generate replacements, roll back generation, delete ledger or promote staged state. Config check alone cannot prove generation agreement. |
| Rotate → new Active | Exact retry binding; publish new matching reference/load ID; start and prove new-generation Ready before stopping again to destroy Previous. Retry destroy exactly, then restart proving independence from Previous. Second rotation while Previous exists rejects; no fallback. |
| Backup | Stopped service, fresh owner-only versioned staging; accept bytes only after zero exit, sync file and parent, atomically publish, independently read/hash in approved protected storage. Never overwrite sole accepted backup. Durable storage proof is additional to CLI success. |
| Recover | Same host, unchanged host key, intact ledger, exact current Active generation only. Reject wrong/missing ledger, wrong host/key, corruption, Previous/Destroyed, rollback. Retain existing correct handoff/config; recover does not return a new install reference. Lost handoff custody requires approved recovery procedure. |
| Destroy Active | Stopped/absence-confirmed logical destruction and exact retry; controlled negative start must fail before Ready; leave stopped. No implicit reinstall/reprovision, remote-erasure or physical sanitization claim. |
| Bearer reload | Owner-only atomic token replacement and SIGHUP to current instance; new token succeeds, old fails. Invalid replacement retains old authorization/readiness. No mission/peer/ReceiveOnly/limits live reload. |
| Remove/deconfigure | Stop and confirm before removing payload/unit. Retain operator config, token/reference, state, provider ledger/generations/operation bindings, external backups and account/UID. Package removal is not provider destroy. |
| Same-artifact reinstall | Same authenticated `.deb` hash, same config, service UID/GID, current unchanged state/provider/host identity. Replace payload only, explicitly validate/start; prove Events, active/retired/reverse mappings, subscriptions, deliveries/ACK, controls, peer pins and carrier identity survive by semantic reopen—not only a marker file. |
| Purge / new-version transitions | Proposed preserve durable operational data/account with explicit warning; owners may select refusal instead. Neither choice may silently destroy data. Generic upgrade/downgrade is not v0.1 rollback; same-runtime version-transition evidence does not authorize schema-changing upgrade, old binaries or snapshots. |
| Interrupted staging | Preserve ambiguous staged evidence and exact private retry record; report only operation type/time/status/sanitized error. No implemented admin cleanup/inspect command is presumed. Remain stopped and escalate through approved procedure. |

The provider semantics and their exclusions above are established; package interlock, robust handoff and full retention proofs remain proposed integration obligations.[13][22]

**PKG-D04 maintenance decision:** select either an auditable enforced single-operator maintenance context covering all allowed starts, or a reviewed race-safe supervisor/interlock. Recommendation: require an explicit start-inhibition proof and recovery procedure regardless of mechanism; reject a bare `systemctl stop`, an unrelated advisory lock, or a `ConditionPathExists` check as race-free proof. A human-only method is acceptable only if owners can demonstrate actual start-path exclusion, including reboot/failed session recovery; otherwise choose the interlock. No new permanent privileged service by default.

**Authority lane:** provider admin is not mission issuance. `aster control-revoke`/`control-rekey` depend on external protected authority/registry custody. All affected nodes reach the stopped rotation checkpoint before retained nodes restart; prove retained-node new-generation acceptance and removed-node authentication rejection. Local destroy is not revocation or erasure of an uncontrolled host. PKG-D06/PKG-D07 and E09 remain blocked without authorized issuance/custody inputs.[13]

P's current install harness now uses staged, sync/rename handoff and checks the stopped supervisor tuple. The old claim that it only uses first-install reference `O_EXCL`/direct config write is stale. It still does not establish complete adversarial/split-crash/concurrent-start coverage, semantic same-artifact reinstall, or the global ten-second start deadline (its probe loop starts after `systemctl start`). Do not reintroduce the removed wrapper or reimplement already updated handoff merely to satisfy the old review description.[47]

## 7. Build inputs, provenance, signing, and reproducibility

**Conditional G2 source contract:** freeze exact recipes, unit, maintainer scripts, namespace/start-exclusion definitions, safe handoff/runbook, config schema/example, Rust/Go source/build instructions, generators, validators, archive/negative/qualification harness and deterministic build definitions in the reviewed source set. An external clean source requires explicit approval and digest binding. No untracked packaging exception. Freeze explicit feature/target/binary set and all candidate-affecting patches before G2.[9][10]

**Input manifest:** exact G2 and source archive/lockfile hashes; Rust/Cargo `1.97.1`, Go `1.26.7` and selected generator pins; cargo-cyclonedx `0.5.9`, cdx-ev `0.34.0` are existing pins, not complete transitive locks. Bind native Debian image/snapshot digest, debhelper/compiler/linker/binutils/glibc/systemd, all runtime/native/OS packages, Python/tool dependencies, approved proxies/CA trust and offline-cache digests, commands/flags, locale/timezone, timestamp strategy and patches/pedigree. Do not disable TLS verification or acquire private signing inputs. P still leaves OS packages and Python transitive inputs incompletely locked.[25][28][37]

**Runtime dependency proof:** derive `Depends` from actual final ARM64 ELFs, inspect architecture/dynamic loader/resolved libraries for every delivered native executable (including companion client), and bind the qualifying runtime OS inventory separately. Do not import amd64 libc results. Build/test Python or cdx tooling is not automatically a runtime dependency; P does not install a Python provisioning wrapper.[39][43]

**SBOM/license contract:** retain one inventory/graph per delivered Rust executable plus Go client/module and native/toolchain/system inputs. Cargo inventory is overinclusive and not linked-code reachability proof. Include project license, complete third-party notices, native/helper dependencies and any patch source/diff/license records. Bind exact `P0-1-D15` existing approved tuple/disposition/role-approval records to the candidate graph. Reopen only on relevant tuple/graph/SBOM/notice/reachability drift; do not require fictitious D15 reapproval or treat it as a blanket allowlist.[10][24]

**Output order:** compile → deterministic strip/final installed bytes → non-circular internal contents manifests → build both complete unsigned `.deb` + companion sets → compare both final unsigned sets → create detached comparison receipt → external release manifest binding selected archives and comparison receipt → detached signature. Manifest entries must include path, role, type, owner/mode where installed, digest, source/input binding, and explicit missing/not-produced state if incomplete. Hash unit/scripts/client sources/docs/notices/SBOMs too, not just binaries. No artifact contains its own final enclosing archive digest. Neither final archive embeds the comparison receipt or its digest; the receipt contains no future release manifest, signature or their digests. These exclusions also apply to the embedded-layout alternative in §3.1. G4/G5 receipts are created later and bind the immutable G3 identities without rebuilding the companion.

**Reproduction:** two clean independent native builds from identical admitted G2/input set, separate outputs/caches; deterministic order/UID/GID/mode/timestamps/compression/path remapping and SBOM serial/time policy. Compare actual final unsigned package, binaries, complete companion (including all metadata), SBOMs/notices and deterministic manifests. Retain both builds' final archive digests, comparison results and difference disposition in the actual two-build comparison receipt outside both compared archives. Do not compare an earlier companion or exclude any delivered companion member; the receipt is external evidence, not an omitted archive member. Matching binaries alone is only binary reproducibility and cannot satisfy complete-companion reproduction; differences are not hidden. Signature nondeterminism is handled separately by the selected signing procedure. P's working-tree `BUILD.txt` is explicitly not a source attestation.[37][45]

**Authentication remains undecided (PKG-D08):** owners select scheme/tool/version, public trust-root/fingerprint distribution, offline verification command, revocation/expiry/unavailable-trust policy, key custodian and evidence retention. Wrong hash/signature/key or unavailable independent trust must stop installation. Checksums beside a downloaded archive or a GitHub upload are not authentication. No signer command or private key has been invented. G3 requires actual approved authentication, not just `dpkg-buildpackage -b -us -uc`.

## 8. Gates without circular prerequisites

| Stage | Required before starting / closing | Not a prerequisite yet / claim limit |
|---|---|---|
| Contract preparation | Fresh policy, authorized sources, current branch/main/review comparison | No owner decision or package execution needed to produce this proposal |
| Separately authorized development build | PKG-D01 reuse/base + PKG-D02 build-relevant layout + PKG-D08 native admitted development inputs selected; permitted code/build scope; exact source/config/features; native environment accessible | Does not need final G3 signature, G4 hardware receipts, final G5/G6 approvals or a pre-existing G2 release freeze. Production credentials/device operations remain unauthorized. Output is unsigned development evidence only. |
| Service development integration | Explicit authority for protected operations on disposable environment, safe input custody/start inhibition and selected paths/namespace | Not customer deployment; actual E01 candidate acceptance must not be inferred from an engineering experiment |
| G2 source/API freeze | Accepted G1; candidate-affecting source integrated/reviewed; chosen package/client/namespace/handoff/validator/config/build/trust procedures; deterministic source/process gates and failure dispositions; owner selections bound | Final package hashes and later physical receipts do not exist yet; freeze their schema/recipe and prerequisites, not fabricated values. |
| G3 artifact freeze | G2, admitted native build inputs, complete manifests/SBOM/notices/provenance, actual independent reproduction/authentication; actual E01 Security + Deployment records must predate production of the bound G3 artifact; exact D15 binding; accepted artifact/security contract | No demand for completed G4/G5 signatures before building G3. A pre-E01 unsigned development build cannot become G3 through later approval or signing; produce a new bound artifact after actual E01 approvals. Unresolved mandatory inputs mean blocked or partial output, never G3 PASS. |
| G4 focused physical qualification | Actual immutable G3; approved exact annex/device/config/network/scenario bindings and explicit device-operation authority; protected custody/authority procedures; accepted test/harness source | Execute unchanged set on **both mandatory physical CM4 devices**; Ubuntu/native-ARM engineering or structural validator success is insufficient. |
| G5 workload/resource qualification | G4, frozen four workload rows and required resource/threshold interpretation; unchanged G3/config/inventory | Execute full disconnected/reconnection window, retain failures and typed downstream not-run; no silent retries/state replacement. |
| G6 final disposition/handoff | All mandatory receipt/hash/authenticity checks; real role attestations and detached Release issue/refuse/defer decision | No author, validator, date, green CI badge or planning task can approve release. Customer handoff only after authorized issue. |

The accepted serial G1→G2→G3→G4→G5→G6 qualification chain remains unchanged. Development preparation may overlap; qualifying gates do not. Later candidate-affecting source changes require new G2/G3, with affected downstream requalification. Config/provider/device/path changes retain historical receipts but invalidate their use for the changed candidate. Missed dates require honest refusal/deferral, not backdating.[9][10]

E01 still needs both roles to accept **both** exact records: provider design `30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f` and presentation amendment `549ea3fd5bdfd62c01bab5a8f1adac4b84a2710ab406ea006119c9048e28d4cd`, together with contract/trust/admin/lifecycle/limitations/acceptance boundary. Existing profile implementation approval is not E01. No new E01 or D15 approval is asserted here.[10][27][58]

## 9. Acceptance-to-command and evidence matrix

**None of these product/build/device commands was executed for this revision.** Existing commands are source-inspected; future lanes below are acceptance contracts, not invented runnable tools. Exact artifact variables mean previously verified selected paths, never broad globs. CI green applies only to the invoked tests, exact checked-out tree and environment.

### 9.1 Reuse existing entry points

| Lane | Existing command / invocation | Supported evidence boundary and gap |
|---|---|---|
| Main quality | `.github/workflows/ci.yml:98–111` separately invokes `python3 tools/test-aster-agent-process.py`, `mise run check`, `mise run agent-process-smoke` | Main now runs full process contracts and stock smoke; old “not in main CI” statement is obsolete. `mise.toml:14–65` includes Rust workspace, Go tests and generated-source check; fixture smoke is unprotected, not installed D06. Supported signal-safe CI Python is required.[25][26] |
| Go generation | `go -C conformance/agent-go test ./...`; `sh tools/check-agent-go-generated.sh`; build `go -C conformance/agent-go build -o OUTPUT ./cmd/agent-smoke` | Reuse existing generated client, not second server interoperability. Bind native output/inputs to companion and adapt only separately authorized installed-service orchestration.[25][56] |
| Configuration | Installed `aster-agent --check-config "$ASTER_AGENT_CONFIG"` as final UID | Silent zero validates generic config/files without provider/state/listener side effects; final profile and real provider startup remain separate.[12] |
| Ubuntu native package | P ARM manual workflow → `dpkg-buildpackage -b -us -uc` → `debian/rules`/`build.sh` | Existing native Ubuntu ARM64 recipe; refuses Debian 13, not G3. Workflow provisions moving apt/Python transitive inputs; no signature/reproduction gate.[28][41] |
| Actual archive | `python3 tools/test_deb_package.py "$DEB" arm64 "$METADATA"` | External metadata argument is optional (default `target/deb-metadata`); real ELF/checksum/mode assertions, not final client/complete-manifest/authentication proof.[49] |
| Ubuntu install | `sudo bash tools/test-deb-install.sh "$DEB"` | Destructive disposable booted Ubuntu harness, refuses existing deployment, creates test provisioning. NEVER run here or on deployed CM4. Updated atomic handoff but incomplete §6 fault/retention matrix.[47] |
| Supplied-package Compose | `python3 tools/aster_deb_compose.py --deb "$DEB"`; offline controller `python3 tools/test_aster_deb_compose.py` | P `mise.toml` includes controller tests; missing dpkg/Compose cases can skip. Real smoke is separate, requires matching daemon architecture, not PID-1/provider evidence.[48][51][54] |
| Provider admin | Existing five command forms `install`, `rotate`, `backup`, `recover`, `destroy` with exact retained IDs and private descriptors | Full grammar in M operations:95–114; root/stopped authority only. No new `cleanup`, `inspect`, `revoke` or signing command invented.[13] |
| Validator V | `python3 tools/check-linux-event-mvp-qualification.py --bundle-root ROOT --body BODY --index INDEX --decision DECISION [--approval RECORD ...] [--artifact-root ROOT]` | Existing PR #19, not merged/adopted just because green. Structural/profile checks do not authenticate signatures or authorize qualification. Preserve incomplete early-stop/partial-G3 and full mutation-coverage boundaries.[59][60][61] |

V's recorded canonicalization, bounds, exits, workload assignment and nominal-versus-visible memory decisions must be reconciled with actual accountable acceptance and exact schema identity, **not requested again as if no design existed**. Reuse #19; missing-case work is separate. Package acceptance must consume the accepted version/entry point and truthful refusal/defer/not-run semantics, not fork another validator or interpret structurally valid synthetic receipts as physical evidence.[59][60]

### 9.2 Required new or extended lanes — not implemented here

| ID / acceptance | Future execution context and positive/negative oracle | Retained exit / owner |
|---|---|---|
| PKG-A01 native build/archive | Actual admitted Debian 13 ARM64 build; reject host/target/distro/input drift; inspect every ELF, package dependency and archive entry; forbid exact fixture/feature/material while requiring selected client companion | Real dev `.deb` + source/input/output manifests + archive results; Deployment/Release; development only until G3 |
| PKG-A02 namespace/unit/path | Static archive checks plus actual target PID-1 loader; invalid account/group/ancestry/ACL/mount/reference/hardlink/symlink and missing namespace negatives | Exact installed unit/filesystem/presentation and isolation receipts; Deployment/Security |
| PKG-A03 maintenance/handoff | Concurrent supported starts, stop timeout/residual processes, invalid/nonzero/partial output, split rename/crash, ambiguous provider commit and exact retry | No unsafe mutation/Ready, retained private recovery custody with sanitized public result; Deployment/Security |
| PKG-A04 service lifecycle | Start→Ready ≤10s, stop→clean absence ≤30s; readiness-before-drain, forced/second-signal distinctions, restart bounds, failed maintenance inhibition | Instance-bound monotonic times/exit/status, no secret logs; API/Deployment |
| PKG-A05 retain/reinstall | Actual remove/reinstall/purge-selected behavior; unchanged exact artifact/config/current state/provider/UID; semantically reopen Events, mappings/fences, subscriptions/delivery/ACK/control/peer identity | Both-device package-bound continuity receipts, not marker-only; Integration/Deployment |
| PKG-A06 complete provider E09 | Install/retry/load; rotate/retry/new Active; backup/retry/durable readback; corrupt/missing start refusal; recover/retry; Previous/Active destroy/retry, post-destroy failure; interruption and coordinated revoke/rekey/removed-node rejection | Both mandatory devices, same G3; E01 + protected authority/custody prerequisites; Security/Deployment/Integration |
| PKG-A07 clients/API/ReceiveOnly | Rust and delivered Go execute publish/query/subscription/stream/poll/ACK/gaps/recovery; valid/invalid bearer reload; both identity orderings, inbound acceptance/no initiation/no local inventory disclosure; two ReceiveOnly nodes transfer zero Events | Both-node receipts, same config/artifact; no radio-silence/independent-server claim; API/Integration |
| PKG-A08 resource/workloads | Four rows and all thresholds in §10; ledger/audit/store headroom, exact retry/no growth, safe corrupt/missing/unauthorized input; configured saturation isolated outside normal profile workload | Physical per-device measurements, all failures/attempts preserved; Profile/Integration |
| PKG-A09 artifact completeness | Correct/wrong/missing package+companion/client/source/notice/manifest inputs; trusted signature and key/hash negatives; two clean native builds compared | Complete reproducible authenticated G3 set; Release/Dependency-license/Security |
| PKG-A10 exact-profile validator | Integrate accepted V or successor; map each config/workload deviation to positive/negative tests; pre-G3/no-output/partial artifact and downstream not-run cases | Accepted schema/source, deterministic sanitized validation, authentication separately verified; Integration/Profile |

Owners must select actual CLI/workflow names and supported environments when implementing these lanes; no proposed `qualify_cm4_package.py` or other absent script is advertised as runnable. Every implemented lane must have side-effect-aware preflight, bounded timeouts, explicit skip/failure semantics, exact-source invocation chain and persistent receipts. A PASS aggregate cannot close an uncalled lane or skipped mandatory case.

## 10. Mandatory release constraints retained

The meeting plan's ten sections remain covered: source/API freeze (§8), annex/device inventory (§8/§10), native artifact (§3/§7), customer runbook (§3/§6), focused both-CM4 qualification (§9), complete packaged secrets lifecycle (§6/§9), resources (§10), 24-hour workload (§10), final decision (§8), and complete customer handoff (§3). Capacity wording is explicitly reconciled, never silently deleted from the baseline.

Exactly two mandatory physical CM4 nodes participate; bind actual hardware/serial commitments and exact OS/filesystem/storage/network/peer/config/scenario identity through owners. An optional third node carrying candidate traffic must have its role and affected scenarios declared; a support-engineering receipt is not authority to add it. No actual device identity, nominal memory proof, approved path, signature or hardware receipt is invented.[9][11]

The frozen scenario has one mission authority, one scope, one topic and **one durable application subscription per scenario, not one per node**. Require semantic protocol `6`, security profile and full hybrid suite `0x0001`, exactly one offline mission root delegating to one mission signer, distinct provisioned node identities, and no fallback. Preserve source payload protection, mission authentication before inventory, replay rejection and downgrade resistance; carrier trust never substitutes for mission/application authority. Optional relay is one customer-controlled pinned HTTPS origin using explicit DER roots and `direct_preferred`; WebPKI, `relay_only`, public fallback, discovery, ingress/host ports/tunnels and unrelated same-namespace sidecars are outside this profile. Health is status-code-only and detailed status remains authenticated. Record the accepted transport/local-metadata exposure budget and actual packet/log/error inspection reference; do not claim universal metadata hiding or uninspected-surface safety.[9]

G6 retains distinct final Profile/Product, Security, Deployment/OS/Artifact, Integration/Device/Physical-carrier, Event-service/API/Runtime, Deterministic-gate, Dependency/License and Legal/Compliance attestations over one canonical body, followed by the Release owner's detached issue/refuse/defer decision over that body and sorted approval digests. Existing E01/D15 prerequisite records are separate, not substitutes. Authentication of signatures remains a real owner-selected verification step outside V's structural checks.[11][59]

| Required row | Frozen workload and oracle |
|---|---|
| API boundary | One exact Event at each 0-byte, 4-KiB and 64-KiB boundary; durable publication/transfer/query/delivery/ACK |
| Two-node topology | 10 four-KiB Events total at 1 Event/s; direct path and explicit no-relay or one approved pinned-relay disposition; if claimed, relay-loss/direct recovery |
| Offline soak | Both nodes disconnect approved path for 24 hours, each publishes ten four-KiB Events/hour (240 each); intervening restart; end sustained publication, restore path and converge within at most 24 further hours; exact IDs/payloads/deduplication/gaps/order/at-least-once delivery/ACK/peerless reopen |
| Capacity-warning probe | 512 distinct local operations with 4-KiB Event payloads plus one exact retry; actionable warning no later than 512, no retry growth; both-node final accounting/headroom |

Each independent row starts with fresh zero-workload state and retains provisioning controls; do not reset midway to conceal failure. All rows use immutable G3/config/inventory/scenario binding and retain both-node measurements. Source projections do not prove byte fit; record protected-source-object bytes, logical ledger use and actual database/filesystem amplification.[9]

Thresholds on the provider-composed agent: stripped deployed executable ≤16 MiB, steady RSS ≤64 MiB, peak RSS ≤128 MiB, idle CPU ≤5% of one core, functional on one core, Ready ≤10 seconds, graceful stop ≤30 seconds, deployment memory ≥1 GiB, initial free local state ≥256 MiB. Record installed size, active CPU, physical growth/final headroom, Event and operation counts, completed audit and energy; energy has no pass threshold. Reconcile V's nominal hardware-capacity interpretation with owners and actual evidence; kernel-visible memory alone neither proves nominal capacity nor justifies invented automatic failure.[9][59]

No complete four-class/IP+BTLE MVP, State/Record/Blob, automatic discovery, bridged scale, generic impairment floor, million-operation/production sizing, independent server interoperability, FIPS, physical radio silence, cross-host recovery, snapshots, arbitrary downgrade, complete host loss, root/PID-1/kernel compromise resistance, physical erasure or production authorization is claimed. ReceiveOnly permits mandatory response traffic. Qualification remains Event-only within the exact accepted envelope; broader baseline requirements remain separate, not erased.[7][9][13]

## 11. Package-specific decision table — all selections pending

**F02 resolved:** package IDs are `PKG-Dxx`; existing governance keeps full `P0-1-D06`, `P0-1-D08`, `P0-1-D15`, `P0-1-E01` identifiers. “D06 approved” without namespace/digest is insufficient. Role labels identify required responsibilities, not invented named-person assignments. Each owner record must state accept/refuse/defer, chosen option, exact document/source/input digests, conditions and approval reference; no row below records an approval.

| ID | Required owner(s) | Choices and recommendation | Acceptance / consequence while pending |
|---|---|---|---|
| PKG-D01 | Package owner + Deployment + Release | Reuse/integrate #21 then focused Debian increment (recommended), or explicitly authorized stack; no duplicate package branch | Record source/base/review split and responsible maintainer; blocks package implementation start |
| PKG-D02 | Deployment + Security | Adopt §4 static account/fixed paths plus dedicated namespace; otherwise documented reviewed alternative preserving provider predicates | Exact path/account/group/isolation checks and safe existing-host behavior; build-relevant layout before dev build, full deployment boundary before G2 |
| PKG-D03 | Security + Deployment | Supply actual P0-1-E01 acceptance of both immutable records, or refuse/defer | No new design implementation presumed; actual trust/admin/lifecycle acceptance must predate production of the bound G3 artifact, not merely declaration/signing or qualification; no retroactive promotion of pre-E01 development bytes, no invented signatures |
| PKG-D04 | Deployment + API + Security | Enforced single-operator exclusion or reviewed interlock; recommend demonstrable all-start-path inhibition; review restart/timeout proposals | §5/§6 race, stop/readiness/failure receipts and exact budgets; blocks installed integration acceptance/G2 closure |
| PKG-D05 | Deployment + Security | Adapt current direct handoff (recommended), or separately authorize helper | Complete output validation, safe atomic publication, split-crash retry/recovery and failed-start inhibition; no removed-wrapper resurrection by assumption |
| PKG-D06 | Security + mission authority + Deployment | Protected existing host-key/operation/backup custody workflow, or explicitly authorize clean new-host setup | Named custody roles, durable backup store, retained exact retries and staging escalation; no host-key replacement/ledger restore shortcut; blocks protected operational execution |
| PKG-D07 | Mission authority + Security + Release | Retain `aster` in `.deb` provisionally recommended, or authenticated operator companion; explicitly accept supported vs compiled development surfaces | Protected issuance/registry/control procedure plus command allowlist; no E09 revoke/rekey closure without authority |
| PKG-D08 | Release + Deployment + Security + Dependency-license | Native Debian input route, package discriminator/version, full lock/reproduction method, signature/trust scheme and persistent evidence store | Development subset selected before build; reproducibility/source/trust definitions before G2; actual signed complete artifacts only G3. Unavailable environment/trust blocks corresponding stage, not this brief |
| PKG-D09 | Dependency-license + Legal/compliance + Release | Bind existing P0-1-D15 approval to exact candidate graph; reopen only relevant drift | Full selected Rust/Go/native/OS/helper notices/SBOM/reachability review; not blanket approval or automatic D15 reapproval |
| PKG-D10 | Capacity/Profile + Release | Record meeting-plan reconciliation to accepted 512 warning/1,024 operator-stop policy (recommended); literal hard rejection would be a new explicit profile/product change | Preserve original plan; no silent hard-1024 baseline or million-operation claim. Bind resource/memory interpretation before physical qualification |
| PKG-D11 | Deployment + Security + Profile | Preserve state/account on purge with warning (recommended), or refuse purge | Observable exact-artifact reinstall and semantic-state retention; generic upgrade/downgrade remains unqualified |
| PKG-D12 | API + Integration/Profile + Release + Dependency-license | Minimal `.deb` + mandatory authenticated companion (§3 recommendation), or embedded client/docs/metadata | Require Go black-box executable/source + Rust instructions/notices/hashes; decide V integration/schema/coverage without duplicating #19; offline complete handoff and positive/negative payload gates before G2/G3 |

**Smallest decision request:** PKG-D01 + build-relevant PKG-D02 + development subset PKG-D08 + PKG-D12 layout. Once separately accepted and implementation/build authorized, the smallest next increment must produce a real native Debian ARM64 development archive with actual archive verification. E01/maintenance/authority/reproduction/signing/device gates remain explicit downstream blockers, not prerequisites for merely drafting or inspecting an unsigned development archive.

## 12. Change trace and independent-review request

**F03 correction trace:** reproduction procedures are separated from the actual detached comparison receipt in §§3/7, with full-companion reproduction retained. The two review clarifications are explicit in §10 (4-KiB capacity payload) and §§8/11 (E01 before artifact production). The research source received independent exact-digest source review; this repository adaptation requires its own independent exact-digest review. No source-review PASS is owner adoption, and all decisions remain pending.

| Original input / finding | Revised destination | Disposition |
|---|---|---|
| Draft §§1/11/12 stale main/package/PR inventory | §1/§2 | Resolved factual refresh; #21 reuse and #20 merge recognized; exact heads and CI limits retained |
| Review F01, draft lines 52/181/225/250 | §3/PKG-D12/PKG-A01 | Wording resolved; exact provider-fixture ban and required Go positive inclusion. Layout remains proposed, owner adoption blocked |
| Review F02, draft local D01–D12 | §11 | Resolved namespace ambiguity with PKG-D01–PKG-D12; existing governance unchanged |
| Draft §3 composition and paths | §3/§4 | Updated for external metadata/no installed docs; ownership/layout remains proposed |
| Draft §4 loader/unit/readiness | §5 | Preserved exact predicates and Type=exec distinction; namespace/systemd acceptance blocked |
| Draft §§5/6 stopped lifecycle/handoff | §6 | Preserved retry/retention/authority; refreshed actual staged P harness. Full maintenance/fault execution blocked |
| Draft §7 outdated main CI and hypothetical validator | §9 | Main process/Go wiring refreshed; actual #19 reused, incomplete validator families explicit |
| Draft §8 source/signing/reproduction | §7/§8 | Preserved completeness; external manifest and later-receipt dependency cycle made explicit; native inputs/trust/actual reproduction blocked |
| Draft §9 owner decisions / capacity ambiguity | §4.1/§11 | Current ledger/profile semantics established, baseline reconciliation still owner action; no approvals invented |
| Draft §10 implementation sequence | §2/§8/§9 | Native dev build separated from G2/G3/G4; only future authorized work, no scaffold or implementation here |
| Draft §§12/13 evidence/handoff | §1/§12 + evidence HANDOFF.md | Fresh manifest/checks; Ukrainian handoff separate; originals preserved |
| Review passed target/static-provider/predicates/path dimensions | §§2–5 | Retained source-grounded constraints; not transferred as runtime PASS |
| Review passed lifecycle/hardening/dependency/gate/evidence dimensions | §§5–9 | Retained; new branch facts distinguished from earlier receipts and source assertions |
| Review blockers: package integration/native route | PKG-D01/08, PKG-A01 | Proposed route; actual selection/build still blocked |
| Review blockers: ownership/namespace/maintenance/authority | PKG-D02–07/11 | Explicit choices/exits; no operator approval or executed proof |
| Review blockers: clients/validator, capacity/memory | PKG-D10/12, §§3/4/9/10 | F01 wording resolved; current choices/design acknowledged; candidate acceptance pending |
| Review blockers: artifact inputs, G3/G4/G5 | §§7–10, PKG-D08/09 | Real authentication/reproduction and both-device receipts absent from this task |
| Every meeting-plan section and four workload rows | §§3/6–10 | Preserved mandatory constraints; no threshold/requirements-credit changes |

Independent publication reviewer: review the exact adapted file and its source-to-candidate patch against the separately retained reviewed-source digest. Verify that the historical checkpoint and citations remain historical; that publication context accurately identifies merged #19/#21 without claiming current compatibility; and that F01, F02, F03, all owner-pending decisions, E01 chronology, workload bounds and nonqualification remain intact. Require separate review for any substantive contract refresh. A source-review PASS does not adopt this contract or close any release gate.

Source manifests, original and independent-review records, source-to-publication mapping, and documentation-check receipts are retained separately by the proposal custodian. They are not included in this repository document and are not product, build, signing, CI, or physical test receipts.

## Sources

[1] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/AGENTS.md — M:AGENTS.md
[2] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/CONTRIBUTING.md — M:CONTRIBUTING.md
[7] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/data-mesh-requirements.md — M:data-mesh-requirements.md
[9] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md — M:docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
[10] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md — M:docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
[11] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md — M:docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
[12] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/reference/aster-agent-config-v1.md — M:docs/reference/aster-agent-config-v1.md
[13] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/implementation/raspberry-pi-provider-v2-operations.md — M:docs/implementation/raspberry-pi-provider-v2-operations.md
[14] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/quickstart/linux-event-mvp-runbook.md — M:docs/quickstart/linux-event-mvp-runbook.md
[15] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/crates/aster-agent/src/config.rs — M:crates/aster-agent/src/config.rs
[16] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/crates/aster-agent/src/event_service.rs — M:crates/aster-agent/src/event_service.rs
[17] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/crates/aster-agent/Cargo.toml — M:crates/aster-agent/Cargo.toml
[18] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/crates/aster-agent/src/main.rs — M:crates/aster-agent/src/main.rs
[20] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/crates/aster-systemd-credentials/README.md — M:crates/aster-systemd-credentials/README.md
[21] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/crates/aster-systemd-credentials/src/lib.rs — M:crates/aster-systemd-credentials/src/lib.rs
[22] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/crates/aster-systemd-credentials/src/admin.rs — M:crates/aster-systemd-credentials/src/admin.rs
[23] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/crates/aster-redb-store/src/event_operation.rs — M:crates/aster-redb-store/src/event_operation.rs
[24] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/release/sbom/README.md — M:docs/release/sbom/README.md
[25] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/mise.toml — M:mise.toml
[26] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/.github/workflows/ci.yml — M:.github/workflows/ci.yml
[27] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/superpowers/specs/2026-09-09-systemd-257-credential-presentation-amendment.md — M:docs/superpowers/specs/2026-09-09-systemd-257-credential-presentation-amendment.md
[28] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/.github/workflows/build-deb-arm64.yml — P:.github/workflows/build-deb-arm64.yml
[31] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/debian/agent.example.json — P:debian/agent.example.json
[32] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/debian/aster.aster-agent.service — P:debian/aster.aster-agent.service
[34] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/debian/aster.install — P:debian/aster.install
[35] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/debian/aster.postinst — P:debian/aster.postinst
[36] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/debian/aster.prerm — P:debian/aster.prerm
[37] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/debian/build.sh — P:debian/build.sh
[39] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/debian/control — P:debian/control
[41] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/debian/rules — P:debian/rules
[43] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/docs/implementation/raspberry-pi-provider-v2-operations.md — P:docs/implementation/raspberry-pi-provider-v2-operations.md
[44] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/docs/release/2026-09-10-deb-observation.md — P:docs/release/2026-09-10-deb-observation.md
[45] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/docs/release/ubuntu-24.04-deb.md — P:docs/release/ubuntu-24.04-deb.md
[46] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/tools/aster_deb_compose.py — P:tools/aster_deb_compose.py
[47] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/tools/test-deb-install.sh — P:tools/test-deb-install.sh
[48] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/tools/test_aster_deb_compose.py — P:tools/test_aster_deb_compose.py
[49] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/tools/test_deb_package.py — P:tools/test_deb_package.py
[50] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/docs/release/2026-09-14-deb-observation.md — P:docs/release/2026-09-14-deb-observation.md
[51] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/docker/deb-test/README.md — P:docker/deb-test/README.md
[54] https://github.com/edgesoftops/astertech/blob/12089da69b5c18db63fdf48304c3a84522bcf038/mise.toml — P:mise.toml
[56] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/conformance/agent-go/cmd/agent-smoke/main.go — M:conformance/agent-go/cmd/agent-smoke/main.go
[58] https://github.com/edgesoftops/astertech/blob/f5ae9051def32cfdaf1688e0258c6f3f2bb00e1c/docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md — M:docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md
[59] https://github.com/edgesoftops/astertech/blob/51846f28c746c5719543f43d11a30f26d239a42a/docs/implementation/linux-event-mvp-qualification-receipt-validator-spec.md — V:docs/implementation/linux-event-mvp-qualification-receipt-validator-spec.md
[60] https://github.com/edgesoftops/astertech/blob/51846f28c746c5719543f43d11a30f26d239a42a/tools/linux_event_mvp_qualification/validator.py — V:tools/linux_event_mvp_qualification/validator.py
[61] https://github.com/edgesoftops/astertech/blob/51846f28c746c5719543f43d11a30f26d239a42a/tools/check-linux-event-mvp-qualification.py — V:tools/check-linux-event-mvp-qualification.py
