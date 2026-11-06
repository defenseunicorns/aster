# Linux BTLE Clean-Restart Hardening Design

**Status:** approved for implementation by the owner on 2026-11-06

**Parent designs:**
`2026-11-03-production-btle-design.md` and
`2026-11-05-linux-btle-unattended-lifecycle-design.md`

## Intent

Close the known Ring-1 clean process-restart gap without changing semantic v9,
the ordered-contact contract, application APIs, or transport selection. Keep
all Linux/BlueZ lifecycle behavior inside `aster-ble-linux`; `aster-node`
continues to observe only contact admission and coarse carrier availability.

The retained CM4 run showed that both Aster processes and their L2CAP channels
stopped cleanly while BlueZ 5.82 continued to report the unpaired peer ACL as
connected. Fresh processes reached `Available`, but contact opens timed out
until one controller entered a new power epoch. The first implementation step
is therefore evidence-preserving diagnosis, not an assumed BlueZ disconnect.

## Goals

- Refactor the Linux carrier I/O and lifecycle code into smaller ownership
  units without changing behavior.
- Retain a closed, sanitized diagnostic that distinguishes controller
  availability, socket open, connected L2CAP channel shutdown, and a BlueZ
  peer ACL that remains connected after the owned channel is drained.
- Reproduce the clean-restart failure on the exact available CM4 stack and bind
  the failure to one component boundary before implementing recovery.
- Implement the narrowest adapter-local recovery supported by that evidence.
- Prove clean stop, immediate process restart, zero-work authenticated contact,
  durable deduplication, and application receipt without controller power
  mutation.
- Re-run the existing Linux/Linux Event path and the foreground Android/Linux
  Event path after the change.

## Safety and ownership constraints

- No controller power toggle, adapter reset, device removal, pairing, trust
  mutation, or mission/protocol change.
- Do not call BlueZ `Device1.Disconnect()` as a generic cleanup primitive. It
  disconnects every profile for the peer and may disable future inbound LE
  connections for an untrusted device until `Connect()` is called.
- Do not add a generic transport lifecycle abstraction. Any recovery mechanism
  remains private to the Linux BTLE adapter.
- A peer-wide or controller-wide action is permitted only after a separately
  reviewed explicit exclusive-ownership configuration and evidence that the
  action restores, rather than suppresses, subsequent inbound and outbound
  L2CAP contacts. This increment does not assume that authority.
- Failure to recover remains a sanitized unavailable/retryable carrier result;
  durable publication and general node readiness remain unaffected.
- All waits, probes, retries, descriptors, tasks, and retained diagnostic data
  remain bounded by the existing Ring-1 limits.

## Selected approach

1. Split stream/MTU adaptation and platform-open responsibilities out of the
   crate root. Preserve public types and behavior.
2. Add an injected Linux peer-link observation seam used only for diagnostics
   and deterministic tests. It reports `absent`, `disconnected`, or
   `connected`; it grants no mission authority and retains no address.
3. Record the peer-link state after the owned ordered contact and L2CAP stream
   have drained. On restart failure, retain the transition sequence and exact
   closed error category.
4. Use a pre-fix physical reproduction to select one minimal recovery change.
   Prefer correct socket/channel teardown or reuse of the existing ACL. If the
   platform exposes only peer-wide destructive control, keep the limitation
   explicit rather than hiding it behind an unsafe reset.
5. Add the recovery regression first, implement the proven change, then run
   the focused portable suite and physical Linux/Linux and Android/Linux
   validation.

## Non-goals

- Discovery, pairing workflow, dynamic role selection, multiple peers or
  controllers, State/Record/Blob execution, daemon packaging, public status
  APIs, multi-carrier selection, IP fallback, or production authorization.
- Crash or power-loss recovery; this increment targets a cleanly drained
  process restart.
- Promoting one CM4/controller result into a general Linux support row.

## Acceptance

- Existing fixed-role, unattended-lifecycle, cancellation, framing, MTU, and
  Android tests remain green.
- Deterministic tests prove observation does not overlap contact ownership,
  leaks no locator, and cannot mutate controller or peer state.
- Two cleanly stopped CM4 evaluators restart immediately and complete a
  zero-work authenticated contact without a controller power epoch change.
- The receiver still exposes exactly the original Event after restart.
- Pixel 9 Pro XL and the Linux reference complete the existing foreground
  semantic-v9 Event validation, or the exact platform blocker is retained
  without broadening the claim.
- Evidence records exact source, binaries, platform/controller versions,
  lifecycle transitions, resource snapshots, and cleanup, with credentials,
  addresses, and mission identities excluded.
