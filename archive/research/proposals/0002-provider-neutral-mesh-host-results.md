# Proposal 0002 result: host contract retained; rust-libp2p profile not selected


- Status: completed — provider-neutral contract retained; no provider admitted
- Date: 2026-08-21
- Proposal: [0002 — Provider-neutral mesh host and focused rust-libp2p profile](0002-provider-neutral-mesh-host.md)
- Starting checkpoint: `6d199d8176091360012dd8d5bcca1fd638248f7b`
- Signed experiment checkpoint: `05250eb201cbb57b606ef50d8eb94785db5aae67`
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Decision: [0023 — Retain the mesh-host contract without selecting rust-libp2p](../decisions/0023-mesh-host-contract-no-libp2p-selection.md)

## Outcome

The experiment answered both parts of its question.

First, Aster can define the missing operational lifecycle independently of a
connectivity library. The new deterministic `MeshHost` contract passed every
scheduled contract fixture: bounded candidate and locator state, automatic and
manual provenance, emission-linked discovery, receive-only behavior, Aster
identity binding, fail-closed carrier reuse, expiry, direct/relay policy,
bounded reconnect, contact quanta, and fair opportunity across 100 candidates.

Second, the focused rust-libp2p 0.56.0 integration is **not selected**. It
passed manual peering, discovery suppression, simultaneous contacts, capture
canary scanning, and a relaxed 64 KiB store-forward run. It nevertheless
failed one mandatory clean trial, exceeded the provisional idle-CPU gate,
implemented no NAT/circuit-relay lane, increased rather than reduced Aster
custom code, and retained an unresolved upstream maintenance advisory.

The native profile remains the stronger LAN control. It is not promoted to a
complete production mesh: NAT traversal, connectivity-relay fallback,
address-change recovery through the composed host, deterministic impairment,
and a simple supported user demonstration remain open.

## Exact experiment profile

The focused provider used TCP, Noise, Yamux, Identify, connection limits, and
a CBOR request/response behavior carrying unchanged Aster frames. Aster's
protected UDP discovery supplied untrusted LAN locators; libp2p mDNS, public
DHT, Gossipsub, public relay services, and public rendezvous were disabled or
not compiled. Aster remained the mission identity and authorization authority.

The signed checkpoint preserves the provider source and exact lock state. Once
the no-selection result was known, the provider and its dependencies were
removed from the continuing source/dependency graph. The result documentation,
provider-neutral host contract, native timing receipts, controller improvements,
and append-only run evidence remain.

## Contract results

Ten deterministic host tests passed. Together they establish:

- normal emission enables automatic discovery;
- constrained and receive-only modes suppress automatic discovery;
- manual candidates remain usable when discovery is suppressed;
- receive-only initiates no contact;
- manual expected-NodeID mismatch fails closed;
- one carrier identity cannot authenticate as two Aster NodeIDs;
- automatic candidates, observed bindings, and stale locators expire while
  manual candidates persist;
- candidate, locator, contact, queue, and carrier-binding state are bounded;
- direct failure selects relay fallback and bounded backoff later retries the
  direct locator; and
- 100 equally eligible candidates receive opportunities with service-count
  skew no greater than one and no more than the active-contact limit.

These are state-machine results. They do not prove a concrete provider's NAT,
relay, or platform behavior.

## Clean LAN reliability

Both exact release artifacts were built from signed checkpoint `05250eb` with
the same compiler image and release settings. Each clean trial used independent
A, B, and C processes and durable roots. It required protected locator-free LAN
discovery, Aster authentication, A→B custody, B restart with A offline, B→C
delivery of the original A-authored ItemID and EnvelopeID, application
acknowledgement, no redelivery after C restart, and duplicate suppression.

| Profile | Mandatory result | Trial elapsed time | Disposition |
|---|---:|---:|---|
| Native UDP control | 30/30 | 23.879–27.844 s; 24.896 s mean | Pass |
| Focused rust-libp2p | 13 passes, failure at trial 14 | 23.816–28.645 s; 25.193 s mean for passes | Fail and abort |

The fixed total includes three six-second node windows plus preparation,
verification, restart, network setup, and teardown. It is not exact delivery
latency.

At failed libp2p trial 14, B and C discovered candidates in 80 ms and 53 ms and
mutually authenticated in 308 ms and 281 ms. They then exchanged only 33 Aster
frames in total before the deadline; C's ordinary subscription returned zero
items. Native passed trial 14 with the same prepared seed and timeout. The
failure therefore belongs to the candidate integration/contact framing, not to
the prepared item or Aster data semantics.

Across the 13 passing libp2p trials, carrier connection management recorded 40
failures and 106 duplicate contacts. Native recorded zero of either across all
30 trials. Libp2p authenticated faster in this laboratory—202–781 ms versus
14–5,227 ms for native—but that setup advantage did not produce reliable
bounded completion.

## Additional functional and security lanes

| Lane | Result | Evidence boundary |
|---|---:|---|
| Manual NodeID@locator peering with discovery suppressed | 1/1 pass | both peers authenticated; zero automatic candidates |
| Constrained-emission discovery suppression | 1/1 pass | zero candidates, contacts, and Aster frames |
| Simultaneous B↔A and B↔C | 1/1 pass | B authenticated both peers at active-contact high-water 2 |
| Route-only custody and application acknowledgement | Pass in reported successful trials | exact source item/envelope and zero post-ack redelivery |
| Capture canary scan | 3/3 pcaps clear | no payload, topic, scope, logical-key, or publisher canary found |
| 64 KiB store-forward at 60-second windows | 1/1 each profile | capacity result only; no exact completion latency |

The simultaneous-contact LAN also exposed A and C to one another. Their
unprovisioned relationship was rejected by Aster; B alone authenticated both
expected peers. The profile still produced many duplicate carrier races.

The provider did not implement the mandatory controlled NAT, circuit-relay,
relay-loss, direct-path reconsideration, address-change, or provider-level
carrier-reuse lanes. The deterministic contract covers the intended policy but
cannot substitute for those concrete network behaviors. Because a mandatory
clean trial already failed, the proposal required stopping before those cells
or any Phase-C downselect.

## Size and dependency comparison

The stripped Linux ARM64 binaries were byte-for-byte identified as follows:

| Profile | SHA-256 | Binary | gzip -9 | Increment over native |
|---|---|---:|---:|---:|
| Native | `625fadb4b2cbd3fe2edaa2ab0793394f001583fc3942a802ee19f4d3550e4ad9` | 4,148,992 B | 2,031,889 B | — |
| Focused rust-libp2p | `c99c57ca5aebf2fb42d639c6007390d15adc8d9820c4aa064d79d3addeb2633d` | 6,248,280 B | 2,956,822 B | 2,099,288 B (+50.6%) |

The active Linux normal-dependency graph contained 73 unique packages for
native and 217 for the focused profile: 144 incremental packages. Cargo's lock
format can retain disabled aggregate-crate options, so counts were taken from
the exact target/feature `cargo tree`, not from raw lockfile entries.

The active graph no longer included the vulnerable `hickory-proto` path from
Proposal 0001 because libp2p mDNS was removed. It still reached unmaintained
`paste 1.0.15` (`RUSTSEC-2024-0436`) through
`libp2p-tcp → if-watch → netlink-packet-core`. The exact offline policy audit
also rejected BSD-2-Clause, Zlib, and ISC expressions because they are absent
from the repository allowlist. Those licenses are OSI-approved; this is policy
bookkeeping rather than evidence of strong-copyleft or proprietary terms. The
maintenance finding remains a production-selection blocker.

## Aster custom-code comparison

Physical source lines are reported because generated-code and language-aware
logical-line tools were not part of the frozen environment. Counts include
comments and blank lines and should be read as review surface, not productivity.

| Boundary | Production raw lines | Role |
|---|---:|---|
| Existing native experiment adapter | 565 | discovery, UDP contact map, Aster drivers |
| New provider-neutral `MeshHost` | 895 | shared lifecycle and policy state machine |
| Focused libp2p provider wrapper | 1,082 | Swarm, connections, queues, duplicate selection, Aster drivers |

The candidate therefore added 1,977 production lines across host plus provider
and deleted none of the 565-line native adapter. Even if the native adapter had
been replaced completely, the wrapper alone was 517 lines larger. The whole
repository's `crates/**/*.rs` tree was 103,803 physical lines at the experiment
checkpoint; the relevant comparison is nevertheless the replaceable boundary,
not dilution against unrelated protocol code.

This fails the accepted buy-over-build test: the dependency did not delete
more custom mechanism than it introduced.

## CPU, memory, and carrier traffic

The final one-node idle sample used a five-second settling period followed by
one measured minute. The proposal reserved ten-minute and one-hour samples for
a surviving provider. Libp2p failed before that phase, and the one-minute result
already crossed the non-compensable <1% screen, so longer samples were stopped
and are not claimed.

| Profile | Settled CPU, one core | Settled memory | Startup peak | Discovery traffic | Result |
|---|---:|---:|---:|---:|---|
| Native | 0.821% | 3.28 MiB | 10.37 MiB | 2,332 B/min | Pass |
| Focused rust-libp2p | 1.284% | 5.34 MiB | 9.48 MiB | 2,332 B/min | Fail CPU |

The memory peak is startup-sensitive and inverted in this single sample;
settled memory is the more useful idle comparison. Both profiles used the same
Aster discovery source, explaining their equal idle traffic.

For the successful 64 KiB run, each of six process windows remained alive for
the full minute. The following totals therefore include post-transfer idle work
and do not isolate delivery latency:

| Profile | Six-window CPU | Six-window network | Four data-window CPU | Four data-window network | Mean / max peak memory |
|---|---:|---:|---:|---:|---:|
| Native | 3.118 s | 638,358 B | 2.025 s | 565,166 B | 7.71 / 9.38 MiB |
| Focused rust-libp2p | 5.152 s | 2,206,346 B | 3.405 s | 1,722,654 B | 8.28 / 10.51 MiB |

Libp2p used 65% more aggregate CPU and 3.46× the aggregate network bytes over
the complete run; in the four data-carrying windows it used 68% more CPU and
3.05× the network bytes. The likely cause is the experiment's mapping of every
Aster frame to a separate libp2p request/response exchange. A production retry
would need one long-lived framed stream per contact and must demonstrate the
deletion benefit before being reconsidered.

The current command workload is bounded to 64 KiB, so the requested 1 MiB
throughput distribution was not available without changing the data model or
building a new benchmark. The candidate did not survive to Phase C; 1 MiB,
10,000-item, 100-process, ten-minute, and one-hour measurements are therefore
recorded as **not reached**, not zero and not pass.

## Recommendation

Retain the provider-neutral `MeshHost` contract and its deterministic tests.
Do not admit or ship this rust-libp2p profile. Preserve the exact signed
experiment checkpoint and receipts, then keep the continuing dependency graph
at the native baseline.

The next bounded implementation should connect the existing native IP control
to `MeshHost` and ship one simple local demonstration that exercises automatic
discovery and manual peering through the same long-running host. That work must
not be called production mesh until it also demonstrates address change,
controlled NAT direct/fallback, reconnect, and a locally operated connectivity
relay. If rust-libp2p is reconsidered later, use a persistent stream rather
than request/response-per-frame and require net custom-code deletion before
resource testing.

No requirement, conformance scenario, MVP status, or production capability is
closed by this result.
