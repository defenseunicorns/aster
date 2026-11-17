# Data Mesh Protocol & Sync Framework — High-Level Software Requirements

**Version:** 0.1 (draft for review)
**Date:** 2026-08-17
**Audience:** Senior software implementation team

---

## 1. Project Brief

This project delivers two things: a **well-defined data synchronization protocol** and a **lightweight, embeddable peer-to-peer framework** implementing it, for moving mission data among US military systems at the tactical edge.

The operating reality this system must serve: on-person devices, on-vehicle devices, mission data systems, and edge endpoints that are battery-constrained, bandwidth-constrained, and intermittently connected — sometimes offline for extended periods. These systems communicate over a shifting mix of transports (IP networks, BTLE, tactical radio, SATCOM, and others over time), none of which can be trusted. Data must flow peer-to-peer, including through intermediate nodes when a consumer has no connectivity or line-of-sight to a producer, and must reconcile cleanly when disconnected nodes resync.

The end state is a protocol and framework that an application developer or system integrator can plug into their app or platform through a simple library or API call — taking full advantage of the mesh without special knowledge of its internals. The implementation team owns all architecture and design decisions; this document defines **what** must be built, not **how**.

**Requirement language:** *Must* = binding. *Should* = strong default; deviation requires documented rationale. *May* = optional. **Tags:** [MVP] required for first release; [Post-MVP] required but deferrable; [Future] candidate, design must not preclude. **Bracketed values** (e.g., [30 days]) are proposed placeholders the team must validate with stakeholders.

---

## 2. Scope

**In scope:**
- An implementation-independent protocol specification
- A reference framework implementing the protocol (see §8 for language constraints)
- Language bindings/SDKs and a documented pattern for producing more
- Transport adapters (IP and BTLE at MVP; extensible to others)
- A conformance test suite

**Non-goals (explicitly out of scope):**
- Real-time streaming media (voice/video) — excluded for MVP (listed as a future candidate in §11)
- Radio, waveform, or link-layer management (the mesh rides on transports; it does not operate them)
- End-user applications or C2 functionality (the mesh moves data; apps interpret it)
- Device management / MDM
- COMSEC doctrine or key-management policy definition (the framework provides mechanisms; policy is set by adopting programs)

---

## 3. Operating Environment & Assumptions

- Networks are **untrusted**: any transport may be observed, replayed, or manipulated by an adversary.
- Nodes go offline for extended periods — target tolerance [30 days] (resync requirements in §5.2).
- Bandwidth may be extremely low; the protocol must remain useful at [low single-digit kbps] link rates with high loss.
- Nodes move between transports over time; several transports may be available simultaneously with very different characteristics.
- RF transports are naturally broadcast (one transmission may reach many receivers).
- Many nodes have robust GPS-disciplined time; **not all do** — correctness must not depend on it.
- A pre-mission provisioning window exists for identity and key material.
- Nodes may be lost or captured; the mesh must be able to exclude them afterward.
- Power and RF emissions are operational costs; transmitting less can be a survival requirement.

---

## 4. Definitions

- **Node** — any device running the framework (or a conformant implementation).
- **Item** — a unit of published data, of exactly one data class (§5.1).
- **Data class** — a category of item with defined sync, merge, and expiry semantics.
- **Topic** — a named content channel a node publishes to or subscribes to.
- **Scope** — an administrative propagation domain (e.g., a team or unit).
- **Relay** — a node forwarding items it does not itself consume.
- **Bridge** — a node connecting two scopes, applying filter policy between them.
- **Transport** — a pluggable adapter carrying protocol traffic over a specific medium (IP, BTLE, etc.).
- **Tombstone** — a propagated deletion marker.
- **Perishability (TTL)** — the time after which an item loses its value.
- **Mission keyset** — key material scoped to a mission/scope, derivable from pre-placed long-term keys.

---

## 5. Functional Requirements

### 5.1 Data Model

- The protocol Must support four data classes, each with declared semantics:
  - **State** (latest-value): small mutable values (e.g., position, status). Converges to the causally latest value; typically highly perishable.
  - **Event** (append-only): immutable items in per-publisher order (e.g., chat, sensor readings). No merge conflicts; consumers Must be able to detect gaps in a publisher's sequence.
  - **Record** (mutable document): items edited over time, possibly concurrently on disconnected nodes (e.g., plans, forms). Subject to conflict handling (§5.3).
  - **Blob** (large binary): immutable content (e.g., imagery, overlays) transferred in chunks, resumable, with content-addressed deduplication. Other items May reference blobs.
- Every published item Must carry: data class, topic, scope, priority, perishability/TTL, and authenticated publisher identity.
- The protocol Must handle items efficiently from tens of bytes up to blobs of at least [hundreds of MB].

### 5.2 Synchronization & Consistency

- The mesh Must provide eventual consistency: all reachable subscribed nodes in a scope converge on the same data once connectivity permits.
- A node offline for the tolerance period (§3) Must resync on return without loss of durable data, subject only to declared TTL and eviction policy.
- Delivery Must be at-least-once with deduplication; applying the same item twice Must be harmless.
- The framework Must track causality sufficient to distinguish sequential updates from concurrent ones.
- Correctness Must Not depend on synchronized wall clocks. Trustworthy time, where available, May enhance behavior (e.g., TTL precision); its absence Must degrade gracefully. Wall-clock timestamps are advisory metadata, never the arbiter of conflicts.
- Deletions Must propagate as tombstones with bounded, configurable retention.
- Sync cost Must be proportional to the difference between two nodes' data, not to total dataset size (efficient anti-entropy/diffing).
- Partial syncs Must be resumable: progress made during a brief contact window is preserved and continued at the next contact, with any peer.

### 5.3 Conflict Handling

- Default resolution per class (concurrency detected via §5.2 causality tracking): **State** — deterministic latest-by-causality with a deterministic tie-break; **Event** — conflict-free by construction; **Blob** — immutable, no conflicts; **Record** — automatically merged where a registered merge policy applies, otherwise **both versions preserved and the conflict annotated**.
- Conflict annotations Must be surfaced to the application through the API for display or resolution.
- The framework Must never silently discard a conflicting version; superseded versions Must remain recoverable until garbage-collected under explicit policy.
- Integrators May register application-level merge functions per topic/class; these Must be deterministic (same inputs → same result on every node).

### 5.4 Priority & Constrained Operation

- A small fixed set of [4] priority levels Must exist. Naming Should align with prevailing message-precedence doctrine (e.g., ROUTINE / PRIORITY / IMMEDIATE / FLASH); final naming to be validated with stakeholders, noting doctrine may vary by service.
- Priority is assigned by the publisher per item; topics May define defaults; integrator policy May cap or override.
- Priority Must govern at least: transmission ordering, retransmission aggressiveness, and storage eviction under pressure (lowest priority evicted first).
- Perishability is orthogonal to priority (data can be critical *and* stale-fast). Expired items Must Not be transmitted and Must be garbage-collected.
- **Emission budgets:** a node Must support constrained-emission policies under which only items at or above a configured priority are transmitted, including a receive-only (radio-silent) mode that still accepts inbound sync. [MVP: the policy hooks; richer policy Post-MVP]
- Constrained-mode behavior Must be simple and predictable — a small parameter matrix (priority level × TTL, plus emission threshold), deliberately limited to keep cognitive load low for operators in the field.

### 5.5 Scoping & Propagation Control

- Two orthogonal controls Must exist: **topics** (what content a node wants) and **scopes** (where content is allowed to propagate).
- Nodes replicate only subscribed topics within joined scopes. No node is ever required to store or forward the global dataset.
- Nodes May act as relays for items within their scopes that they do not consume, subject to configurable storage/bandwidth quotas.
- Bridges Must be able to connect scopes with filter policy (by topic and priority). Aggregation/summarization at bridges is [Future].
- Scopes May nest hierarchically to reflect organizational structure and bound propagation.

### 5.6 Peer-to-Peer & Store-and-Forward

- Any two conformant nodes sharing a transport Must be able to sync directly, with no server or infrastructure required.
- Items Must reach consumers via intermediate nodes when producer and consumer have no direct connectivity or line-of-sight — multi-hop, store-and-forward dissemination across intermittent contacts (relay read-access constraints in §6).
- On broadcast media, the protocol Should exploit one-to-many delivery (one transmission serving many receivers) rather than repeating per-peer unicast exchanges.
- Duplicate and loop suppression Must bound redundant propagation.

### 5.7 Discovery & Peering

- Peers Must be discoverable automatically where the transport allows (e.g., local broadcast/advertisement on IP, BTLE advertising), and Must also support pre-provisioned/manual peering.
- Discovery Must respect emission policy: a node in constrained-emission or silent mode is not discoverable.
- Peers Must mutually authenticate before exchanging data (§6).

### 5.8 Transports

- Transports Must be pluggable behind a defined abstraction; adding a transport Must Not require protocol changes.
- The protocol Must handle fragmentation and reassembly across MTUs ranging from tens of bytes to 1500+; framing overhead Must be small enough to be practical on the smallest supported MTU.
- [MVP] **IP** — Must work across NAT'd networks. NAT traversal Should be infrastructure-free wherever the network permits; relay-assisted fallback May be supported but Must Not be a hard dependency for local/mesh operation.
- [MVP] **BTLE.**
- [Future] **LoRa, serial, file-based.** The file transport (physical media transfer) requires the entire sync exchange to be serializable offline — the protocol design Must Not preclude this.
- Transport adapters Should expose link characteristics (bandwidth, cost, emission footprint) so scheduling and priority decisions can use them.

---

## 6. Security Requirements

- **Zero-trust transport:** the system Must Not rely on transport- or network-layer security for confidentiality, integrity, or authenticity.
- Every item Must be encrypted and authenticated **at the source** and verified at consumption (end-to-end). Relays and bridges Must be able to store and forward items without payload plaintext access.
- **Layered metadata protection:** forwarding metadata (topic, scope, priority, routing) Must Not travel in plaintext. It Must be protected at a mesh membership layer — readable by authenticated mesh nodes so relays can make forwarding decisions, opaque to outside observers. On-the-wire plaintext Must be minimized to what the transport itself requires.
- **Identity:** every node Must have a unique cryptographic identity, provisioned pre-mission.
- **Keying model:** the design Should support pre-placed long-term keys from which per-mission and per-scope keys are derived, so read access to a scope requires holding that scope's keys — possessing a mesh node Must Not grant read access to all scopes.
- **Revocation:** exclusion of lost/compromised devices Must propagate through the mesh itself under intermittent connectivity. In-field re-keying of a scope Must be possible. A zeroization hook (rapid destruction of local key material) Must be provided.
- **Freshness:** replay of previously captured traffic Must Not cause acceptance of stale or duplicate data as new.
- **Algorithms:** NIST-standardized cryptography Must be used, with hybrid classical + post-quantum schemes for key establishment and signatures (e.g., NIST PQC selections such as ML-KEM and ML-DSA). FIPS 140-3 validated modules Should be used where available; FIPS-approved algorithms Must be used regardless. Algorithm agility (versioned negotiation) Must exist, with explicit protection against downgrade attacks.
- **Cost amortization:** kilobyte-scale operations such as post-quantum signatures May be amortized across sessions or batches rather than applied per item, provided the end-to-end authenticity and encryption requirements above still hold; per-item overhead Must remain compatible with the link-rate floors in §9.
- No hand-rolled cryptographic primitives; only vetted, widely reviewed implementations.

---

## 7. Developer Experience & Embeddability

- The framework Must be a single embeddable library with a C-compatible FFI, plus a documented, repeatable **binding pattern** (with template) for producing language bindings.
- [MVP] At least [2] first-class bindings, chosen by the team from: Go, Java/Kotlin (Android), Swift (iOS), Python, Node.js. Remaining targets follow the pattern [Post-MVP].
- [MVP] An optional out-of-process agent exposing the API over gRPC (or similar local IPC) Should be provided for integrators who cannot link natively.
- The public API Must be limited to high-level operations — publish, subscribe, query, conflict annotations, sync/peer status — and Must Not expose cryptographic primitives, fragmentation, transport selection, or sync internals.
- Publishing while disconnected Must succeed locally and sync later; the API is offline-first.
- **Integration bar:** a competent developer Must be able to integrate basic publish/subscribe in under [1 day] using only shipped documentation and examples; a minimal working sample Should be under [~50 lines].

---

## 8. Implementation Constraints

- **Primary language:** a memory- and type-safe language capable of static compilation — Rust is the designated choice for the core framework. Components requiring C or other languages are acceptable where necessary but Must be documented with rationale.
- **Dependencies** Must be: OSI-approved licenses only, with **no strong copyleft and no proprietary licenses**; actively maintained; under identifiable governance; and following basic security practices (vulnerability reporting channel, history of timely patching). A dependency and license inventory (SBOM) Must be maintained.
- **Buy over build:** prefer existing, well-maintained FOSS tools, libraries, and **published standards** over bespoke designs wherever they meet requirements. Where the team builds instead of buys, the evaluation and rationale Must be recorded.
- **Interoperability:** the protocol specification is the authority. Two independent conformant implementations Must interoperate; the reference framework is one implementation, not the definition.

---

## 9. Performance & Resource Targets

- **Device tiers:**
  - **Tier 1 — MCU-class** (no OS): [Future]. A reduced-subset protocol profile is acceptable. Target [≤ 256 KB RAM, ≤ 2 MB flash]; item storage May use external flash. MVP design Must Not preclude this profile.
  - **Tier 2 — embedded Linux / mobile:** the [MVP] baseline.
  - **Tier 3 — vehicle / mission-system class:** larger storage and relay/bridge duty.
- Tier 2 targets: [≤ 10 MB] added binary size; [≤ 64 MB] steady-state RAM (Should target [≤ 32 MB], since mobile OSes aggressively reclaim background processes) at a [10,000-item] metadata working set — blob content Must stream from storage, not scale RAM; functional on a [single ARM core].
- Battery: no busy-polling; sync duty cycles Must be configurable; idle cost near zero.
- Useful at link rates down to [low single-digit kbps] and loss rates up to [50%].
- Mesh scale targets: [≥ 100] nodes per scope, spread across links/transports (not all sharing a single low-rate RF channel); [≥ 1,000] nodes across bridged scopes.
- Local storage Must be bounded and configurable (eviction policy per §5.4).

---

## 10. Compatibility & Evolution

- The protocol Must be versioned. Mixed-version meshes Must interoperate at the highest common version; nodes Must Not fail on unknown-but-ignorable extensions.
- New data classes and transports Must be addable without breaking deployed nodes (cryptographic agility per §6).
- A deprecation policy Must be documented before v1.0.

---

## 11. MVP Definition & Phasing

**MVP** — ships every §13 deliverable, with feature scope:
- Transports: IP (incl. NAT'd networks) and BTLE
- All four data classes; conflict detection with annotation (rich auto-merge policies may be minimal)
- Topics, scopes, relays; bridge filtering
- [4]-level priority + TTL; emission-policy hooks incl. receive-only mode
- Pre-mission identity/keying, revocation, payload E2E crypto + mesh-layer metadata protection

**Post-MVP:**
- Remaining language bindings; richer auto-merge policy library; expanded emission-policy controls; out-of-process gRPC agent if not in MVP

**Future candidates:**
- Tier 1 MCU profile; LoRa, serial, and file transports; bridge aggregation/summarization; streaming-media reconsideration

---

## 12. Acceptance Scenarios (illustrative; the release Must pass equivalents)

- Two nodes sync over BTLE, then over IP; an item published via one transport is consumed via the other.
- A node offline [30 days] rejoins and converges with its scope, with no durable data lost.
- Two disconnected nodes edit the same record; on resync, both versions survive with the conflict annotated (or merged per registered policy); nothing is silently lost.
- A consumer with no connectivity or LOS to a producer receives the producer's items via an intermediate relay; the relay cannot read the payloads it carried.
- On a constrained link, higher-priority items are delivered first and expired items are never transmitted.
- A node under emission constraint transmits only items at or above the threshold; in receive-only mode it still ingests inbound sync.
- A revoked device is excluded from all further exchanges; the affected scope is re-keyed in the field.
- Two nodes behind different NATs sync without pre-deployed infrastructure where the network permits; relay fallback works where it doesn't.
- A packet capture on any transport reveals no plaintext payload or mesh metadata.
- An independent implementation built from the protocol spec passes the conformance suite against the reference framework.

---

## 13. Deliverables

- Protocol specification (implementation-independent, versioned)
- Reference framework (Rust core, C FFI) and transport adapters (IP, BTLE)
- Language bindings per §7 and the binding pattern/template documentation
- Conformance test suite
- Integrator documentation with worked examples
- Dependency/license inventory (SBOM) and buy-vs-build decision record

---

## 14. Open Items for the Team & Stakeholders

- Validate priority level count/naming against applicable service doctrine.
- Validate all bracketed placeholder values (offline tolerance, resource budgets, scale, link-rate floors).
- Select the MVP language bindings from the §7 list.
- Complete the standards evaluation and buy-vs-build record (§8).
- Determine the FIPS validation path (validated module availability for chosen algorithms, including PQC hybrids).
