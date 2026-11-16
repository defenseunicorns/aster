# Decision 0007: Small link adapters, optional infrastructure

- Status: accepted for reference
- Date: 2026-08-18

The IP reference uses nonblocking UDP for local/manual paths, opaque multicast
discovery, a small UDP observed-address rendezvous exchange for hole punching,
and a separately deployable TCP ciphertext relay fallback. Rendezvous is pairing,
not identity; every path still runs the core hybrid handshake. Local operation
has no infrastructure dependency.

The provisioned discovery secret never appears on the network. Each announcement
uses a fresh OS-random nonce and a truncated HKDF-SHA-256 proof. Manual peers,
discovered endpoints, punch capabilities, rendezvous waiters, active relay pairs,
relay frames, and relay queue bytes all have fixed bounds; stale rendezvous
registrations expire. These limits fail closed or drop untrusted hints without
changing durable mesh truth.

This is intentionally smaller than admitting a P2P stack that failed the public
security-process gate. It does not claim every NAT can be crossed directly.

The transport-neutral runtime owns MTU fragmentation and bounded reassembly.
The BTLE reference carries each already-fragmented frame exactly once, and owns
broadcast behavior, negotiated-MTU enforcement, disconnect handling, and
emission policy behind a narrow `BleRadio` platform contract. It prefers L2CAP
credit channels and permits GATT fallback. Simulation verifies protocol
behavior; physical BlueZ/platform evidence remains a release gate and is not
replaced by a fake hardware claim.

## Selected-node ordered BTLE amendment

The accepted semantic/reference `BleRadio` and `BleLink` path above remains
unchanged. For the selected semantic-v9 node, this decision additionally
authorizes an in-process asynchronous, connection-oriented contact seam and a
bounded Linux LE L2CAP credit-based-channel evaluation adapter.

This selected-node path uses the adapter-neutral ordered-contact framing owned
by `BleL2capV1`; one protected frame may span multiple platform writes and
L2CAP SDUs. That path-specific framing supersedes core datagram fragmentation
ownership only for this ordered contact. It is a carrier implementation detail,
not a new replication record, semantic version, storage format, or public API.

The initial evaluation fixes one provisioned initiator, one provisioned
listener, one controller per process, and one session channel. It supports only
the record-protected hybrid security profile. Bluetooth addresses, PSMs,
pairing, bonds, controller handles, and link encryption grant no Aster identity
or authorization. The complete mission handshake precedes inventory or Event
data. GATT is not an implicit fallback: a future `BleGattV1` is a separately
registered adapter and requires its own review and evidence.

Discovery encoding, dynamic roles, duplicate-contact reduction, live hot-plug
recovery, a production MTU floor, Profile-5 attempt channels, automatic
multi-carrier selection, and production authorization remain outside this
amendment. Physical evidence is required before even the bounded Ring 1
evaluation claim moves; it cannot establish a general hardware support row.
