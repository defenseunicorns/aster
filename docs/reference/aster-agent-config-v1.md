# Aster agent configuration version 1

> ****

This reference describes the strict JSON accepted by the customer Event
runtime. The profile is one Event-only, single-scope process with exact manual
peers and at most one customer-controlled connectivity relay. It has no State,
Record, Blob, automatic-discovery, bridge, or multi-scope forwarding fields.
Unknown and duplicate fields are rejected at every object level.

The repository `aster-agent` binary can validate this document with
`--check-config`. A customer runtime must statically compose the public
`run_customer_agent` entry point with exactly one protected
`ProvisioningSecretLoader`; the repository's unprotected acceptance fixture is
test-only and is not a customer provider.

## Safe evaluation example

Every path inside the JSON must be absolute. The credential files must already
exist and meet the rules below before this example passes validation. The
all-zero `mission_load_id` is a synthetic operation identifier, not a
credential or provisioning reference.

```json
{
  "schema_version": 1,
  "state": {
    "directory": "/var/lib/aster-agent"
  },
  "application": {
    "listen": "127.0.0.1:8181"
  },
  "health": {
    "listen": "127.0.0.1:8182"
  },
  "mesh": {
    "bind": "0.0.0.0:8183",
    "sync_interval_ms": 500,
    "peers": []
  },
  "credentials": {
    "client_token_file": "/run/aster-agent/client-token",
    "mission_secret_ref_file": "/run/aster-agent/mission-reference",
    "mission_load_id": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "storage": {
    "max_items": 10000,
    "max_payload_bytes": 67108864
  },
  "limits": {
    "max_connections": 64,
    "max_unauthenticated_connections": 8,
    "max_header_bytes": 16384,
    "first_authentication_timeout_ms": 5000,
    "max_in_flight_requests": 64,
    "shutdown_grace_ms": 30000
  }
}
```

The 10,000-item/64-MiB values are the capacity at which the repository's
crash/recovery acceptance scenario passed. They are qualification evidence,
not a production sizing recommendation and not a change to the validation
minimum. Logical limits do not include redb/filesystem overhead, process RSS,
untracked files, snapshots, swap, backups, or Blob-depot allocation.

## Field reference

All fields below are required unless the Default column says otherwise.
Unsigned integer fields use their JSON integer representation.

| JSON path | Type | Default | Accepted value and rule |
|---|---|---|---|
| `schema_version` | integer | none | Exactly `1`. |
| `state.directory` | string path | none | Absolute lexical path. Validation does not create or open it; startup requires exclusive access to the durable state. |
| `application.listen` | socket address | none | IPv4 or IPv6 loopback only. Must differ from `health.listen`. Plaintext Connect/gRPC/gRPC-Web. |
| `health.listen` | socket address | none | IPv4 or IPv6 loopback only. Must differ from `application.listen`. Plaintext HTTP health only. |
| `mesh.bind` | socket address | none | Valid IP socket address for the selected mesh carrier. It is not an application listener. |
| `mesh.sync_interval_ms` | integer | none | `1..=60000`. |
| `mesh.peers` | array of strings | none | `0..=256` exact manual peers. Each is `CARRIER_ID@IP:PORT=MISSION_NODE_ID_HEX64`. Carrier identities must be unique and mission identities must be unique; distinct peers may share a socket address. |
| `mesh.relay` | object or `null` | omitted/`null` | At most one controlled relay. See Relay below. |
| `credentials.client_token_file` | string path | none | Absolute path to the owner-only bearer-token file. |
| `credentials.mission_secret_ref_file` | string path | none | Absolute path to one owner-only canonical serialized `ProvisioningSecretRef`; JSON never carries its bytes. |
| `credentials.mission_load_id` | string | none | Exactly 64 hexadecimal characters (case-insensitive), decoded as the provider load-operation ID. |
| `storage.max_items` | integer | none | Aggregate logical store limit, `4161..=18446744073709551615`. |
| `storage.max_payload_bytes` | integer | none | Aggregate logical retained-byte limit, `17891328..=18446744073709551615`. |
| `limits` | object | compiled ceilings | May be omitted or contain any subset of the six tightening fields below. |
| `limits.max_connections` | integer | `64` | `1..=64` total application connections. |
| `limits.max_unauthenticated_connections` | integer | `8` | `1..=8` not-yet-authenticated application connections. This is an independent ceiling and may exceed a tightened `max_connections`, although doing so provides no extra total capacity. |
| `limits.max_header_bytes` | integer | `16384` | `1..=16384` parsed application request-header bytes. |
| `limits.first_authentication_timeout_ms` | integer | `5000` | `1..=5000` from connection admission to the first authenticated request. |
| `limits.max_in_flight_requests` | integer | `64` | `1..=64` business responses/streams in flight across the node. |
| `limits.shutdown_grace_ms` | integer | `30000` | `1..=30000` for application drain and selected-node shutdown together. A second termination signal or expiry forces exit code `2`; clean shutdown is `0` and a terminal failure is `1`. |

The server also retains compiled, non-configurable bounds: 1 MiB encoded
request/message, 4 MiB protobuf element memory, 2 MiB encoded protobuf
response, RPC deadlines of 10 ms through 30 seconds (10-second default), 32
HTTP/2 streams per connection, and streaming poll backoff of 100 through
60,000 ms. Event query, delivery, and scan pages are each `1..=1024`.

## Relay

When `mesh.relay` is present, all three scalar fields are required and
`der_roots` defaults to an empty array:

| JSON path | Type | Default | Accepted value and rule |
|---|---|---|---|
| `mesh.relay.url` | string | none | HTTPS root-origin URL, at most 2,048 serialized bytes, with a host and no username, password, non-root path, query, or fragment. |
| `mesh.relay.trust` | string enum | none | `webpki` or `der_roots`. |
| `mesh.relay.route_policy` | string enum | none | `direct_preferred` or `relay_only`. |
| `mesh.relay.der_roots` | array of paths | `[]` | With `webpki`, must be empty. With `der_roots`, requires `1..=8` absolute paths. Each file must be regular, nonempty, valid DER CA certificate data, at most 65,536 bytes; aggregate data is at most 262,144 bytes. |

`webpki` selects the embedded WebPKI roots. `der_roots` replaces that set with
only the supplied roots. DER-root files are public trust anchors and do not use
the credential-file owner/no-follow policy. The relay URL and route policy are
carrier locators only: they grant no mission identity, scope, topic, or Event
authorization. Every relay contact must still pass the same exact carrier and
independent mission authentication as a direct contact. Public/default relay
selection and relay fallback outside this one pinned origin are not supported.

## Storage reserve calculation

The configured values map directly to `StoreLimits`. Validation then reserves:

- 4,096 items for mission-control authority;
- 64 items of emergency tombstone slack;
- 16,777,216 bytes for controls and canonical publication intent;
- 65,536 bytes of emergency tombstone slack; and
- capacity for at least one 1,048,576-byte maximum agent message.

Therefore `max_items >= 4096 + 64 + 1 = 4161` and
`max_payload_bytes >= 16777216 + 65536 + 1048576 = 17891328`.
The ordinary global Event custody ceiling is derived, not independently
configured: `max_items - 4160` and `max_payload_bytes - 16842752`. Version 1
has no per-scope, bridge, or Blob-depot quota field and never raises a limit
automatically. Saturation returns the sanitized public resource-exhaustion
error; clients must back off or request a smaller valid page.

## Credential files

On Unix, both credential files are opened with no final-symlink following and
close-on-exec. Each must be a regular file owned by the process's effective
user, with no permission bits outside owner read/write (`0600` or stricter),
and its complete metadata must remain stable across the bounded read.
Non-Unix secure credential loading currently fails closed.

The token file is at most 258 bytes before trailing CR/LF removal. The token
after removal must be 32 through 256 ASCII bytes drawn only from letters,
digits, `-`, `.`, `_`, and `~`. The canonical mission-reference file is at most
8,192 bytes. Parent-directory symlink/rename resistance is not claimed; the
deployment owner must provide the directory ownership and isolation boundary.

`SIGHUP` rereads only `client_token_file`. A completely validated replacement
atomically becomes active; a failed reload retains the previous token and
readiness. Mission reference, load ID, peers, relay, storage, and limits change
only through restart.

## Validation and diagnostics

Run the supported side-effect-free validation mode:

```sh
cargo run --locked -p aster-agent -- \
  --check-config /absolute/path/to/agent.json
```

`--check-config` parses every JSON and cross-field rule, reads relay DER roots
when configured, and validates both credential files including canonical
mission-reference decoding. It does not create/open state, bind a socket, or
invoke a provisioning provider. Provider availability and durable-state
opening are startup checks. `--check-config` and `--config` are mutually
exclusive and neither may be combined with legacy development flags.

Success is silent with exit code `0`. Failure is nonzero and contains only one
of these fixed configuration reasons (the stock CLI prefixes it with `ERROR`):

- `configuration path must be absolute`
- `configuration contains a duplicate field`
- `configuration listeners must be distinct`
- `configuration contains a duplicate peer carrier`
- `configuration contains a duplicate peer mission`
- `credential file boundary is invalid`
- `configuration file cannot be read`
- `configuration mission load id is invalid`
- `configuration peer is invalid`
- `configuration relay is invalid`
- `configuration storage limits are invalid`
- `configuration limit is out of range`
- `configuration listener must be loopback`
- `configuration is missing a required field`
- `configuration storage cannot preserve required reserves`
- `configuration synchronization interval is out of range`
- `configuration syntax is invalid`
- `configuration has too many peers`
- `configuration contains an unknown field`
- `configuration schema version is unsupported`

Diagnostics do not echo field values, paths, credentials, peer coordinates,
provider text, or raw lower-level errors. Treat the reason as a rule category;
inspect the configuration locally without copying sensitive values into logs.

## Supported boundary

Customer qualification additionally requires a protected provider and a
deployment-owned dedicated network namespace containing only the agent and its
intended trusted application. Plaintext loopback without that isolation is
development-only. Protected provider delivery, namespace and service-manager
artifacts, packaging, amd64/arm64 validation, representative deployment,
physical/mixed-network proof, security review, SBOM/signing, and release
authorization remain open and owned by their respective workstreams.
