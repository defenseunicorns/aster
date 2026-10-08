# asterctl

Clean Room — Privileged

`asterctl` is a command-line utility for introspecting and controlling Aster
nodes through a running `aster-agent`. 

The plaintext RPC client accepts only loopback IPv4 or IPv6 addresses. Remote
agents require a local authenticated tunnel endpoint; `--host` cannot send
bearer tokens or Event payloads directly over a remote plaintext connection.

Currently it provides `status`, `publish`, `query`, `subscribe`,
`subscriptions`, and `unsubscribe`.

See man page for usage details

## Build and run

```sh
cargo build --locked -p asterctl
./target/debug/asterctl --help
man -l crates/asterctl/asterctl.1
```

## Verification

Run the CLI unit and process regressions with `cargo test --locked -p asterctl`.

For a compatibility smoke against the checked-in agent, run:

```sh
cargo build --locked -p asterctl -p aster-agent \
    --bin asterctl --bin aster-agent-acceptance-fixture \
    --features aster-agent/client,aster-agent/acceptance-test-provider
python3 tools/test-asterctl-real.py
```

The smoke uses ephemeral test-only provisioning and exercises authenticated
status, finite-TTL publication and its idempotent replay, query, subscription
creation and replay, subscription listing, deletion and repeated deletion,
and rejected authentication. It does not qualify deployed
credentials, packages, or network delivery.

## Arguments

```text
asterctl [OPTIONS] (--token TOKEN | --token-file PATH) [COMMAND [ARGS...]]
asterctl --help
```

| Argument | Meaning |
| --- | --- |
| `-h, --host IP` | Agent IPv4 or IPv6 address; default `127.0.0.1` |
| `-p, --port PORT` | RPC port, 1–65535; default `8181` |
| `--timeout SECONDS` | Client timeout for each RPC, 1–86400 whole seconds; default `10`; agent-side limits also apply |
| `-j, --json` | Pretty-printed JSON; RPC fields use ProtoJSON, with CLI operation metadata described below |
| `-t, --token TOKEN` | Plain-text API token, without the `Bearer ` prefix |
| `--token-file PATH` | Read that same token from a regular file |
| `--help` | Show help without connecting or reading a token file |

Global options can precede or follow the command. Omitting it selects `status`.
Exactly one of `--token TOKEN` or `--token-file PATH` is required to run a
command; repeated sources and combining both options are errors. `--help`
requires no token. Running `asterctl` with no arguments reports the missing
token source; tokens are not read from a default file or the environment. Long
options with values accept both `--name value` and `--name=value`. Short
options with values require a separate argument, such as `-p 8181`; `-p=8181`
is rejected. Flags such as `--json`, `--help`, and `--tombstone` take no value.
File paths passed as a separate argument use the operating system's native
path representation.

The token must match the agent's `credentials.client_token_file`: 32–256 ASCII
letters, digits, or `-._~`. A token file may have trailing LF/CRLF; its maximum
size is 258 bytes. Other whitespace is not trimmed. Normal filesystem access
permissions apply; keep the file private, for example with mode `0600`.
Plain-text command-line arguments may appear in process listings and shell
history. The CLI never includes tokens or remote error messages in diagnostics.

The client uses ConnectRPC with Protobuf messages over HTTP and sends one
Bearer authorization header. The current agent accepts loopback listeners;
`--host` does not change that server restriction. There is no TLS. Each RPC
has a configurable timeout (10 seconds by default), a 4-MiB response limit and a
4-MiB decoded-element budget.
Use `--timeout 30` or `--timeout=30` before or after the command to change the
client deadline. The agent may enforce a shorter deadline: the current
`aster-agent` caps each RPC at 30 seconds, even when the client requests more.
Query applies a fresh deadline to each page request, not to the whole query.
The RPC timeout does not limit time spent entering a payload on stdin.

## Publish

Initialize one journal for a stable application identity, then reuse it across
CLI invocations:

```sh
asterctl publication-init --journal ./publisher.redb --client-id chat-controller
asterctl --token-file ./client.token publish \
    --journal ./publisher.redb --client-id chat-controller \
    --topic chat.events --scope mission/team/alpha "Hello, Aster!"

cat image.png | asterctl --token-file ./client.token publish \
    --journal ./publisher.redb --client-id chat-controller \
    --topic chat.events --scope mission/team/alpha
```

Journal initialization is local and requires no token. It refuses an existing
file. Keep the journal in a protected directory: it contains complete plaintext
intents and payloads. Opening a missing, corrupt, already-open, or differently
configured journal fails before reading stdin or contacting the agent. Do not
delete and recreate an established journal or choose a new client ID to retry
an uncertain operation. Lost-journal recovery is outside this increment.

Supply one `MSG` argument or read the payload from stdin until EOF. When stdin
is a terminal, the CLI prints instructions to stderr before reading: finish
with Ctrl-D on an empty line, or cancel with Ctrl-C. Piped input, an explicit
`MSG`, and tombstone publications do not print these instructions. Payload
bytes are preserved, including NUL bytes and newlines from stdin; no newline is
added to `MSG`. Use `--` before a message beginning with `-`. The complete
encoded request, including space for the largest session and sequence fields,
must fit within 1 MiB.

The CLI recovers its fenced publication session, assigns a positive operation
sequence durably, and announces that sequence before `PublishNumberedEvent`.
It saves the committed result before displaying it. A failed publication stays
journaled; new publication is blocked while an earlier intent remains pending.
After an uncertain outcome, recover using the same journal and identity:

```sh
asterctl --token-file ./client.token --json publication-recover \
    --journal ./publisher.redb --client-id chat-controller
asterctl --token-file ./client.token --json publication-retry \
    --journal ./publisher.redb --client-id chat-controller --sequence 1
```

`publication-show --sequence N` inspects one retained original intent locally;
it does not contact the agent. This supports applying a recovered result using
the exact original payload after process replacement.

`publication-retry` sends the original journaled intent or displays its recovered
committed receipt. Apply the result idempotently, then reclaim its journal and
server result rows explicitly:

```sh
asterctl --token-file ./client.token publication-ack \
    --journal ./publisher.redb --client-id chat-controller --sequence 1
```

`publication-abandon` with the same identity and `--sequence N` permanently
consumes the next unadmitted sequence. It cannot undo a committed Event. Use it
only when deliberately discarding that pending operation. Transport errors do
not trigger abandonment. TTL cleanup may retire Event content while its
committed receipt remains recoverable until acknowledgement.

See `asterctl publish --help` or [asterctl-publish(1)](asterctl-publish.1) for
publication options. Subscription creation retains its existing operation-key
model until the separate client-ownership increment.

## Query

```sh
asterctl --token-file ./client.token query
asterctl --token-file ./client.token query \
    --topic chat.events --scope 'mission/team/*' --limit 102020
asterctl --token-file ./client.token --json query --logical-key device-1
```

Without `--limit`, query displays all matching Events. `--limit N` caps the
number of Events displayed, independently of the agent's per-request scan
bound. The client continues even when an intermediate response contains no
matches. Zero displays no Events and does not contact the agent.

Filters are optional and combined. `--scope mission/team` selects the exact
scope; `--scope 'mission/team/*'` also includes every sub-scope. The trailing
`/*` is the only supported wildcard form. Quote it to prevent shell expansion.
An omitted logical key applies no filter; `--logical-key ''` selects an empty key.

The client reads incrementally, keeping a bounded RPC response in memory.
If a response exceeds the agent's budget, it reduces the internal scan size
and retries the same read. Other RPC errors stop the command.
See [asterctl-query(1)](asterctl-query.1) for the command reference.

## Subscribe

```sh
asterctl --token-file ./client.token subscribe \
    --scope mission/team/alpha --operation-key=auto chat.events
asterctl --token-file ./client.token --json subscribe \
    --scope 'mission/team/*' --operation-key chat-reader chat.events
```

`TOPIC` is a required positional argument; `--scope` is also required.
The scope wildcard has the same meaning as in `query`. Use `--` before a
topic beginning with `-`.

Subscriptions persist after the command exits and across agent restarts.
Matching Events already stored on the node are also eligible for delivery.
The command creates the subscription; retrieving deliveries is a separate RPC.

`--operation-key KEY|auto` is required. If the subscription already exists for
that key and the same parameters, the command exits with code `0` and prints
its ID to stdout. Reusing the key with different parameters fails.
JSON reports `inserted: false` for an identical existing subscription. This
changes the previous CLI behavior, which returned code `1` for that retry.
See [asterctl-subscribe(1)](asterctl-subscribe.1).

## Subscriptions

```sh
asterctl --token-file ./client.token subscriptions
asterctl --token-file ./client.token subscriptions --json
```

Lists the node's Event subscriptions in subscription-ID order. Text output
shows the ID, topic, scope, and operation key. A trailing `/*` in the scope
includes sub-scopes. UTF-8 operation keys are quoted and escaped; other keys
are labeled Base64.

JSON is an array with `subscriptionId`, `topic`, `scope`,
`includeDescendantScopes`, and `operationKey`. IDs and operation keys use
Base64; `scope` has no `/*` suffix. An empty list produces no text, or `[]`
in JSON. See [asterctl-subscriptions(1)](asterctl-subscriptions.1).

## Unsubscribe

```sh
asterctl --token-file ./client.token unsubscribe "$SUBSCRIPTION_ID"
asterctl --token-file ./client.token --json unsubscribe "$SUBSCRIPTION_ID"
```

Removes an Event subscription and its delivery ledger. Use the ID returned by
`subscribe` or listed by `subscriptions`.

Prints `Subscription removed` or `Subscription already absent`; both succeed.
With `--json`, prints `alreadyAbsent`: `false` when removed, `true` when already
absent.

See [asterctl-unsubscribe(1)](asterctl-unsubscribe.1).

## Operation keys and manual recovery

`subscribe` requires `--operation-key KEY|auto`.
`--operation-key auto` and `--operation-key=auto` are equivalent. An omitted
key is an argument error (exit code `2`), detected before sending an RPC:

```text
asterctl: --operation-key is required; specify a key or 'auto'
```

An explicit key is 1–256 UTF-8 bytes and is sent unchanged. The exact value
`auto` is reserved: it generates a new key from 16 random bytes encoded as
32 lowercase hexadecimal characters. After the request is prepared and
validated, the generated key is written to stderr and flushed before the RPC
is sent, including with `--json`:

```text
asterctl: operation-key=8f129cd0e346a27b9014fe6c72a583bd
```

If writing or flushing that message fails, the command exits with code `1`
without sending the RPC. Subscription JSON results
also include `operation_key`, for both explicit and generated keys.

A timeout, lost connection, or unusable response can leave the operation's
outcome unknown: the agent may already have committed it. In that case, the
command exits with code `1` and reports the key and recovery instruction on
stderr, for example:

```text
asterctl: CreateEventSubscription outcome unknown: deadline_exceeded
retry the identical request with --operation-key=8f129cd0e346a27b9014fe6c72a583bd
```

Request rejections
such as `invalid_argument` or `aborted` are reported as failures. Codes that
also represent lost or unusable responses, including `resource_exhausted`,
are conservatively reported as unknown outcomes.

To recover, repeat the request against the same agent with the printed key
and identical parameters and payload. For stdin, retain and reuse the original
bytes. Do not use `auto` for that retry: every invocation generates a new key.
No automatic subscription retry is performed. Subscription creation keeps no
persistent journal; printing
and flushing a key does not guarantee durable storage. Automation should save
an explicit key and the request before invoking the command.

Existing scripts must now supply a key or explicitly select `auto`. The literal
key `auto` can no longer be supplied through this option.

## Output and exit status

Plain text groups status into node, peers, storage, publication operations, and
delivery sections, with aligned labels. Counters use comma-separated thousands;
booleans display `Yes` or `No`; enum names display as readable words (for
example, `Last contact complete`). Unknown enum values display as `Unknown (N)`.
Identities remain full standard padded base64.

Publication results show the client operation sequence, committed Event and
transfer IDs, original acceptance marker, and current content status. Retired
content retains its committed identity and includes a retirement reason in
JSON. Use query to inspect source counters, priority, or TTL while content is
available. Printing a result does not acknowledge or erase it.

Storage sizes use binary units (`B`, `KiB`, `MiB`, and so on), rounded to at most
two decimal places. Durations use days, hours, minutes, and seconds, such as
`2h` or `1m 5s`. Zero remains visible as `0`, `0 B`, or `0 s`. Capacity usage
and hard limits appear together as `used / limit`. See the
[text output example](tests/status.txt).

RPC response fields use ProtoJSON with lowerCamelCase field names:

- `uint64` values are exact decimal strings;
- enums use their full Protobuf names; unknown numeric values remain numeric;
- bytes use standard padded base64;
- booleans remain `true` or `false`, including defaults;
- finite doubles are numbers; nonfinite doubles follow ProtoJSON strings.

Both formats include scalar defaults and empty peer lists, but omit absent
message fields and absent `ttlMs`. Present nested messages include their scalar defaults. For
example, `estimatedSecondsToExhaustion` equal to zero is printed as `0 s` in
text and `"0"` in JSON. Status does not add fields such as `running`, `online`,
or `endpoint`.

Query text displays each Event with aligned metadata and its payload. Text
values are quoted and escaped; non-UTF-8 logical keys and payloads are labeled
Base64. JSON output is one array of Events, each encoded with the ProtoJSON
types above. An empty query produces no text, or `[]` in JSON.

Subscribe prints only the Base64 subscription ID and a newline to stdout.
Its JSON result contains `subscriptionId` and `inserted`, including `false`
when an identical subscription already exists.

`publish` and `subscribe` JSON objects additionally contain the
top-level CLI field `operation_key`. It is the actual key as a UTF-8 string,
with JSON escaping as needed, not Base64 or the reserved selector `auto`.
This field is added by the CLI; it is not part of the RPC response schema.

Results, including an existing subscription ID, go to stdout with a final
newline. Errors and
the pre-send generated-key message go to stderr. Query writes Events as they
arrive; if a later request fails, earlier output remains and the JSON array may
be incomplete. Exit codes are `0` for success/help (including an identical existing
subscription and a downstream closed stdout pipe), `1` for
authentication/RPC/input/output/command errors, and `2` for invalid arguments,
including a missing operation key. RPC diagnostics use
fixed protocol error codes; `publish` and `subscribe` include the operation key
when recovery is needed. Remote error text and API tokens are never included.
Rejections and read failures may include local troubleshooting hints.
Mutation timeouts still report an unknown outcome: the agent may have committed
the request. Retry `publish` or `subscribe` only with the same operation key and
identical parameters and payload; retry `unsubscribe` with the same subscription ID.
