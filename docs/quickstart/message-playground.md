# Real-process Event message playground

For a guided, named, staged first experience, start with
[Aster Field Notes](hello.md). This page documents the broader numeric
2-through-32-node exploratory surface retained underneath it.

The message playground is an exploratory companion to the deterministic
[capability tours](capability-tour.md). It starts a user-selected number of
real Aster agent processes, gives every process an independent identity and
redb store, and lets you publish messages through any running node's local
ConnectRPC API while watching the exact Event appear at other nodes.

This is deliberately an Event-only developer demo. Every node is a content
member for the same `mesh.messages` topic and can read every playground
message. It is not the payload-blind relay tour and must be used only with
synthetic data.

## Start a playground

Install the pinned tools, then choose between 2 and 32 nodes:

```sh
mise install
mise run playground -- --nodes 5
```

The playground runner currently targets Unix/POSIX hosts. Its disposable
unprotected-reference credential persistence fails closed on unsupported
platforms.

The wrapper builds `aster` and `aster-agent`, provisions disposable reference
credentials, and starts five independent operating-system processes on local
loopback sockets. The processes form a fixed line: node 0 contacts node 1,
node 1 contacts nodes 0 and 2, and so on. The default `auto` view opens a
dashboard on a capable terminal and otherwise prints progressive plain-text
updates. The dashboard keeps a command prompt visible; it does not hide
state-changing single-key shortcuts.

The node count is a startup choice and is intentionally capped at 32. It is not
an unlimited-node interface or evidence for the requirements' provisional
100-node-per-scope target.

One run accepts at most 1,024 publish attempts, and each UTF-8 message is
limited to 4,096 bytes. Start a fresh run for a new exploratory session; these
limits bound the controller's in-memory presence matrix and retained journal.
An RPC failure can leave durable acceptance uncertain, so failed publish calls
also consume an attempt rather than reusing an idempotency key.

## Send messages and change availability

The controller accepts:

| Command | Effect |
|---|---|
| `send NODE TEXT` | Publish `TEXT` as a durable Event through the named running node. |
| `isolate NODE` | Keep the node available to its local application while withdrawing it from playground contacts. |
| `rejoin NODE` | Restore the node's configured playground contacts so retained Events can move again. |
| `stop NODE` | Stop the selected node process without deleting its store. |
| `start NODE` | Restart the selected node from its retained store. |
| `status` | Show the current process, contact, and Event observations. |
| `assert-unseen MESSAGE NODE[,NODE...]` | Run one fresh exact local query at each ready node and require that `MESSAGE` is absent. |
| `quit` | Stop and reap the child processes, retain the run directory, and exit. |

For example:

```text
send 0 hello from the left
isolate 2
send 2 committed while peerless
rejoin 2
status
```

Local publish success means the selected node durably accepted the Event. The
view separately reports how many nodes have been directly observed to contain
that exact Event. A contact-status label or a quiet interval is never treated
as proof of global convergence.

`assert-unseen` is a one-shot local observation for scripts and demos. A pass
means only that the exact Event was absent from the completed QueryEvents view
at every named node. It says nothing about later arrival, unqueried nodes, or
global convergence.

Aster's application delivery boundary remains at least once. This is not an
exactly-once or real-time messaging service.

## Automation and terminal views

Choose an explicit view when capturing output or using a screen reader:

```sh
mise run playground -- --nodes 4 --view plain
mise run playground -- --nodes 4 --view raw
```

The views are:

- `auto`: use the dashboard only on a capable interactive terminal;
- `tui`: request the updating dashboard and persistent prompt;
- `plain`: emit sanitized progressive lines and a normal prompt;
- `raw`: emit controller JSON Lines on stdout while keeping child output in
  retained log files.

The playground sanitizes terminal text before display. Messages remain
application payloads, not trusted terminal control sequences.

## Retained run directory

The controller creates a fresh temporary root, prints its exact location, and
retains it after normal exit, failure, or interruption. It contains the
independent node stores, disposable unprotected-reference mission bundles,
owner-only local API tokens, a bounded rotating controller journal, and
bounded rotating recent agent output under `<root>/logs`. The numbered log
segments are inspection tails, not complete per-process acceptance receipts.
The journal and each node's stdout/stderr retain four 256 KiB segments; journal
rotation preserves complete JSON Lines records, while agent segments preserve
the bounded byte tail.

Ctrl-C and ordinary exit stop and reap the processes before returning status
to the shell; retention is intentional so failures can be inspected. The root
contains readable demo messages and test credentials. Do not commit it, reuse
its credentials, or place operational data in the playground.

## Exact claim boundary

The playground makes local application behavior visible; it is not an
acceptance receipt or a release profile. A successful run is bounded to:

- 2 through 32 real processes from one Aster build;
- one host, loopback sockets, manually prepared peers, and the fixed local
  playground topology;
- one authority, scope, epoch, and Event topic;
- same-implementation Event publication and observation through the alpha
  loopback ConnectRPC agent;
- all-member content access rather than payload-blind relaying; and
- disposable unprotected-reference provisioning.

It does not establish global convergence, an at-least-100-node scale result,
resource or performance limits, physical or multi-host operation, automatic
discovery, NAT behavior, controlled-relay fallback, BTLE, cross-transport or
mixed-implementation interoperability, State/Record/Blob live behavior,
protected operational provisioning, independent review, or production and
release authorization. Use the deterministic capability tours and
[requirements status](../validation/requirements-status.md) for their
separate evidence boundaries.
