# Aster operational quickstart

This Linux-only quickstart runs two real local Aster nodes behind one private
browser workbench.

This directory is a self-contained CLI candidate for team review. It is not
wired into the Cargo workspace, release packaging, or the existing `aster`
command; that integration is a separate decision.

## Run

Put compatible `aster`, `aster-agent`, and `asterctl` executables in one
directory, then run:

```sh
./quickstart --bin-dir /path/to/aster/bin
```

In the browser: start Publisher, start Receiver, authenticate the pair, then
send an Event. **Committed at Publisher** means Aster returned a durable
publication receipt. **Received at Receiver** means the other node observed
the same Event identifier and payload.

Expand any collapsible workflow step under **Command transcript** to see its
real commands, internal operations, working directories, results, and separate
input/output streams. Each command or stream has a contextual copy button. The
view keeps at most 128 entries and 65,536 bytes per stream; it labels truncated
output, redacted arguments, and commands that are unsafe to replay. This
evidence stays local to the disposable
process; cleanup removes its workspace, and ending the quickstart discards the
transcript.

The browser remains the control surface. Optional observer terminals do not own
the nodes:

```sh
./quickstart attach publisher --detail guided
./quickstart attach receiver --detail debug
```

Output detail can be `compact`, `guided` (the default), or `debug`. If a desktop
terminal cannot open, copy the command shown by the browser; live browser output
continues. Press `Ctrl-C` in the launcher or choose **Clean up everything** to
stop owned processes and remove the disposable workspace.

After one successful delivery, the browser offers a separate optional
transport-unavailable experiment. It is not part of first-run setup.

This is a loopback UX evaluation. It is not a BTLE test, hardware qualification,
production deployment, or protocol/API change.
