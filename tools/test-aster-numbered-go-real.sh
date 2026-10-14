#!/bin/sh
# Clean Room — Privileged: local protocol interoperability, no qualification credit.
set -eu
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
task_root="$(mktemp -d "${TMPDIR:-/tmp}/aster-numbered-go-binaries.XXXXXX")"
cleanup() { rm -rf -- "$task_root"; }
trap cleanup EXIT HUP INT TERM
cargo build --locked -p aster-agent --bin aster-agent-acceptance-fixture --features client,acceptance-test-provider
go -C "$script_dir/../conformance/agent-go" build -o "$task_root/agent-smoke" ./cmd/agent-smoke
go -C "$script_dir/../conformance/agent-go" build -o "$task_root/agent-load" ./cmd/agent-load
python3 "$script_dir/test-aster-numbered-go-real.py" \
  --fixture "$script_dir/../target/debug/aster-agent-acceptance-fixture" \
  --client "$task_root/agent-smoke" --load "$task_root/agent-load"
