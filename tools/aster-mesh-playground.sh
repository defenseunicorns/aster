#!/bin/sh

set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
presenter="$script_dir/aster_tour_ui.py"
playground="$script_dir/aster_mesh_playground.py"
view_mode="${ASTER_PLAYGROUND_VIEW:-auto}"
aster_bin="${ASTER_PLAYGROUND_ASTER_BIN:-}"
agent_bin="${ASTER_PLAYGROUND_AGENT_BIN:-}"
cli_bin="${ASTER_PLAYGROUND_CLI_BIN:-}"

view_value_pending=0
for playground_argument in "$@"; do
  if [ "$view_value_pending" -eq 1 ]; then
    view_mode="$playground_argument"
    view_value_pending=0
    continue
  fi
  case "$playground_argument" in
    --aster|--aster=*|--agent|--agent=*|--cli|--cli=*)
      echo "--aster, --agent and --cli are wrapper-managed options" >&2
      exit 2
      ;;
    --view) view_value_pending=1 ;;
    --view=*) view_mode="${playground_argument#--view=}" ;;
  esac
done
if [ "$view_value_pending" -eq 1 ]; then
  echo "--view requires a value" >&2
  exit 2
fi

case "$view_mode" in
  auto|tui|plain|raw) ;;
  *)
    echo "ASTER_PLAYGROUND_VIEW must be one of: auto, tui, plain, raw" >&2
    exit 2
    ;;
esac

if { [ -n "$aster_bin" ] && [ -z "$agent_bin" ]; } ||
   { [ -z "$aster_bin" ] && [ -n "$agent_bin" ]; }; then
  echo "ASTER_PLAYGROUND_ASTER_BIN and ASTER_PLAYGROUND_AGENT_BIN must be set together" >&2
  exit 2
fi

if [ ! -r "$presenter" ]; then
  echo "playground build presenter is not readable: $presenter" >&2
  exit 2
fi
if [ ! -r "$playground" ]; then
  echo "playground application is not readable: $playground" >&2
  exit 2
fi

extract_binary() {
  receipt="$1"
  target="$2"
  python3 -c 'import json, sys
objects = (json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip())
paths = [obj["executable"] for obj in objects if obj.get("reason") == "compiler-artifact" and obj.get("executable") and obj.get("target", {}).get("name") == sys.argv[2] and "bin" in obj.get("target", {}).get("kind", [])]
if not paths:
    raise SystemExit(f"build receipt contains no executable for {sys.argv[2]}")
print(paths[-1])' "$receipt" "$target"
}

if [ -z "$aster_bin" ] || [ -z "$agent_bin" ]; then
  if [ -n "${ASTER_PLAYGROUND_BUILD_PARENT:-}" ]; then
    build_parent="$ASTER_PLAYGROUND_BUILD_PARENT"
    mkdir -p "$build_parent"
  else
    playground_tmp_root="${TMPDIR:-/tmp}"
    build_parent="$(mktemp -d "${playground_tmp_root%/}/aster-playground-build.XXXXXX")"
  fi
  build_receipt="$build_parent/cargo-build.json"
  build_stderr="$build_parent/cargo-build.stderr"
  if [ -e "$build_receipt" ] || [ -e "$build_stderr" ]; then
    echo "playground build parent already contains retained output: $build_parent" >&2
    exit 2
  fi

  if python3 "$presenter" build \
    --view "$view_mode" \
    --stdout-receipt "$build_receipt" \
    --stderr-receipt "$build_stderr" -- \
    cargo build --locked --manifest-path "$repo_root/Cargo.toml" \
      -p aster-node -p aster-agent -p asterctl --bins \
      --features aster-agent/nearby-discovery --message-format=json; then
    :
  else
    build_status=$?
    echo "Playground build receipts retained under: $build_parent" >&2
    exit "$build_status"
  fi

  if [ -z "$aster_bin" ]; then
    if aster_bin="$(extract_binary "$build_receipt" aster)"; then
      :
    else
      extract_status=$?
      echo "Playground build receipts retained under: $build_parent" >&2
      exit "$extract_status"
    fi
  fi
  if [ -z "$agent_bin" ]; then
    if agent_bin="$(extract_binary "$build_receipt" aster-agent)"; then
      :
    else
      extract_status=$?
      echo "Playground build receipts retained under: $build_parent" >&2
      exit "$extract_status"
    fi
  fi
  if [ -z "$cli_bin" ]; then
    cli_bin="$(extract_binary "$build_receipt" asterctl)"
  fi
fi

if [ -z "$cli_bin" ]; then
  cli_bin="$(dirname "$agent_bin")/asterctl"
fi
if [ ! -x "$cli_bin" ]; then
  echo "ASTER_PLAYGROUND_CLI_BIN is not executable: $cli_bin" >&2
  exit 2
fi

if [ ! -x "$aster_bin" ]; then
  echo "ASTER_PLAYGROUND_ASTER_BIN is not executable: $aster_bin" >&2
  exit 2
fi
if [ ! -x "$agent_bin" ]; then
  echo "ASTER_PLAYGROUND_AGENT_BIN is not executable: $agent_bin" >&2
  exit 2
fi

aster_bin_dir="$(CDPATH= cd -- "$(dirname -- "$aster_bin")" && pwd)"
aster_bin="$aster_bin_dir/$(basename -- "$aster_bin")"
agent_bin_dir="$(CDPATH= cd -- "$(dirname -- "$agent_bin")" && pwd)"
agent_bin="$agent_bin_dir/$(basename -- "$agent_bin")"

# Replace the wrapper so terminal signals and the playground's exact status
# cross this final process boundary unchanged.
exec python3 "$playground" \
  --aster "$aster_bin" \
  --agent "$agent_bin" \
  --cli "$cli_bin" \
  --view "$view_mode" \
  "$@"
