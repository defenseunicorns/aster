#!/bin/sh

set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
scenario="$script_dir/testdata/aster-mesh-playground-real.commands"

if [ ! -r "$scenario" ]; then
  echo "playground smoke scenario is not readable: $scenario" >&2
  exit 2
fi

# The playground wrapper builds the node, agent, and journaled publication CLI and replaces itself with the
# controller. Its status is therefore the exact result of every wait in this
# real three-agent scenario.
exec sh "$script_dir/aster-mesh-playground.sh" \
  --nodes 3 \
  --view raw \
  --script "$scenario"
