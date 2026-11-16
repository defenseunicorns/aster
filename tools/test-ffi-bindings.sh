#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Real local ABI tests; no transport, operational credentials or external services.
set -eu
umask 077
cargo build --locked -p aster-ffi --examples
cargo build --locked -p aster-ffi
cc -std=c11 -Wall -Wextra -Werror -pedantic -Ibindings/c -fsyntax-only bindings/c/header_smoke.c
c++ -std=c++17 -Wall -Wextra -Werror -pedantic -Ibindings/c -fsyntax-only bindings/c/header_smoke.cpp
task_root=$(mktemp -d /tmp/aster-ffi-bindings.XXXXXX)
trap 'rm -rf "$task_root"' EXIT HUP INT TERM
cc -std=c11 -Wall -Wextra -Werror -pedantic -Ibindings/c bindings/c/runtime_smoke.c \
    -Ltarget/debug -laster_ffi -Wl,-rpath,"$(pwd)/target/debug" -o "$task_root/c-smoke"
target/debug/examples/prepare_binding_test_state "$task_root/testdata"
"$task_root/c-smoke" "$task_root/testdata/state" "$task_root/testdata/mission.bundle"
python3 -m unittest discover -s bindings/python/tests
GOCACHE=${GOCACHE:-/tmp/aster-mesh-go-cache} go -C bindings/go test -count=1 -tags aster_workspace ./...
# Run all three public examples against the same durable state: the stable
# operation key must retry exactly across languages and process restarts.
mkdir "$task_root/examples"
target/debug/examples/prepare_binding_test_state "$task_root/examples/testdata"
cc -std=c11 -Wall -Wextra -Werror -pedantic -Ibindings/c examples/c_basic.c \
    -Ltarget/debug -laster_ffi -Wl,-rpath,"$(pwd)/target/debug" -o "$task_root/c-example"
"$task_root/c-example" "$task_root/examples/testdata/mission.bundle" "$task_root/examples/testdata/state"
PYTHONPATH=bindings/python python3 examples/python_basic.py \
    "$task_root/examples/testdata/mission.bundle" "$task_root/examples/testdata/state"
GOCACHE=${GOCACHE:-/tmp/aster-mesh-go-cache} go -C bindings/go run -tags aster_workspace ../../examples/go_basic.go \
    "$task_root/examples/testdata/mission.bundle" "$task_root/examples/testdata/state"
