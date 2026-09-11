#!/usr/bin/env bash
# Build the CI-only interpreter against the Ubuntu runner's native libc.
# See docs/ci-python.md for exact source provenance and the mise selection contract.
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?CI runner scratch directory is required}"
: "${GITHUB_PATH:?GitHub Actions PATH output is required}"
: "${MISE_PYTHON_VERSION:?An explicit mise Python path is required}"
[[ "$(uname -s)" == Linux ]]
prefix="$RUNNER_TEMP/aster-ci-python-3.13.7"
[[ "$MISE_PYTHON_VERSION" == "path:$prefix" ]]
# Never reuse an unverified pre-existing installation or download/build tree.
mkdir "$prefix"
build_root="$(mktemp -d "$RUNNER_TEMP/aster-ci-python-build.XXXXXX")"
cd "$build_root"
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  --tlsv1.2 --connect-timeout 30 --max-time 180 \
  https://www.python.org/ftp/python/3.13.7/Python-3.13.7.tar.xz \
  --output Python-3.13.7.tar.xz
printf '%s  %s\n' \
  5462f9099dfd30e238def83c71d91897d8caa5ff6ebc7a50f14d4802cdaaa79a \
  Python-3.13.7.tar.xz | sha256sum --check --strict
tar -xf Python-3.13.7.tar.xz
cd Python-3.13.7
# No moving pyenv/python-build checkout, PGO/LTO workload, or pip installation.
./configure --prefix="$prefix" --with-ensurepip=no
make -j2
make install
"$prefix/bin/python3" -c 'import bz2, ctypes, hashlib, lzma, sqlite3, ssl, zlib; import os; assert hasattr(os, "POSIX_SPAWN_CLOSEFROM")'
printf '%s\n' "$prefix/bin" >> "$GITHUB_PATH"
