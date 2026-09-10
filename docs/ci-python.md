# CI Python safe-spawn interpreter

The Ubuntu 24.04 `quality` lane builds **CPython 3.13.7** from its exact public
source archive before installing the remaining mise toolchain. This is CI-only
maintenance, not a new product dependency, supported release artifact, or a
requirements-evidence promotion. Other jobs and the repository's Python version
pin are unchanged.

## Why source-build this pin

The previously selected Python-build-standalone 3.13.7 Linux archive was compiled
without `HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDCLOSEFROM_NP`. A newer runner libc alone
cannot expose a CPython constant omitted at compile time. The stock
`SignalSafePopen` requires close-from descriptor actions, a new session, and
atomic child signal-mask restoration; its fail-closed behavior is unchanged.

Building the official release with the runner's native compiler/libc lets
CPython's own configure check detect `posix_spawn_file_actions_addclosefrom_np`.
No CPython patches, subprocess fallback, moving pyenv/python-build checkout,
new package manager, pip dependencies, PGO, or LTO are introduced. The build
uses two make jobs and a 15-minute step deadline within the existing 45-minute
quality-job budget. It fails rather than reusing a pre-existing installation.
Required standard-library extension imports are checked after installation.

This pins source input, **not bit-for-bit binary reproducibility**: the hosted
Ubuntu image, compiler, libc, and development headers remain runner-provided
inputs. Source compilation and total job timing must be qualified on actual CI.

## Ubuntu build prerequisites

Run [34524164653](https://github.com/edgesoftops/astertech/actions/runs/34524164653/job/103028850660)
at `cb7a77dfda7a671a9a0997496dede24ec584d78e` completed compilation and
installation, then failed the required import with `No module named '_bz2'`.
Configure had reported both `bzlib.h` and `lzma.h` absent and both `_bz2` and
`_lzma` missing. Fixing only bzip2 would leave the next required import broken.
The other required native modules (`_ctypes`, `_hashlib`, `_sqlite3`, `_ssl`,
and `zlib`) were detected. Configure also reported `_dbm`, `_gdbm`, `readline`,
`_tkinter`, and `_uuid` missing; these are not in this CI interpreter's required
import contract and this change does not add their development packages.

Before configuring CPython, the quality lane explicitly installs the following
native build inputs, using the Ubuntu 24.04 runner's configured APT repositories
and normal signature verification. It does not add a PPA, external repository,
pip package, or product dependency. The five-minute prerequisite step does not
increase the existing 45-minute job or 15-minute source-build deadlines.

| Ubuntu package / public source | Observed Noble revision (2026-09-10) | Build role |
| --- | --- | --- |
| [build-essential](https://packages.ubuntu.com/noble/build-essential) | `12.10ubuntu1` | Native compiler, libc development files, and make |
| [pkg-config](https://packages.ubuntu.com/noble/pkg-config) | `1.8.1-2build1` | Configure library discovery |
| [libbz2-dev](https://packages.ubuntu.com/noble/libbz2-dev) | `1.0.8-5.1ubuntu0.1` | `bzlib.h` and bzip2 link input for `bz2` |
| [libffi-dev](https://packages.ubuntu.com/noble/libffi-dev) | `3.4.6-1build1` | `ctypes` |
| [liblzma-dev](https://packages.ubuntu.com/noble/liblzma-dev) | `5.6.1+really5.4.5-1ubuntu0.3` | `lzma.h` and liblzma link input for `lzma` |
| [libsqlite3-dev](https://packages.ubuntu.com/noble/libsqlite3-dev) | `3.45.1-1ubuntu2.7` | `sqlite3` |
| [libssl-dev](https://packages.ubuntu.com/noble/libssl-dev) | `3.0.13-0ubuntu3.15` | `ssl` and OpenSSL-backed `hashlib` |
| [zlib1g-dev](https://packages.ubuntu.com/noble/zlib1g-dev) | `1:1.3.dfsg-3.1ubuntu2.2` | `zlib` |

These are observed package-page revisions, **not exact APT install pins**.
Like the existing hosted-image compiler/libc inputs, they follow the configured
Noble archive/security updates. The step logs actual installed package versions
with `dpkg-query`; those run-specific direct-package versions, not this observation
table, are the direct-package build receipt, not complete compiler/libc or
transitive-library provenance. This deliberately avoids freezing obsolete security revisions
or claiming a reproducible Ubuntu snapshot. CPython's exact source version and
SHA-256 remain unchanged. Public package pages establish availability, not a
successful install or build on the next runner. The owner explicitly approved in
the task conversation this narrow CI-only policy: official Ubuntu 24.04/Noble
distro-managed packages, including security updates, with logged installed
direct-package versions rather than exact pins for every APT revision. This is
policy approval only, not release/publication approval, a governance waiver, a
full SBOM, or a reproducible-build claim. It does not renew authorization for
the blocked additional mutation-test execution; independent review and actual
Linux verification remain required.

Regression tests execute the prerequisite shell with intercepted package calls,
requiring update-before-install with `APT::Update::Error-Mode=any`, the complete
required package set, the package/version receipt format, and immediate failure
on nonzero update/install exits. The [Noble apt-get manual](https://manpages.ubuntu.com/manpages/noble/en/man8/apt-get.8.html)
documents this error mode as failing update on any error, including transient
errors; the local tests intercept calls and do not reproduce real APT failures.
A workflow-order guard
requires prerequisites before the source build. Each of the seven existing
required imports is independently fault-injected into the real post-install
validation: every missing module must fail before publishing `GITHUB_PATH`.
The imports, close-from assertion, and stock safe-spawn implementation are not
weakened. These local tests do not replace a real reviewed Linux run: mise setup,
the direct/nested preflight, full process suite, full quality gate, and stock
smoke were all skipped in the failed run.

## Public source registration

| Component | Version / license | Source and role |
| --- | --- | --- |
| CPython | 3.13.7 / PSF License Version 2 plus bundled notices | [Official release](https://www.python.org/downloads/release/python-3137/); [source archive](https://www.python.org/ftp/python/3.13.7/Python-3.13.7.tar.xz). CI test interpreter only. |
| mise | 2026.4.28 / MIT | Existing pinned toolchain manager; [tagged source](https://github.com/jdx/mise/tree/v2026.4.28). No new mise version or installation mechanism. |

Archive SHA-256:

```text
5462f9099dfd30e238def83c71d91897d8caa5ff6ebc7a50f14d4802cdaaa79a
```

The digest was computed from the official HTTPS archive and independently
matched to the `messageDigest` in its official
[Sigstore bundle](https://www.python.org/ftp/python/3.13.7/Python-3.13.7.tar.xz.sigstore).
That comparison is **not cryptographic Sigstore signature verification**. CI
verifies the reviewed SHA-256 before extracting or building the archive; TLS
verification remains enabled.

## Interpreter consistency, including nested mise

After checkout, an initialization run step resolves `$RUNNER_TEMP` and writes
`MISE_PYTHON_VERSION=path:<RUNNER_TEMP>/aster-ci-python-3.13.7` to `$GITHUB_ENV`
before the build and mise setup action. GitHub's [context-availability table](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability)
does not allow `runner` in job-level `env` (it is allowed in step-level `env`).
The [environment-file contract](https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-an-environment-variable)
makes this selection available to all subsequent steps in the job, not to the
initialization step itself. No step-local override replaces that selection.
The install prefix exists before mise runs. `GITHUB_PATH` selects the same
prefix for direct `python3` commands, but PATH is not the sole override:

- [ToolsetBuilder](https://github.com/jdx/mise/blob/v2026.4.28/src/toolset/builder.rs)
  loads runtime `MISE_*_VERSION` selections after config-file versions.
- [ToolRequest](https://github.com/jdx/mise/blob/v2026.4.28/src/toolset/tool_request.rs)
  parses `path:` as an explicit tool prefix.
- [ToolVersion](https://github.com/jdx/mise/blob/v2026.4.28/src/toolset/tool_version.rs)
  canonicalizes that prefix and uses it as the install path.
- The [backend default](https://github.com/jdx/mise/blob/v2026.4.28/src/backend/mod.rs)
  uses the runtime prefix's `bin`; the
  [Python backend](https://github.com/jdx/mise/blob/v2026.4.28/src/plugins/core/python.rs)
  only overrides that behavior on Windows.

Before any acceptance work, CI runs the preflight directly and through
`mise exec -- mise run ci-python-preflight`. Both must resolve exactly the
selected interpreter. This exercises two real mise resolution boundaries and a
real mise task without changing the stock smoke task. The job-scoped override
also remains available to `mise run check` and its recursive tasks.

The preflight imports the **unchanged stock `SignalSafePopen`** and starts a
bounded child with standard I/O redirection and `close_fds=True`. The child must
report the exact executable/version, its own session, an empty signal mask
although the parent blocked SIGUSR1, and closure of a deliberately inheritable
file descriptor. Any mismatch or unsupported safe-spawn operation fails the
step. Timeouts kill and reap the child; the parent mask and descriptor are
restored/closed on all exits. Regression tests cover absent selection, wrong
interpreter, and the real local interpreter's supported-or-rejected outcome.

## Acceptance mapping

| Required behavior | Quality-lane command | Evidence boundary |
| --- | --- | --- |
| Compatible exact interpreter and real nested selection | `python3 .github/scripts/check-ci-python.py`; `mise exec -- mise run ci-python-preflight` | Must pass on Ubuntu 24.04; local rejection is not a Linux pass. |
| Entire Python process contract suite | `python3 tools/test-aster-agent-process.py` | No filtering, skips added to the suite, or softened oracles. |
| Existing repository quality gate | `mise run check` | Existing locked/offline Rust quality behavior retained. |
| Stock real-process and Go client recovery smoke | `mise run agent-process-smoke` | Existing fixture build, prepare contract, checker, and cleanup unchanged. |

`required` already demands literal success from `quality`. No conditional bypass
or `continue-on-error` is added. Independent review must precede commit/push;
actual Linux execution remains necessary before claiming this gate passes.
