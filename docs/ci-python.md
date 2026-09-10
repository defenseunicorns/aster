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
