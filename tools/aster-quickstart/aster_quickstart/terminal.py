"""Minimal Linux terminal launcher for optional quickstart observers."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import subprocess

from .transcript import TranscriptJournal


_MAX_ARGUMENTS = 64
_MAX_ARGUMENT_BYTES = 4_096


@dataclass(frozen=True)
class ObserverCommand:
    """One observer invocation with an explicit launch working directory."""

    argv: tuple[str, ...]
    cwd: Path

    def __post_init__(self) -> None:
        if isinstance(self.argv, (str, bytes)) or not self.argv or len(self.argv) > _MAX_ARGUMENTS:
            raise ValueError("observer argv is invalid")
        if any(
            type(argument) is not str
            or not argument
            or "\x00" in argument
            or len(argument.encode()) > _MAX_ARGUMENT_BYTES
            for argument in self.argv
        ):
            raise ValueError("observer argv is invalid")
        if not isinstance(self.cwd, Path) or not self.cwd.is_absolute():
            raise ValueError("observer cwd must be an absolute Path")

    def copyable(self) -> str:
        """Render an explicit shell command for a user-controlled terminal."""

        return f"cd -- {shlex.quote(str(self.cwd))} && {shlex.join(self.argv)}"

    def __iter__(self) -> Iterator[str]:
        """Keep existing terminal callback seams compatible with argv iteration."""

        return iter(self.argv)


def _normalize_command(argv: ObserverCommand | Sequence[str]) -> ObserverCommand | None:
    if isinstance(argv, ObserverCommand):
        return argv
    if isinstance(argv, (str, bytes)):
        return None
    try:
        return ObserverCommand(tuple(argv), Path.cwd())
    except (TypeError, ValueError):
        return None


def open_terminal(
    argv: ObserverCommand | Sequence[str],
    executable: Path = Path("/usr/bin/x-terminal-emulator"),
    *,
    transcript: TranscriptJournal | None = None,
    transcript_step: str = "setup",
) -> bool:
    """Launch one observer using the verified x-terminal-emulator contract."""

    observer = _normalize_command(argv)
    if observer is None:
        return False
    arguments = list(observer.argv)
    if not observer.cwd.is_dir():
        return False
    command = [str(executable), "-e", *arguments]
    handle = (
        transcript.start_command(transcript_step, command, cwd=str(observer.cwd))
        if transcript is not None
        else None
    )
    if (
        not isinstance(executable, Path)
        or not executable.is_absolute()
        or not executable.exists()
        or not os.access(executable, os.X_OK)
    ):
        if handle is not None:
            handle.finish(None, outcome="launch failed")
        return False
    try:
        subprocess.Popen(
            command,
            close_fds=True,
            cwd=str(observer.cwd),
            start_new_session=True,
        )
    except OSError:
        if handle is not None:
            handle.finish(None, outcome="spawn failed")
        return False
    if handle is not None:
        handle.finish(None, outcome="spawned")
    return True


__all__ = ["ObserverCommand", "open_terminal"]
