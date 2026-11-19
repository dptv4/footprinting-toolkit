#!/usr/bin/env python3
"""Command execution helpers with dry-run and external-tool checks."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Sequence

from rich.console import Console

console = Console(stderr=True)


@dataclass(slots=True)
class CmdResult:
    """Outcome of an external command invocation."""

    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float


def run_cmd(
    cmd: list[str],
    *,
    timeout: int = 120,
    dry_run: bool = False,
) -> CmdResult:
    """Run *cmd* and return a :class:`CmdResult`.

    When ``dry_run`` is true the command is only printed (returncode ``0``,
    empty stdout/stderr, duration ``0.0``) and nothing is executed.
    """
    pretty = " ".join(cmd)

    if dry_run:
        # Escape opening bracket so rich does not treat [dry-run] as a style tag.
        console.print(f"[cyan]\\[dry-run][/cyan] {pretty}")
        return CmdResult(
            cmd=list(cmd),
            returncode=0,
            stdout="",
            stderr="",
            duration=0.0,
        )

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        duration = time.perf_counter() - started
        return CmdResult(
            cmd=list(cmd),
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            duration=duration,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.perf_counter() - started
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        console.print(
            f"[yellow]Timeout[/yellow] after {timeout}s: {pretty}"
        )
        return CmdResult(
            cmd=list(cmd),
            returncode=124,
            stdout=stdout,
            stderr=stderr or f"timed out after {timeout}s",
            duration=duration,
        )
    except OSError as exc:
        duration = time.perf_counter() - started
        console.print(f"[red]Failed to run[/red] {pretty}: {exc}")
        return CmdResult(
            cmd=list(cmd),
            returncode=127,
            stdout="",
            stderr=str(exc),
            duration=duration,
        )


def tool_available(name: str) -> bool:
    """Return True if *name* resolves on ``PATH``."""
    return shutil.which(name) is not None


def require_tools(tools: Sequence[str]) -> list[str]:
    """Warn about missing tools and return the ones that are available.

    Missing tools are reported with rich; checks are skipped rather than
    aborting the process. Callers should only run commands for the returned
    (available) tool names.
    """
    available: list[str] = []
    missing: list[str] = []

    for name in tools:
        if tool_available(name):
            available.append(name)
        else:
            missing.append(name)

    if missing:
        listed = ", ".join(missing)
        console.print(
            f"[yellow]Missing tools[/yellow]: {listed} — "
            "skipping related checks (install them to enable)."
        )

    return available


def check_root() -> bool:
    """Return True if running as root; otherwise warn and return False.

    Use before privileged scans (e.g. ``nmap -sU``).
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True

    console.print(
        "[yellow]Root required[/yellow] for this check "
        "(e.g. nmap -sU) — skipping."
    )
    return False
