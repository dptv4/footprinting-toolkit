#!/usr/bin/env python3
"""FTP enumeration: banner, anonymous access, nmap scripts, write-perm inference."""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import load_latest, render_table, save_report
from core.runner import require_tools, run_cmd

console = Console()

MODULE_NAME = "ftp"
DEFAULT_PORT = 21
DEFAULT_TIMEOUT = 30
NMAP_SCRIPTS = "ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor"

# Unix LIST permission token, e.g. drwxrwxrwx or -rw-r--r--
_PERM_RE = re.compile(r"^([bcdlps\-])([r\-][w\-][xsS\-]){3}")


def register_parser(parser: argparse.ArgumentParser) -> None:
    """Single source of truth for CLI flags/defaults (used by main.py and __main__)."""
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="FTP host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="FTP host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"FTP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Socket / command timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned actions / commands without connecting",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use target from the latest report when positional/-t is omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path for JSON report (writes sibling .md too)",
    )


def _resolve_target(args: argparse.Namespace) -> str | None:
    target = args.target_flag or args.target
    if target:
        return target

    if not args.latest:
        return None

    for module in (MODULE_NAME, "discovery"):
        report = load_latest(module)
        if not report:
            continue
        if report.get("target"):
            return str(report["target"])
        data = report.get("data") or {}
        ports = data.get("ports") or data.get("open_ports") or []
        for entry in ports:
            if int(entry.get("port", -1)) == args.port or str(
                entry.get("service", "")
            ).lower() in {"ftp", "ftp-data"}:
                host = entry.get("host") or report.get("target")
                if host:
                    return str(host)
    return None


def _grab_banner(host: str, port: int, timeout: int, dry_run: bool) -> dict[str, Any]:
    result: dict[str, Any] = {"host": host, "port": port, "banner": None, "error": None}
    if dry_run:
        console.print(
            f"[cyan]\\[dry-run][/cyan] banner grab tcp://{host}:{port} (timeout={timeout}s)"
        )
        return result

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            raw = sock.recv(1024)
        banner = raw.decode("utf-8", errors="replace").strip()
        result["banner"] = banner
        console.print(f"[green]Banner[/green]: {banner}")
    except OSError as exc:
        result["error"] = str(exc)
        console.print(f"[yellow]Banner failed[/yellow]: {exc}")
    return result


def _parse_list_write_hints(listing: list[str]) -> list[dict[str, Any]]:
    """Infer possible write access from LIST permission bits (no uploads)."""
    hints: list[dict[str, Any]] = []
    for line in listing:
        parts = line.split(maxsplit=8)
        if len(parts) < 9:
            continue
        perms = parts[0]
        name = parts[8]
        match = _PERM_RE.match(perms)
        if not match:
            continue
        # other-write bit (index 8 in drwxrwxrwx) or owner/group write on dirs
        other_write = len(perms) >= 9 and perms[8] == "w"
        group_write = len(perms) >= 6 and perms[5] == "w"
        is_dir = perms[0] == "d"
        if other_write or (is_dir and group_write and name in {".", "./"}):
            hints.append(
                {
                    "name": name,
                    "perms": perms,
                    "other_write": other_write,
                    "group_write": group_write,
                    "is_dir": is_dir,
                }
            )
    return hints


def _anonymous_enum(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "anonymous_login": False,
        "welcome": None,
        "listing": [],
        "write_hints": [],
        "error": None,
    }
    if dry_run:
        console.print(
            f"[cyan]\\[dry-run][/cyan] ftplib anonymous login + LIST "
            f"{host}:{port} (timeout={timeout}s); write check via LIST perms only"
        )
        return result

    import ftplib

    ftp: ftplib.FTP | None = None
    try:
        ftp = ftplib.FTP()
        ftp.connect(host=host, port=port, timeout=timeout)
        result["welcome"] = (ftp.getwelcome() or "").strip()
        ftp.login(user="anonymous", passwd="anonymous@")
        result["anonymous_login"] = True
        console.print("[green]Anonymous login[/green]: success")

        listing: list[str] = []
        try:
            ftp.retrlines("LIST", listing.append)
        except ftplib.error_perm as exc:
            result["error"] = f"LIST failed: {exc}"
            console.print(f"[yellow]LIST failed[/yellow]: {exc}")
        result["listing"] = listing
        if listing:
            render_table(
                [{"line": line} for line in listing[:50]],
                title=f"FTP LIST (anonymous) — {host}:{port}",
            )

        # Permission inference only — never STOR/APPE/MKD upload or create.
        hints = _parse_list_write_hints(listing)
        result["write_hints"] = hints
        if hints:
            console.print(
                "[yellow]Possible writable paths (from LIST perms only)[/yellow]:"
            )
            render_table(hints, title="Write permission hints")
        else:
            console.print(
                "[dim]No world/group-write hints in LIST "
                "(inference only; no files uploaded).[/dim]"
            )
    except ftplib.error_perm as exc:
        result["error"] = str(exc)
        console.print(f"[yellow]Anonymous login denied[/yellow]: {exc}")
    except (OSError, EOFError, ftplib.Error) as exc:
        result["error"] = str(exc)
        console.print(f"[yellow]FTP error[/yellow]: {exc}")
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:  # noqa: BLE001
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001
                    pass

    return result


def _nmap_ftp_scripts(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ran": False,
        "cmd": [],
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }
    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-p",
        str(port),
        "--script",
        NMAP_SCRIPTS,
        host,
    ]
    result["cmd"] = cmd

    # Always show the planned command in dry-run; still warn if nmap is absent.
    available = require_tools(["nmap"])
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        return result

    if "nmap" not in available:
        return result

    cmd_result = run_cmd(cmd, timeout=timeout, dry_run=False)
    result["ran"] = True
    result["returncode"] = cmd_result.returncode
    result["stdout"] = cmd_result.stdout
    result["stderr"] = cmd_result.stderr
    if cmd_result.stdout.strip():
        console.print(cmd_result.stdout.rstrip())
    return result


def _write_output(path: str, module: str, target: str, data: dict[str, Any]) -> Path:
    out = Path(path)
    if out.is_dir() or str(path).endswith(("/", "\\")):
        out.mkdir(parents=True, exist_ok=True)
        json_path = out / f"{module}_{target.replace('/', '_')}.json"
    else:
        json_path = out if out.suffix == ".json" else out.with_suffix(".json")
        json_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {"module": module, "target": target, "data": data}
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    md_path = json_path.with_suffix(".md")
    md_path.write_text(
        f"# Report: `{module}`\n\n**target:** `{target}`\n\n```json\n"
        f"{json.dumps(data, indent=2, ensure_ascii=False, default=str)}\n```\n",
        encoding="utf-8",
    )
    console.print(f"[green]Wrote[/green]: {json_path}")
    return json_path


def run(args: argparse.Namespace) -> int:
    """Execute FTP enumeration for the resolved target."""
    target = _resolve_target(args)
    if not target:
        console.print(
            "[red]Target required[/red]: pass positional TARGET, -t/--target, "
            "or --latest with an existing report."
        )
        return 2

    port: int = args.port
    timeout: int = args.timeout
    dry_run: bool = bool(args.dry_run)

    console.print(
        f"[bold]FTP enum[/bold] → {target}:{port}"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )

    data: dict[str, Any] = {
        "port": port,
        "timeout": timeout,
        "dry_run": dry_run,
        "banner": _grab_banner(target, port, timeout, dry_run),
        "anonymous": _anonymous_enum(target, port, timeout, dry_run),
        "nmap": _nmap_ftp_scripts(target, port, timeout, dry_run),
    }

    if not dry_run:
        save_report(MODULE_NAME, target, data)
        if args.output:
            _write_output(args.output, MODULE_NAME, target, data)
    else:
        console.print(
            f"[cyan]\\[dry-run][/cyan] skip save_report "
            f"(would write reports/{MODULE_NAME}_{target}_<timestamp>.json)"
        )
        if args.output:
            console.print(f"[cyan]\\[dry-run][/cyan] skip -o/--output {args.output}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ftp_enum.py",
        description="FTP enumeration (banner, anonymous, nmap scripts, write hints).",
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
