#!/usr/bin/env python3
"""NFS enumeration: rpcinfo, showmount/exports, optional read-only mount listing."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import load_latest, render_table, save_report
from core.runner import check_root, require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "nfs"
DEFAULT_PORT = 2049
DEFAULT_TIMEOUT = 120
NMAP_SCRIPTS = "rpcinfo,nfs-ls,nfs-showmount,nfs-statfs"
NFS_RPC_PROGRAMS = ("nfs", "mountd", "nlockmgr")

# showmount -e lines: "/export client1,client2" or "/export *"
_EXPORT_RE = re.compile(
    r"^(?P<path>/\S*)\s+(?P<clients>.+?)\s*$"
)
_EVERYONE_TOKENS = {
    "*",
    "everyone",
    "(everyone)",
    "world",
    "0.0.0.0",
    "0.0.0.0/0",
    "::/0",
    "<world>",
}


def _result(
    check: str,
    command: str | list[str],
    status: str,
    summary: str,
    raw: Any = None,
) -> dict[str, Any]:
    cmd = command if isinstance(command, str) else " ".join(command)
    return {
        "check": check,
        "command": cmd,
        "status": status,
        "summary": summary,
        "raw": raw if raw is not None else {},
    }


def register_parser(parser: argparse.ArgumentParser) -> None:
    """Single source of truth for CLI flags/defaults (used by main.py and __main__)."""
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="NFS host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="NFS host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Preferred NFS port (default: {DEFAULT_PORT}; nmap probes 111,2049)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Command timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned commands without connecting",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use target/ports from the latest discovery report when omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path for JSON report (writes sibling .md too)",
    )
    parser.add_argument(
        "--mount-check",
        action="store_true",
        help=(
            "If root: mount each export read-only (-o ro,nolock) under a temp dir, "
            "list with ls -ln, then always unmount (never writes)"
        ),
    )


def _resolve_target_and_ports(
    args: argparse.Namespace,
) -> tuple[str | None, list[int]]:
    """Resolve target; with --latest also recover open NFS-related ports from discovery."""
    target = args.target_flag or args.target
    ports: list[int] = [111, 2049]

    if args.latest:
        report = load_latest("discovery")
        if report:
            if not target and report.get("target"):
                target = str(report["target"])
            data = report.get("data") or {}
            discovered = data.get("ports") or data.get("open_ports") or []
            found_ports: list[int] = []
            for entry in discovered:
                try:
                    port = int(entry.get("port", -1))
                except (TypeError, ValueError):
                    continue
                service = str(entry.get("service", "")).lower()
                if port in {111, 2049} or service in {
                    "nfs",
                    "nfsd",
                    "rpcbind",
                    "portmap",
                    "mountd",
                }:
                    found_ports.append(port)
                    host = entry.get("host")
                    if not target and host:
                        target = str(host)
            if found_ports:
                ports = sorted(set(found_ports))
                console.print(
                    f"[green]--latest[/green]: open ports from discovery → {ports}"
                )

        if not target:
            # Fall back to last nfs report target.
            nfs_report = load_latest(MODULE_NAME)
            if nfs_report and nfs_report.get("target"):
                target = str(nfs_report["target"])

    return target, ports


def _print_status(item: dict[str, Any]) -> None:
    colors = {
        "ok": "green",
        "fail": "red",
        "skipped": "yellow",
        "finding": "magenta",
    }
    color = colors.get(item["status"], "white")
    console.print(
        f"[{color}]{item['status'].upper()}[/{color}] "
        f"[bold]{item['check']}[/bold]: {item['summary']}"
    )


def _is_everyone(client: str) -> bool:
    token = client.strip().lower()
    if token in _EVERYONE_TOKENS:
        return True
    if token.endswith("*") and "/" not in token:
        return True
    return False


def _parse_showmount_exports(stdout: str) -> list[dict[str, Any]]:
    """Parse showmount -e output into path / clients / everyone flag."""
    exports: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("export list"):
            continue
        match = _EXPORT_RE.match(stripped)
        if not match:
            continue
        path = match.group("path")
        clients_raw = match.group("clients").strip()
        clients = [c.strip() for c in re.split(r"\s*,\s*", clients_raw) if c.strip()]
        everyone = any(_is_everyone(c) for c in clients) or _is_everyone(clients_raw)
        exports.append(
            {
                "path": path,
                "clients": clients,
                "clients_raw": clients_raw,
                "everyone": everyone,
            }
        )
    return exports


def _parse_rpcinfo_programs(stdout: str) -> list[str]:
    """Return lowercased program names found in rpcinfo -p output."""
    found: set[str] = set()
    for line in stdout.splitlines():
        # rpcinfo -p: "program vers proto   port  service"
        parts = line.split()
        if len(parts) >= 5 and parts[0].isdigit():
            found.add(parts[-1].lower())
        else:
            for name in NFS_RPC_PROGRAMS:
                if re.search(rf"\b{re.escape(name)}\b", line, re.I):
                    found.add(name)
    return sorted(found)


def _run_external(
    check: str,
    cmd: list[str],
    *,
    timeout: int,
    dry_run: bool,
    tool: str,
    finding_pred: Any | None = None,
    parse: Any | None = None,
) -> dict[str, Any]:
    pretty = " ".join(cmd)
    available = tool_available(tool)

    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        summary = (
            f"{tool} not installed — check skipped"
            if not available
            else "dry-run — not executed"
        )
        item = _result(
            check,
            pretty,
            "skipped",
            summary,
            raw={"dry_run": True, "tool_available": available},
        )
        _print_status(item)
        return item

    if not available:
        item = _result(
            check,
            pretty,
            "skipped",
            f"{tool} not installed — check skipped",
        )
        _print_status(item)
        return item

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    raw: dict[str, Any] = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "duration": completed.duration,
    }
    parsed = parse(completed.stdout) if parse else None
    if parsed is not None:
        raw["parsed"] = parsed

    if completed.returncode not in (0, 1) and not completed.stdout.strip():
        item = _result(
            check,
            pretty,
            "fail",
            f"{tool} failed (rc={completed.returncode})",
            raw=raw,
        )
        _print_status(item)
        return item

    finding_summary = finding_pred(completed.stdout, parsed) if finding_pred else None
    if isinstance(finding_summary, str) and finding_summary:
        item = _result(check, pretty, "finding", finding_summary, raw=raw)
        _print_status(item)
        return item

    item = _result(
        check,
        pretty,
        "ok",
        f"{tool} completed (rc={completed.returncode})",
        raw=raw,
    )
    _print_status(item)
    return item


def _check_nmap(
    host: str, ports: list[int], timeout: int, dry_run: bool
) -> dict[str, Any]:
    port_list = ",".join(str(p) for p in sorted(set(ports))) or "111,2049"
    cmd = [
        "nmap",
        "-Pn",
        "-p",
        port_list,
        "-sV",
        "--script",
        NMAP_SCRIPTS,
        host,
    ]
    return _run_external(
        "nmap-nfs",
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="nmap",
    )


def _check_rpcinfo(host: str, timeout: int, dry_run: bool) -> dict[str, Any]:
    cmd = ["rpcinfo", "-p", host]

    def finding_pred(stdout: str, parsed: Any) -> str | None:
        programs = parsed if isinstance(parsed, list) else _parse_rpcinfo_programs(stdout)
        hits = [p for p in NFS_RPC_PROGRAMS if p in programs]
        if hits:
            return f"RPC programs exposed: {', '.join(hits)}"
        return None

    return _run_external(
        "rpcinfo",
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="rpcinfo",
        finding_pred=finding_pred,
        parse=_parse_rpcinfo_programs,
    )


def _check_showmount(
    host: str, timeout: int, dry_run: bool
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    cmd = ["showmount", "-e", host]

    def finding_pred(stdout: str, parsed: Any) -> str | None:
        exports = parsed if isinstance(parsed, list) else _parse_showmount_exports(stdout)
        open_exports = [e["path"] for e in exports if e.get("everyone")]
        if open_exports:
            return (
                f"Export(s) open to everyone/*: {', '.join(open_exports)}"
            )
        return None

    item = _run_external(
        "showmount-exports",
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="showmount",
        finding_pred=finding_pred,
        parse=_parse_showmount_exports,
    )
    exports = (item.get("raw") or {}).get("parsed") or []
    if exports and not dry_run:
        rows = [
            {
                "path": e["path"],
                "clients": ", ".join(e.get("clients") or [e.get("clients_raw", "")]),
                "everyone": str(bool(e.get("everyone"))),
            }
            for e in exports
        ]
        render_table(rows, title=f"NFS exports ({host})")
    return item, exports if isinstance(exports, list) else []


def _mount_check_exports(
    host: str,
    exports: list[dict[str, Any]],
    timeout: int,
    dry_run: bool,
) -> dict[str, Any]:
    """Read-only mount each export, ls -ln, always unmount. Never writes files."""
    check = "mount-check-ro"
    if dry_run:
        sample_paths = [e["path"] for e in exports] or ["/export"]
        for path in sample_paths:
            run_cmd(
                [
                    "mount",
                    "-t",
                    "nfs",
                    "-o",
                    "ro,nolock",
                    f"{host}:{path}",
                    "/tmp/nfs_enum_XXXX",
                ],
                timeout=timeout,
                dry_run=True,
            )
            run_cmd(["ls", "-ln", "/tmp/nfs_enum_XXXX"], timeout=timeout, dry_run=True)
            run_cmd(["umount", "/tmp/nfs_enum_XXXX"], timeout=timeout, dry_run=True)
        summary = (
            f"dry-run — would RO-mount {len(exports)} export(s)"
            if exports
            else "dry-run — would RO-mount each showmount export (none parsed yet)"
        )
        item = _result(
            check,
            f"mount -t nfs -o ro,nolock {host}:<export> <tmpdir> && ls -ln && umount",
            "skipped",
            summary,
            raw={"dry_run": True, "exports": sample_paths},
        )
        _print_status(item)
        return item

    if not exports:
        item = _result(
            check,
            "mount -t nfs -o ro,nolock …",
            "skipped",
            "No exports to mount",
        )
        _print_status(item)
        return item

    if not check_root():
        item = _result(
            check,
            "mount -t nfs -o ro,nolock …",
            "skipped",
            "Root required for --mount-check — skipped",
        )
        _print_status(item)
        return item

    if not tool_available("mount") or not tool_available("umount"):
        require_tools(["mount", "umount"])
        item = _result(
            check,
            "mount/umount",
            "skipped",
            "mount/umount not available — skipped",
        )
        _print_status(item)
        return item

    listings: list[dict[str, Any]] = []
    errors: list[str] = []

    for export in exports:
        path = export["path"]
        mount_src = f"{host}:{path}"
        tmpdir = tempfile.mkdtemp(prefix="nfs_enum_")
        mounted = False
        try:
            mount_cmd = [
                "mount",
                "-t",
                "nfs",
                "-o",
                "ro,nolock",
                mount_src,
                tmpdir,
            ]
            mount_res = run_cmd(mount_cmd, timeout=timeout, dry_run=False)
            if mount_res.returncode != 0:
                errors.append(
                    f"{path}: mount failed (rc={mount_res.returncode}) "
                    f"{(mount_res.stderr or mount_res.stdout).strip()}"
                )
                continue
            mounted = True
            ls_res = run_cmd(["ls", "-ln", tmpdir], timeout=timeout, dry_run=False)
            listing = {
                "path": path,
                "mountpoint": tmpdir,
                "ls_rc": ls_res.returncode,
                "ls": ls_res.stdout,
            }
            listings.append(listing)
            console.print(f"[green]ls -ln[/green] {mount_src}")
            if ls_res.stdout.strip():
                console.print(ls_res.stdout.rstrip())
        finally:
            if mounted:
                umount_res = run_cmd(["umount", tmpdir], timeout=timeout, dry_run=False)
                if umount_res.returncode != 0:
                    # Best-effort lazy unmount if busy
                    run_cmd(["umount", "-l", tmpdir], timeout=timeout, dry_run=False)
                    errors.append(f"{path}: umount issue (rc={umount_res.returncode})")
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except OSError:
                try:
                    os.rmdir(tmpdir)
                except OSError:
                    pass

    status = "ok"
    summary = f"RO-listed {len(listings)}/{len(exports)} export(s)"
    if errors and not listings:
        status = "fail"
        summary = f"Mount check failed for all exports ({len(errors)} error(s))"
    elif errors:
        summary = f"{summary}; {len(errors)} error(s)"

    item = _result(
        check,
        f"mount -t nfs -o ro,nolock {host}:<export> <tmpdir> && ls -ln && umount",
        status,
        summary,
        raw={"listings": listings, "errors": errors},
    )
    _print_status(item)
    return item


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
    """Execute NFS enumeration for the resolved target."""
    target, ports = _resolve_target_and_ports(args)
    if not target:
        console.print(
            "[red]Target required[/red]: pass positional TARGET, -t/--target, "
            "or --latest with an existing discovery/nfs report."
        )
        return 2

    timeout: int = args.timeout
    dry_run: bool = bool(args.dry_run)
    mount_check: bool = bool(args.mount_check)
    # Prefer --port when user overrides; still keep 111 alongside 2049 for nmap.
    if args.port and args.port not in ports:
        ports = sorted(set(ports + [args.port, 111, 2049]))

    console.print(
        f"[bold]NFS enum[/bold] → {target} (ports {ports})"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )

    require_tools(["nmap", "rpcinfo", "showmount"])

    checks: list[dict[str, Any]] = []
    checks.append(_check_nmap(target, ports, timeout, dry_run))
    checks.append(_check_rpcinfo(target, timeout, dry_run))
    showmount_item, exports = _check_showmount(target, timeout, dry_run)
    checks.append(showmount_item)

    if mount_check:
        checks.append(_mount_check_exports(target, exports, timeout, dry_run))
    else:
        skipped = _result(
            "mount-check-ro",
            "mount -t nfs -o ro,nolock …",
            "skipped",
            "--mount-check not set (default off)",
        )
        checks.append(skipped)
        _print_status(skipped)

    findings = [c for c in checks if c.get("status") == "finding"]
    data: dict[str, Any] = {
        "port": args.port,
        "ports": ports,
        "timeout": timeout,
        "dry_run": dry_run,
        "mount_check": mount_check,
        "checks": checks,
        "exports": exports,
        "findings": [
            {"check": f["check"], "summary": f["summary"]} for f in findings
        ],
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
        prog="nfs_enum.py",
        description=(
            "NFS enumeration (rpcinfo, showmount, nmap scripts, optional RO mount). "
            "Enumeration only — no writes to mounted shares."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
