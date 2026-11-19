#!/usr/bin/env python3
"""SNMP enumeration: communities, walks, interesting OIDs, braa, v3, nmap (UDP/161)."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import REPORTS_DIR, load_latest, render_table, save_report
from core.runner import check_root, require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "snmp"
DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 60
DEFAULT_RETRIES = 2
DEFAULT_COMMUNITIES = ("public", "private", "manager")
DEFAULT_VERSION = "2c"

# Interesting OID shortcuts (name → numeric OID / walk root)
INTERESTING_OIDS: dict[str, str] = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifTable": "1.3.6.1.2.1.2.2",
    "hrSWRunName": "1.3.6.1.2.1.25.4.2.1.2",
    "hrSWInstalledName": "1.3.6.1.2.1.25.6.3.1.2",
    "tcpConnTable": "1.3.6.1.2.1.6.13",
    "winUsers": "1.3.6.1.4.1.77.1.2.25",
}

_WEAK_COMMUNITIES = {"public", "private"}


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
        help="SNMP host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="SNMP host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"SNMP UDP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Command timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=(
            f"SNMP/UDP retries (default: {DEFAULT_RETRIES}). "
            "UDP may produce false negatives — increase if needed."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned commands without connecting",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use target from the latest discovery/snmp report when omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path for JSON report (writes sibling .md too)",
    )
    parser.add_argument(
        "--communities",
        default=None,
        help=(
            "Optional community wordlist file. "
            f"If omitted, uses built-in: {', '.join(DEFAULT_COMMUNITIES)}"
        ),
    )
    parser.add_argument(
        "--version",
        choices=("1", "2c", "3"),
        default=DEFAULT_VERSION,
        help=f"Preferred SNMP version for walks (default: {DEFAULT_VERSION})",
    )
    parser.add_argument(
        "--oids",
        default=None,
        help="Comma-separated extra OIDs/roots to walk/get (appended to interesting set)",
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
            try:
                port = int(entry.get("port", -1))
            except (TypeError, ValueError):
                continue
            service = str(entry.get("service", "")).lower()
            if port == 161 or "snmp" in service:
                host = entry.get("host") or report.get("target")
                if host:
                    return str(host)
    return None


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


def _load_communities(path: str | None) -> list[str]:
    if not path:
        return list(DEFAULT_COMMUNITIES)
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Communities file not found: {file_path}")
    values = [
        line.strip()
        for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return values or list(DEFAULT_COMMUNITIES)


def _write_communities_temp(communities: list[str]) -> Path:
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        prefix="snmp_comms_",
        suffix=".txt",
        delete=False,
    )
    with handle as fh:
        fh.write("\n".join(communities) + "\n")
    return Path(handle.name)


def _parse_onesixtyone(stdout: str) -> list[str]:
    """Extract community strings from onesixtyone output."""
    found: list[str] = []
    for line in stdout.splitlines():
        # Formats:
        # 10.10.10.10 [public] Windows ...
        # 10.10.10.10:161 public
        match = re.search(r"\[([^\]]+)\]", line)
        if match:
            comm = match.group(1).strip()
            if comm and comm not in found:
                found.append(comm)
            continue
        parts = line.split()
        if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+", parts[0]):
            # ip community ...
            candidate = parts[1].strip("[]")
            if candidate and not candidate.startswith("(") and candidate not in found:
                found.append(candidate)
    return found


def _snmp_get(
    target: str,
    community: str,
    oid: str,
    *,
    version: str,
    port: int,
    timeout: int,
    retries: int,
    dry_run: bool,
) -> tuple[str, str]:
    """Return (stdout, effective_version). Tries preferred version then fallback."""
    versions = [version] if version in {"1", "2c"} else ["2c", "1"]
    if version == "2c":
        versions = ["2c", "1"]
    elif version == "1":
        versions = ["1", "2c"]

    stdout = ""
    used = versions[0]
    for ver in versions:
        cmd = [
            "snmpget",
            "-v",
            ver,
            "-c",
            community,
            "-t",
            str(max(1, timeout // 10 or 1)),
            "-r",
            str(retries),
            "-O",
            "nq",
            f"{target}:{port}",
            oid,
        ]
        if dry_run:
            run_cmd(cmd, timeout=timeout, dry_run=True)
            return "", ver
        if not tool_available("snmpget"):
            return "", ver
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        used = ver
        stdout = completed.stdout.strip()
        if completed.returncode == 0 and stdout and "Timeout" not in stdout:
            return stdout, ver
    return stdout, used


def _snmp_walk(
    target: str,
    community: str,
    oid: str,
    *,
    version: str,
    port: int,
    timeout: int,
    retries: int,
    dry_run: bool,
) -> tuple[str, str, list[str]]:
    versions = ["2c", "1"] if version == "2c" else ["1", "2c"] if version == "1" else ["2c", "1"]
    stdout = ""
    used = versions[0]
    cmd_used: list[str] = []
    for ver in versions:
        cmd = [
            "snmpwalk",
            "-v",
            ver,
            "-c",
            community,
            "-t",
            str(max(1, min(5, timeout // 5 or 1))),
            "-r",
            str(retries),
            f"{target}:{port}",
            oid,
        ]
        cmd_used = cmd
        if dry_run:
            run_cmd(cmd, timeout=timeout, dry_run=True)
            return "", ver, cmd
        if not tool_available("snmpwalk"):
            return "", ver, cmd
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        used = ver
        stdout = completed.stdout
        if completed.returncode == 0 and stdout.strip() and "Timeout" not in completed.stderr:
            return stdout, ver, cmd
        # Also accept partial data
        if stdout.strip() and "Timeout" not in stdout.splitlines()[0]:
            return stdout, ver, cmd
    return stdout, used, cmd_used


def _extract_snmp_value(stdout: str) -> str:
    if not stdout:
        return ""
    line = stdout.splitlines()[0].strip()
    # OID = TYPE value  OR  just value with -Onq
    if " = " in line:
        return line.split(" = ", 1)[1].strip()
    return line


def _probe_write_access(
    target: str,
    community: str,
    *,
    version: str,
    port: int,
    timeout: int,
    retries: int,
    dry_run: bool,
) -> bool | None:
    """Deduce SET permission without changing state (wrong type → wrongType)."""
    # sysContact.0 as INTEGER should yield wrongType if writable, authorizationError if not.
    ver = "2c" if version == "3" else version
    cmd = [
        "snmpset",
        "-v",
        ver,
        "-c",
        community,
        "-t",
        "1",
        "-r",
        str(retries),
        f"{target}:{port}",
        "1.3.6.1.2.1.1.4.0",
        "i",
        "1",
    ]
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        return None
    if not tool_available("snmpset"):
        return None
    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    blob = (completed.stdout + completed.stderr).lower()
    if "wrongtype" in blob or "bad value" in blob or "inconsistentvalue" in blob:
        return True
    if any(
        tok in blob
        for tok in (
            "noaccess",
            "authorizationerror",
            "notwritable",
            "noaccessauthorization",
            "permission denied",
        )
    ):
        return False
    return None


def _check_onesixtyone(
    target: str,
    communities: list[str],
    port: int,
    timeout: int,
    dry_run: bool,
) -> dict[str, Any]:
    check = "onesixtyone"
    comm_file = _write_communities_temp(communities)
    cmd = ["onesixtyone", "-c", str(comm_file), "-p", str(port), target]
    pretty = " ".join(cmd)

    try:
        if dry_run:
            run_cmd(cmd, timeout=timeout, dry_run=True)
            item = _result(
                check,
                pretty,
                "skipped",
                "dry-run — not executed",
                raw={"dry_run": True, "communities": communities},
            )
            _print_status(item)
            return item

        if not tool_available("onesixtyone"):
            require_tools(["onesixtyone"])
            # Fallback: treat built-in list as candidates to try with snmpwalk
            item = _result(
                check,
                pretty,
                "skipped",
                "onesixtyone not installed — will probe communities via snmpwalk fallback",
                raw={"communities_fallback": communities},
            )
            _print_status(item)
            return item

        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        found = _parse_onesixtyone(completed.stdout)
        raw = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "communities": found,
        }
        weak = [c for c in found if c.lower() in _WEAK_COMMUNITIES]
        if found and weak:
            item = _result(
                check,
                pretty,
                "finding",
                f"Valid communities: {', '.join(found)} (weak: {', '.join(weak)})",
                raw=raw,
            )
        elif found:
            item = _result(
                check,
                pretty,
                "finding",
                f"Valid communities: {', '.join(found)}",
                raw=raw,
            )
        else:
            item = _result(
                check,
                pretty,
                "ok",
                "No communities confirmed by onesixtyone (UDP may false-negative)",
                raw=raw,
            )
        _print_status(item)
        return item
    finally:
        try:
            comm_file.unlink(missing_ok=True)
        except OSError:
            pass


def _valid_communities_from_checks(
    onesixtyone_item: dict[str, Any],
    fallback: list[str],
) -> list[str]:
    raw = onesixtyone_item.get("raw") or {}
    found = list(raw.get("communities") or [])
    if found:
        return found
    # Fallback when onesixtyone skipped/missing: try default/file list
    return list(raw.get("communities_fallback") or fallback)


def _check_walks(
    target: str,
    communities: list[str],
    *,
    version: str,
    port: int,
    timeout: int,
    retries: int,
    dry_run: bool,
) -> dict[str, Any]:
    check = "snmpwalk-full"
    if not communities:
        item = _result(
            check,
            "snmpwalk -v2c -c <community> TARGET",
            "skipped",
            "No communities to walk",
        )
        _print_status(item)
        return item

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    walks: dict[str, Any] = {}
    commands: list[str] = []

    for community in communities:
        stdout, used_ver, cmd = _snmp_walk(
            target,
            community,
            ".",
            version=version if version != "3" else "2c",
            port=port,
            timeout=timeout,
            retries=retries,
            dry_run=dry_run,
        )
        commands.append(" ".join(cmd))
        if dry_run:
            continue
        out_path = REPORTS_DIR / f"snmp_walk_{target.replace('/', '_')}_{community}.txt"
        out_path.write_text(stdout or "", encoding="utf-8", errors="replace")
        walks[community] = {
            "version": used_ver,
            "path": str(out_path),
            "lines": len((stdout or "").splitlines()),
            "preview": "\n".join((stdout or "").splitlines()[:20]),
        }
        console.print(
            f"[green]Saved walk[/green] community={community} → {out_path.name} "
            f"({walks[community]['lines']} lines, v{used_ver})"
        )

    if dry_run:
        item = _result(
            check,
            " ; ".join(commands) or "snmpwalk …",
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "communities": communities},
        )
        _print_status(item)
        return item

    if not tool_available("snmpwalk"):
        require_tools(["snmpwalk"])
        item = _result(check, "snmpwalk …", "skipped", "snmpwalk not installed — check skipped")
        _print_status(item)
        return item

    any_data = any(w.get("lines", 0) > 0 for w in walks.values())
    item = _result(
        check,
        " ; ".join(commands),
        "ok" if any_data else "fail",
        f"Walks saved for {len(walks)} community(ies)",
        raw={"walks": walks},
    )
    _print_status(item)
    return item


def _check_interesting_oids(
    target: str,
    communities: list[str],
    *,
    version: str,
    port: int,
    timeout: int,
    retries: int,
    dry_run: bool,
    extra_oids: list[str],
) -> dict[str, Any]:
    check = "interesting-oids"
    oid_map = dict(INTERESTING_OIDS)
    for idx, oid in enumerate(extra_oids):
        oid_map[f"custom_{idx}"] = oid

    if not communities:
        item = _result(check, "snmpget/snmpwalk OIDs", "skipped", "No communities available")
        _print_status(item)
        return item

    # Prefer first community for summary; collect per-community for report
    per_comm: dict[str, dict[str, str]] = {}
    table_rows: list[dict[str, str]] = []
    commands: list[str] = []

    if dry_run:
        sample = communities[0]
        for name, oid in list(oid_map.items())[:8]:
            run_cmd(
                ["snmpget", "-v", "2c", "-c", sample, f"{target}:{port}", oid]
                if oid.endswith(".0")
                else ["snmpwalk", "-v", "2c", "-c", sample, f"{target}:{port}", oid],
                timeout=timeout,
                dry_run=True,
            )
        run_cmd(
            [
                "snmpset",
                "-v",
                "2c",
                "-c",
                sample,
                f"{target}:{port}",
                "1.3.6.1.2.1.1.4.0",
                "i",
                "1",
            ],
            timeout=timeout,
            dry_run=True,
        )
        item = _result(
            check,
            "snmpget/snmpwalk interesting OIDs",
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "oids": oid_map},
        )
        _print_status(item)
        return item

    for community in communities:
        values: dict[str, str] = {}
        for name, oid in oid_map.items():
            # scalar gets vs table walks
            if name in {
                "ifTable",
                "hrSWRunName",
                "hrSWInstalledName",
                "tcpConnTable",
                "winUsers",
            } or not oid.endswith(".0"):
                stdout, ver, cmd = _snmp_walk(
                    target,
                    community,
                    oid,
                    version=version if version != "3" else "2c",
                    port=port,
                    timeout=timeout,
                    retries=retries,
                    dry_run=dry_run,
                )
                commands.append(" ".join(cmd))
                if dry_run:
                    continue
                lines = [ln for ln in (stdout or "").splitlines() if ln.strip()]
                values[name] = f"{len(lines)} entries" if lines else ""
                if lines:
                    values[f"{name}_sample"] = " | ".join(lines[:3])[:240]
            else:
                cmd = [
                    "snmpget",
                    "-v",
                    "2c",
                    "-c",
                    community,
                    f"{target}:{port}",
                    oid,
                ]
                commands.append(" ".join(cmd))
                stdout, ver = _snmp_get(
                    target,
                    community,
                    oid,
                    version=version if version != "3" else "2c",
                    port=port,
                    timeout=timeout,
                    retries=retries,
                    dry_run=dry_run,
                )
                if dry_run:
                    continue
                values[name] = _extract_snmp_value(stdout)
        per_comm[community] = values
        rw = _probe_write_access(
            target,
            community,
            version=version if version != "3" else "2c",
            port=port,
            timeout=timeout,
            retries=retries,
            dry_run=False,
        )
        access = "rw" if rw is True else "ro" if rw is False else "unknown"
        table_rows.append(
            {
                "community": community,
                "version": version if version != "3" else "2c",
                "access": access,
                "sysDescr": (values.get("sysDescr") or "")[:80],
                "sysName": (values.get("sysName") or "")[:40],
            }
        )

    if not tool_available("snmpget") and not tool_available("snmpwalk"):
        require_tools(["snmpget", "snmpwalk"])
        item = _result(check, "snmpget/snmpwalk", "skipped", "net-snmp tools missing")
        _print_status(item)
        return item

    if table_rows:
        render_table(table_rows, title="SNMP communities summary")

    findings: list[str] = []
    for row in table_rows:
        if row["community"].lower() in _WEAK_COMMUNITIES:
            findings.append(f"weak community '{row['community']}'")
        if row["access"] == "rw":
            findings.append(f"write access via '{row['community']}'")

    raw = {"per_community": per_comm, "summary": table_rows}
    if findings:
        item = _result(
            check,
            "snmpget/snmpwalk interesting OIDs",
            "finding",
            "; ".join(dict.fromkeys(findings)),
            raw=raw,
        )
    else:
        item = _result(
            check,
            "snmpget/snmpwalk interesting OIDs",
            "ok",
            f"Collected OID summaries for {len(communities)} community(ies)",
            raw=raw,
        )
    _print_status(item)
    return item


def _check_braa(
    target: str,
    communities: list[str],
    timeout: int,
    dry_run: bool,
) -> dict[str, Any]:
    check = "braa"
    if not communities:
        item = _result(check, "braa …", "skipped", "No communities for braa")
        _print_status(item)
        return item

    # braa community@host:.1.3.6.*
    cmds = [f"braa {c}@{target}:.1.3.6.*" for c in communities]
    if dry_run:
        for c in communities:
            run_cmd(["braa", f"{c}@{target}:.1.3.6.*"], timeout=timeout, dry_run=True)
        item = _result(
            check,
            " ; ".join(cmds),
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True},
        )
        _print_status(item)
        return item

    if not tool_available("braa"):
        require_tools(["braa"])
        item = _result(check, " ; ".join(cmds), "skipped", "braa not installed — check skipped")
        _print_status(item)
        return item

    outputs: dict[str, Any] = {}
    for community in communities:
        cmd = ["braa", f"{community}@{target}:.1.3.6.*"]
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        outputs[community] = {
            "returncode": completed.returncode,
            "stdout": completed.stdout[:5000],
            "stderr": completed.stderr[:1000],
            "lines": len(completed.stdout.splitlines()),
        }
    any_data = any(v.get("lines", 0) > 0 for v in outputs.values())
    item = _result(
        check,
        " ; ".join(cmds),
        "ok" if any_data else "fail",
        f"braa finished for {len(communities)} community(ies)",
        raw={"outputs": outputs},
    )
    _print_status(item)
    return item


def _check_snmpv3(
    target: str,
    port: int,
    timeout: int,
    retries: int,
    dry_run: bool,
    version_flag: str,
) -> dict[str, Any]:
    check = "snmpv3-noauth"
    cmd = [
        "snmpwalk",
        "-v",
        "3",
        "-l",
        "noAuthNoPriv",
        "-t",
        "2",
        "-r",
        str(retries),
        f"{target}:{port}",
        "1.3.6.1.2.1.1",
    ]
    pretty = " ".join(cmd)

    # Always offer the check; emphasize when --version 3
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(
            check, pretty, "skipped", "dry-run — not executed", raw={"dry_run": True}
        )
        _print_status(item)
        return item

    if not tool_available("snmpwalk"):
        item = _result(check, pretty, "skipped", "snmpwalk not installed — check skipped")
        _print_status(item)
        return item

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    raw = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    blob = completed.stdout + completed.stderr
    if completed.stdout.strip() and "Timeout" not in blob:
        item = _result(
            check,
            pretty,
            "finding",
            "SNMPv3 responded with noAuthNoPriv — unauthenticated access possible",
            raw=raw,
        )
    elif re.search(r"authorizationError|unknownUserName|unsupportedSecurityLevel", blob, re.I):
        item = _result(
            check,
            pretty,
            "ok",
            "SNMPv3 present but noAuthNoPriv not accepted",
            raw=raw,
        )
    else:
        status = "ok" if version_flag != "3" else "fail"
        item = _result(
            check,
            pretty,
            status,
            "No SNMPv3 noAuthNoPriv response (UDP may false-negative)",
            raw=raw,
        )
    _print_status(item)
    return item


def _check_nmap(
    target: str, port: int, timeout: int, dry_run: bool
) -> dict[str, Any]:
    check = "nmap-snmp"
    cmd = [
        "nmap",
        "-sU",
        "-Pn",
        "-p",
        str(port),
        "--script",
        "snmp-info,snmp-sysdescr,snmp-processes",
        target,
    ]
    pretty = " ".join(cmd)

    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(
            check, pretty, "skipped", "dry-run — not executed", raw={"dry_run": True}
        )
        _print_status(item)
        return item

    if not tool_available("nmap"):
        require_tools(["nmap"])
        item = _result(check, pretty, "skipped", "nmap not installed — check skipped")
        _print_status(item)
        return item

    if not check_root():
        item = _result(
            check,
            pretty,
            "skipped",
            "Root required for nmap -sU SNMP scripts — skipped",
        )
        _print_status(item)
        return item

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    raw = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.stdout.strip():
        console.print(completed.stdout.rstrip())
    findings: list[str] = []
    if re.search(r"public|private", completed.stdout, re.I):
        findings.append("nmap SNMP scripts exposed community/system info")
    if findings:
        item = _result(check, pretty, "finding", "; ".join(findings), raw=raw)
    else:
        item = _result(
            check,
            pretty,
            "ok",
            f"nmap completed (rc={completed.returncode})",
            raw=raw,
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
    """Execute SNMP enumeration for the resolved target."""
    target = _resolve_target(args)
    if not target:
        console.print(
            "[red]Target required[/red]: pass positional TARGET, -t/--target, "
            "or --latest with an existing report."
        )
        return 2

    try:
        communities = _load_communities(args.communities)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    extra_oids = [
        o.strip()
        for o in str(args.oids or "").split(",")
        if o.strip()
    ]

    port: int = args.port
    timeout: int = args.timeout
    retries: int = args.retries
    dry_run = bool(args.dry_run)
    version: str = args.version

    console.print(
        f"[bold]SNMP enum[/bold] → {target}:{port}/udp version={version} "
        f"communities={len(communities)} retries={retries}"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )
    console.print(
        "[yellow]Note[/yellow]: SNMP is UDP — false negatives are common; "
        f"raise --retries (current: {retries}) if needed."
    )

    require_tools(["onesixtyone", "snmpwalk", "snmpget", "snmpset", "braa", "nmap"])

    checks: list[dict[str, Any]] = []
    onesixty = _check_onesixtyone(target, communities, port, timeout, dry_run)
    checks.append(onesixty)

    valid = _valid_communities_from_checks(onesixty, communities)
    if dry_run and not valid:
        valid = communities

    checks.append(
        _check_walks(
            target,
            valid,
            version=version,
            port=port,
            timeout=timeout,
            retries=retries,
            dry_run=dry_run,
        )
    )
    interesting = _check_interesting_oids(
        target,
        valid,
        version=version,
        port=port,
        timeout=timeout,
        retries=retries,
        dry_run=dry_run,
        extra_oids=extra_oids,
    )
    checks.append(interesting)
    checks.append(_check_braa(target, valid, timeout, dry_run))
    checks.append(_check_snmpv3(target, port, timeout, retries, dry_run, version))
    checks.append(_check_nmap(target, port, timeout, dry_run))

    findings = [c for c in checks if c.get("status") == "finding"]
    summary_rows = (interesting.get("raw") or {}).get("summary") or []

    data: dict[str, Any] = {
        "port": port,
        "timeout": timeout,
        "retries": retries,
        "dry_run": dry_run,
        "version": version,
        "communities_tested": communities,
        "communities_valid": valid,
        "extra_oids": extra_oids,
        "checks": checks,
        "summary": summary_rows,
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
        prog="snmp_enum.py",
        description=(
            "SNMP enumeration (communities, walks, interesting OIDs, braa, v3, nmap). "
            "UDP/161 — retries recommended. Enumeration only."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
