#!/usr/bin/env python3
"""Oracle TNS enumeration: version, listener status, optional SID guessing (no default creds)."""

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

from core.parser import load_latest, render_table, save_report
from core.runner import require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "oracle"
DEFAULT_PORT = 1521
DEFAULT_TIMEOUT = 120


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
        help="Oracle host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="Oracle host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Oracle TNS port (default: {DEFAULT_PORT})",
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
        help="Use target from the latest discovery/oracle report when omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path for JSON report (writes sibling .md too)",
    )
    parser.add_argument(
        "--sid",
        default=None,
        help="Known/candidate Oracle SID to probe (informative check only)",
    )
    parser.add_argument(
        "--sid-wordlist",
        default=None,
        help="Optional SID wordlist file (no built-in list; enables SID enumeration)",
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
            if port == 1521 or "oracle" in service or "tns" in service:
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


def _odat_bin() -> str | None:
    for name in ("odat", "odat.py"):
        if tool_available(name):
            return name
    return None


def _tnscmd_bin() -> str | None:
    for name in ("tnscmd10g", "tnscmd"):
        if tool_available(name):
            return name
    return None


def _parse_tnscmd_output(stdout: str) -> dict[str, Any]:
    """Extract SERVICE_NAME, SID, version and listener hints from tnscmd output."""
    services = sorted(
        set(re.findall(r"SERVICE_NAME\s*=\s*([^\s\)\]]+)", stdout, re.I))
    )
    sids = sorted(set(re.findall(r"\bSID(?:_NAME)?\s*=\s*([^\s\)\]]+)", stdout, re.I)))
    # Also catch (SID=ORCL)
    sids = sorted(set(sids) | set(re.findall(r"\(SID=([^)]+)\)", stdout, re.I)))
    services = sorted(
        set(services) | set(re.findall(r"\(SERVICE_NAME=([^)]+)\)", stdout, re.I))
    )

    version = ""
    ver_match = re.search(
        r"(?:Version|TNSLS|Oracle\s+(?:Database\s+)?(?:Release\s+)?)([0-9]+(?:\.[0-9]+)+)",
        stdout,
        re.I,
    )
    if ver_match:
        version = ver_match.group(1)
    else:
        # "Version 19.0.0.0.0" style in status
        ver_match = re.search(r"Version\s+([0-9]+(?:\.[0-9A-Za-z]+)+)", stdout, re.I)
        if ver_match:
            version = ver_match.group(1)

    listeners = sorted(
        set(
            re.findall(
                r"(?:ALIAS|LISTENER(?:_NAME)?)\s*[=:]\s*([^\s,]+)",
                stdout,
                re.I,
            )
        )
    )

    # Unauthenticated status / no listener password indicators
    unauth_status = bool(
        re.search(
            r"STATUS\s+of\s+the\s+LISTENER|Listening Endpoints|Services Summary",
            stdout,
            re.I,
        )
    )
    no_password = bool(
        re.search(
            r"security\s*(OFF|ON:\s*Local OS Auth)|PASSWORD\s*=\s*(OFF|NONE)|"
            r"The listener password|no password|Security OFF",
            stdout,
            re.I,
        )
    ) or (
        unauth_status
        and not re.search(r"TNS-\d+.*password|requires.*password", stdout, re.I)
    )

    return {
        "service_names": services,
        "sids": sids,
        "version": version,
        "listeners": listeners,
        "unauthenticated_status": unauth_status,
        "listener_no_password_hint": no_password and unauth_status,
    }


def _check_nmap_tns(
    host: str, port: int, timeout: int, dry_run: bool
) -> dict[str, Any]:
    check = "nmap-oracle-tns-version"
    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-p",
        str(port),
        "--script",
        "oracle-tns-version",
        host,
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

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    raw = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.stdout.strip():
        console.print(completed.stdout.rstrip())

    version = ""
    match = re.search(
        r"(?:Version|Oracle TNS listener):\s*([^\n]+)", completed.stdout, re.I
    )
    if match:
        version = match.group(1).strip()
    raw["version"] = version

    if version:
        item = _result(
            check,
            pretty,
            "finding",
            f"TNS version via nmap: {version}",
            raw=raw,
        )
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


def _check_tnscmd(
    host: str, port: int, timeout: int, dry_run: bool
) -> dict[str, Any]:
    check = "tnscmd10g"
    tnscmd = _tnscmd_bin()
    version_cmd = [
        tnscmd or "tnscmd10g",
        "version",
        "-h",
        host,
        "-p",
        str(port),
    ]
    status_cmd = [
        tnscmd or "tnscmd10g",
        "status",
        "-h",
        host,
        "-p",
        str(port),
    ]
    pretty = f"{' '.join(version_cmd)} ; {' '.join(status_cmd)}"

    if dry_run:
        run_cmd(version_cmd, timeout=timeout, dry_run=True)
        run_cmd(status_cmd, timeout=timeout, dry_run=True)
        item = _result(
            check, pretty, "skipped", "dry-run — not executed", raw={"dry_run": True}
        )
        _print_status(item)
        return item

    if not tnscmd:
        require_tools(["tnscmd10g"])
        item = _result(
            check, pretty, "skipped", "tnscmd10g not installed — check skipped"
        )
        _print_status(item)
        return item

    version_res = run_cmd(version_cmd, timeout=timeout, dry_run=False)
    status_res = run_cmd(status_cmd, timeout=timeout, dry_run=False)
    combined = (version_res.stdout or "") + "\n" + (status_res.stdout or "")
    if version_res.stdout.strip():
        console.print(version_res.stdout.rstrip())
    if status_res.stdout.strip():
        console.print(status_res.stdout.rstrip())

    parsed = _parse_tnscmd_output(combined)
    raw = {
        "version_cmd": {
            "returncode": version_res.returncode,
            "stdout": version_res.stdout,
            "stderr": version_res.stderr,
        },
        "status_cmd": {
            "returncode": status_res.returncode,
            "stdout": status_res.stdout,
            "stderr": status_res.stderr,
        },
        "parsed": parsed,
    }

    rows: list[dict[str, str]] = []
    if parsed.get("version"):
        rows.append({"field": "version", "value": parsed["version"]})
    for sid in parsed.get("sids") or []:
        rows.append({"field": "SID", "value": sid})
    for svc in parsed.get("service_names") or []:
        rows.append({"field": "SERVICE_NAME", "value": svc})
    for lst in parsed.get("listeners") or []:
        rows.append({"field": "listener", "value": lst})
    if rows:
        render_table(rows, title="tnscmd10g parsed")

    findings: list[str] = []
    if parsed.get("listener_no_password_hint") or parsed.get("unauthenticated_status"):
        findings.append(
            "Listener status available without authentication "
            "(possible missing listener password)"
        )
    if parsed.get("version"):
        findings.append(f"TNS/Oracle version: {parsed['version']}")

    if findings:
        item = _result(check, pretty, "finding", "; ".join(findings), raw=raw)
    elif version_res.returncode not in (0, 1) and status_res.returncode not in (0, 1):
        item = _result(check, pretty, "fail", "tnscmd10g version/status failed", raw=raw)
    else:
        item = _result(check, pretty, "ok", "tnscmd10g completed", raw=raw)
    _print_status(item)
    return item


def _check_sid_wordlist(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
    wordlist: str | None,
) -> dict[str, Any]:
    check = "sid-enum"
    if not wordlist:
        item = _result(
            check,
            "odat sidguesser / nmap oracle-sid-brute",
            "skipped",
            "--sid-wordlist not provided (no built-in SID list)",
        )
        _print_status(item)
        return item

    path = Path(wordlist)
    odat = _odat_bin()

    if dry_run:
        if odat:
            run_cmd(
                [
                    odat,
                    "sidguesser",
                    "-s",
                    host,
                    "-p",
                    str(port),
                    "--sids-file",
                    str(path),
                ],
                timeout=timeout,
                dry_run=True,
            )
        run_cmd(
            [
                "nmap",
                "-Pn",
                "-p",
                str(port),
                "--script",
                "oracle-sid-brute",
                "--script-args",
                f"oracle-sid-brute.sidfile={path}",
                host,
            ],
            timeout=timeout,
            dry_run=True,
        )
        item = _result(
            check,
            f"odat sidguesser --sids-file {path} | nmap oracle-sid-brute",
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "wordlist": str(path)},
        )
        _print_status(item)
        return item

    if not path.is_file():
        item = _result(
            check,
            f"SID wordlist {path}",
            "fail",
            f"SID wordlist not found: {path}",
        )
        _print_status(item)
        return item

    # Prefer ODAT sidguesser
    if odat:
        cmd = [
            odat,
            "sidguesser",
            "-s",
            host,
            "-p",
            str(port),
            "--sids-file",
            str(path),
        ]
        pretty = " ".join(cmd)
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        raw = {
            "tool": odat,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        if completed.stdout.strip():
            console.print(completed.stdout.rstrip())
        found = sorted(
            set(
                re.findall(
                    r"(?:SID|valid|found)\s*[:=]\s*([A-Za-z0-9_$#]+)",
                    completed.stdout,
                    re.I,
                )
            )
        )
        # ODAT often prints "ORCL is valid" / "[+] ORCL"
        found = sorted(
            set(found)
            | set(re.findall(r"\[\+\]\s*([A-Za-z0-9_$#]+)", completed.stdout))
            | set(
                re.findall(
                    r"\b([A-Z][A-Z0-9_$#]{0,7})\b.*\b(?:valid|exists|found)\b",
                    completed.stdout,
                    re.I,
                )
            )
        )
        raw["sids"] = found
        if found:
            render_table([{"sid": s} for s in found], title="Oracle SIDs (odat)")
            item = _result(
                check,
                pretty,
                "finding",
                f"SID(s) discovered via odat: {', '.join(found)}",
                raw=raw,
            )
        else:
            item = _result(
                check,
                pretty,
                "ok",
                "odat sidguesser finished (no SIDs parsed)",
                raw=raw,
            )
        _print_status(item)
        return item

    # Fallback: nmap oracle-sid-brute with sidfile
    if not tool_available("nmap"):
        require_tools(["odat", "nmap"])
        item = _result(
            check,
            "odat/nmap SID enum",
            "skipped",
            "odat and nmap not available — SID enum skipped",
        )
        _print_status(item)
        return item

    cmd = [
        "nmap",
        "-Pn",
        "-p",
        str(port),
        "--script",
        "oracle-sid-brute",
        "--script-args",
        f"oracle-sid-brute.sidfile={path}",
        host,
    ]
    pretty = " ".join(cmd)
    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    raw = {
        "tool": "nmap",
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.stdout.strip():
        console.print(completed.stdout.rstrip())
    found = sorted(
        set(
            re.findall(
                r"(?:SID|Oracle SID):\s*([A-Za-z0-9_$#]+)",
                completed.stdout,
                re.I,
            )
        )
    )
    raw["sids"] = found
    if found:
        render_table([{"sid": s} for s in found], title="Oracle SIDs (nmap)")
        item = _result(
            check,
            pretty,
            "finding",
            f"SID(s) discovered via nmap: {', '.join(found)}",
            raw=raw,
        )
    else:
        item = _result(
            check,
            pretty,
            "ok",
            "nmap oracle-sid-brute finished (no SIDs parsed)",
            raw=raw,
        )
    _print_status(item)
    return item


def _check_sid_probe(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
    sid: str | None,
) -> dict[str, Any]:
    check = "sid-probe"
    if not sid:
        item = _result(
            check,
            "odat sidguesser --sid SID",
            "skipped",
            "--sid not provided",
        )
        _print_status(item)
        return item

    odat = _odat_bin()
    # Informative only: single-SID file for sidguesser / nmap
    if dry_run:
        if odat:
            run_cmd(
                [
                    odat,
                    "sidguesser",
                    "-s",
                    host,
                    "-p",
                    str(port),
                    "--sids-file",
                    f"<temp:{sid}>",
                ],
                timeout=timeout,
                dry_run=True,
            )
        else:
            run_cmd(
                [
                    "nmap",
                    "-Pn",
                    "-p",
                    str(port),
                    "--script",
                    "oracle-sid-brute",
                    "--script-args",
                    f"oracle-sid-brute.sidfile=<temp:{sid}>",
                    host,
                ],
                timeout=timeout,
                dry_run=True,
            )
        item = _result(
            check,
            f"probe SID={sid}",
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "sid": sid},
        )
        _print_status(item)
        return item

    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", prefix="oracle_sid_", suffix=".txt", delete=False
    ) as fh:
        fh.write(sid.strip() + "\n")
        tmp_path = Path(fh.name)

    try:
        if odat:
            cmd = [
                odat,
                "sidguesser",
                "-s",
                host,
                "-p",
                str(port),
                "--sids-file",
                str(tmp_path),
            ]
            pretty = " ".join(cmd)
            completed = run_cmd(cmd, timeout=timeout, dry_run=False)
            blob = completed.stdout + completed.stderr
            raw = {
                "tool": odat,
                "sid": sid,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
            if completed.stdout.strip():
                console.print(completed.stdout.rstrip())
            responds = bool(
                re.search(
                    rf"\b{re.escape(sid)}\b.*(valid|exists|found|ok)|"
                    rf"(valid|exists|found).*{re.escape(sid)}",
                    blob,
                    re.I,
                )
            ) or (
                completed.returncode == 0
                and sid.upper() in blob.upper()
                and not re.search(r"invalid|not found|refused", blob, re.I)
            )
            if responds:
                item = _result(
                    check,
                    pretty,
                    "finding",
                    f"SID '{sid}' appears to respond (odat informative check)",
                    raw=raw,
                )
            else:
                item = _result(
                    check,
                    pretty,
                    "ok",
                    f"SID '{sid}' not confirmed as valid",
                    raw=raw,
                )
            _print_status(item)
            return item

        if not tool_available("nmap"):
            require_tools(["odat", "nmap"])
            item = _result(
                check,
                f"probe SID={sid}",
                "skipped",
                "odat/nmap not available — SID probe skipped",
                raw={"sid": sid},
            )
            _print_status(item)
            return item

        cmd = [
            "nmap",
            "-Pn",
            "-p",
            str(port),
            "--script",
            "oracle-sid-brute",
            "--script-args",
            f"oracle-sid-brute.sidfile={tmp_path}",
            host,
        ]
        pretty = " ".join(cmd)
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        raw = {
            "tool": "nmap",
            "sid": sid,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        if completed.stdout.strip():
            console.print(completed.stdout.rstrip())
        responds = bool(
            re.search(rf"\b{re.escape(sid)}\b", completed.stdout, re.I)
        ) and not re.search(r"0 SIDs found|No Oracle", completed.stdout, re.I)
        if responds:
            item = _result(
                check,
                pretty,
                "finding",
                f"SID '{sid}' appears to respond (nmap informative check)",
                raw=raw,
            )
        else:
            item = _result(
                check,
                pretty,
                "ok",
                f"SID '{sid}' not confirmed as valid",
                raw=raw,
            )
        _print_status(item)
        return item
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


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
    """Execute Oracle TNS enumeration for the resolved target."""
    target = _resolve_target(args)
    if not target:
        console.print(
            "[red]Target required[/red]: pass positional TARGET, -t/--target, "
            "or --latest with an existing report."
        )
        return 2

    port: int = args.port
    timeout: int = args.timeout
    dry_run = bool(args.dry_run)

    console.print(
        f"[bold]Oracle TNS enum[/bold] → {target}:{port}"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )
    console.print(
        "[dim]Note:[/dim] default DB credentials (scott/tiger, etc.) are NOT tested; "
        "see docs/cheatsheets/oracle.md for manual reference."
    )

    require_tools(["nmap", "tnscmd10g", "odat"])

    checks: list[dict[str, Any]] = []
    checks.append(_check_nmap_tns(target, port, timeout, dry_run))
    tnscmd_item = _check_tnscmd(target, port, timeout, dry_run)
    checks.append(tnscmd_item)
    checks.append(
        _check_sid_wordlist(target, port, timeout, dry_run, args.sid_wordlist)
    )
    checks.append(_check_sid_probe(target, port, timeout, dry_run, args.sid))

    parsed = (tnscmd_item.get("raw") or {}).get("parsed") or {}
    findings = [c for c in checks if c.get("status") == "finding"]

    data: dict[str, Any] = {
        "port": port,
        "timeout": timeout,
        "dry_run": dry_run,
        "sid": args.sid,
        "sid_wordlist": args.sid_wordlist,
        "parsed_tnscmd": parsed,
        "checks": checks,
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
        prog="oracle_enum.py",
        description=(
            "Oracle TNS enumeration (version, listener status, optional SID wordlist). "
            "Does NOT test default credentials (scott/tiger, …)."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
