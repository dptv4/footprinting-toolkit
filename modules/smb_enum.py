#!/usr/bin/env python3
"""SMB enumeration: discovery, null/guest sessions, shares, users (no brute force)."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import load_latest, render_table, save_report
from core.runner import require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "smb"
DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 120
NMAP_DISCOVERY_SCRIPTS = (
    "smb-os-discovery,smb-protocols,smb2-security-mode,smb2-time"
)
NMAP_ENUM_SCRIPTS = "smb-enum-shares,smb-enum-users"

_USER_RID_RE = re.compile(
    r"user:\[(?P<name>[^\]]+)\]\s+rid:\[(?P<rid>[^\]]+)\]",
    re.IGNORECASE,
)
_SHARE_LINE_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?P<type>Disk|IPC|Printer|—|-)\s*(?P<comment>.*)?$",
    re.IGNORECASE,
)
_SMBMAP_PERM_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?P<perms>READ(?:\s*,\s*WRITE)?|WRITE|READ ONLY|NO ACCESS|DEAD|DISABLED)",
    re.IGNORECASE,
)


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
        help="SMB host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="SMB host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Preferred SMB port (default: {DEFAULT_PORT}; nmap still probes 139,445)",
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
        help="Use target from the latest report when positional/-t is omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path for JSON report (writes sibling .md too)",
    )
    parser.add_argument(
        "--user",
        default=None,
        help="Optional username for authenticated smbclient/smbmap (else null session only)",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Optional password for authenticated smbclient/smbmap",
    )
    parser.add_argument(
        "--domain",
        default=None,
        help="Optional domain/workgroup for authenticated checks",
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
            port = int(entry.get("port", -1))
            service = str(entry.get("service", "")).lower()
            if port in {139, 445} or service in {"smb", "microsoft-ds", "netbios-ssn"}:
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


def _parse_smbclient_shares(stdout: str) -> list[dict[str, str]]:
    shares: list[dict[str, str]] = []
    in_table = False
    for line in stdout.splitlines():
        if re.search(r"Sharename\s+Type", line, re.IGNORECASE):
            in_table = True
            continue
        if in_table and re.match(r"^-+", line.strip()):
            continue
        if in_table and not line.strip():
            if shares:
                break
            continue
        if in_table and re.match(r"^(SMB|Reconnecting|Unable|session)", line, re.I):
            break
        if not in_table:
            continue
        match = _SHARE_LINE_RE.match(line)
        if match:
            shares.append(
                {
                    "share": match.group("name"),
                    "type": match.group("type"),
                    "comment": (match.group("comment") or "").strip(),
                    "access": "listed (null/auth)",
                }
            )
    return shares


def _parse_smbmap_shares(stdout: str) -> list[dict[str, str]]:
    shares: list[dict[str, str]] = []
    for line in stdout.splitlines():
        match = _SMBMAP_PERM_RE.search(line)
        if not match:
            continue
        name = match.group("name")
        if name.lower() in {"disk", "----", "sharename"}:
            continue
        perms = match.group("perms").upper().replace(" ", "")
        if "READ" in perms and "WRITE" in perms:
            access = "READ/WRITE"
        elif "READ" in perms:
            access = "READ"
        elif "WRITE" in perms:
            access = "WRITE"
        elif "NOACCESS" in perms.replace(" ", ""):
            access = "NO ACCESS"
        else:
            access = match.group("perms")
        shares.append({"share": name, "access": access, "source": "smbmap"})
    return shares


def _parse_enumdomusers(stdout: str) -> list[dict[str, str]]:
    users: list[dict[str, str]] = []
    for match in _USER_RID_RE.finditer(stdout):
        rid_raw = match.group("rid")
        try:
            rid_int = int(rid_raw, 0)
            rid_display = f"{rid_raw} ({rid_int})"
        except ValueError:
            rid_display = rid_raw
        users.append({"user": match.group("name"), "rid": rid_display, "rid_raw": rid_raw})
    return users


def _signing_not_required(text: str) -> bool:
    lowered = text.lower()
    if "message signing is enabled and required" in lowered:
        return False
    if "message signing is enabled but not required" in lowered:
        return True
    if re.search(r"signing\s*:\s*disabled", lowered):
        return True
    if "not required" in lowered and "sign" in lowered:
        return True
    return False


def _smbv1_enabled(text: str) -> bool:
    lowered = text.lower()
    if re.search(r"smb\s*v?1|nt lm 0\.12|dialects?.*1\.|smbv1:\s*true|smbv1.*enabled", lowered):
        # Avoid false positive on "smbv1: false" / "not enabled"
        if re.search(r"smbv1\s*[:=]\s*false|smbv1.*not enabled|smb1.*disabled", lowered):
            return False
        return True
    return False


def _anonymous_share_access(shares: list[dict[str, str]]) -> bool:
    for share in shares:
        access = str(share.get("access", "")).upper()
        name = str(share.get("share", ""))
        if name.endswith("$") and "WRITE" not in access:
            continue
        if any(tok in access for tok in ("READ", "WRITE", "LISTED")):
            return True
    return False


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


def _check_nmap_discovery(
    host: str, port: int, timeout: int, dry_run: bool
) -> dict[str, Any]:
    cmd = [
        "nmap",
        "-Pn",
        "-p",
        "139,445",
        "-sV",
        "--script",
        NMAP_DISCOVERY_SCRIPTS,
        host,
    ]

    def finding_pred(stdout: str, _parsed: Any) -> str | None:
        findings: list[str] = []
        if _signing_not_required(stdout):
            findings.append("SMB signing not required")
        if _smbv1_enabled(stdout):
            findings.append("SMBv1 appears enabled")
        return "; ".join(findings) if findings else None

    return _run_external(
        "nmap-smb-discovery",
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="nmap",
        finding_pred=finding_pred,
    )


def _check_smbclient(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
    *,
    user: str | None = None,
    password: str | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    if user is None:
        check = "smbclient-null-list"
        cmd = ["smbclient", "-N", "-L", f"//{host}", "-p", str(port)]
        label = "null session"
    else:
        check = "smbclient-auth-list"
        auth = f"{user}%{password or ''}"
        cmd = ["smbclient", "-L", f"//{host}", "-U", auth, "-p", str(port)]
        if domain:
            cmd.extend(["-W", domain])
        label = f"auth as {domain + chr(92) if domain else ''}{user}"

    def finding_pred(stdout: str, parsed: Any) -> str | None:
        shares = parsed if isinstance(parsed, list) else _parse_smbclient_shares(stdout)
        if user is None and shares and _anonymous_share_access(
            [{**s, "access": s.get("access", "LISTED")} for s in shares]
        ):
            return f"Anonymous share listing via smbclient ({len(shares)} share(s), {label})"
        return None

    item = _run_external(
        check,
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="smbclient",
        finding_pred=finding_pred,
        parse=_parse_smbclient_shares,
    )
    shares = (item.get("raw") or {}).get("parsed") or []
    if shares and not dry_run:
        render_table(shares, title=f"smbclient shares ({label})")
    return item


def _check_smbmap(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
    *,
    user: str,
    password: str,
    domain: str | None = None,
    check_name: str,
) -> dict[str, Any]:
    cmd = [
        "smbmap",
        "-H",
        host,
        "-u",
        user,
        "-p",
        password,
        "-P",
        str(port),
    ]
    if domain:
        cmd.extend(["-d", domain])

    def finding_pred(stdout: str, parsed: Any) -> str | None:
        shares = parsed if isinstance(parsed, list) else _parse_smbmap_shares(stdout)
        interesting = [
            s
            for s in shares
            if s.get("access") in {"READ", "WRITE", "READ/WRITE"}
            and not str(s.get("share", "")).endswith("$")
        ]
        anon_like = user in {"", "guest"}
        if anon_like and interesting:
            return (
                f"Anonymous/guest share access via smbmap "
                f"({len(interesting)} readable/writable non-admin share(s))"
            )
        writable = [s for s in shares if "WRITE" in str(s.get("access", "")).upper()]
        if writable:
            return f"Writable share(s) detected: {', '.join(s['share'] for s in writable)}"
        return None

    item = _run_external(
        check_name,
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="smbmap",
        finding_pred=finding_pred,
        parse=_parse_smbmap_shares,
    )
    shares = (item.get("raw") or {}).get("parsed") or []
    if shares and not dry_run:
        render_table(shares, title=f"smbmap ({check_name})")
    return item


def _check_rpcclient(
    host: str, timeout: int, dry_run: bool
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    rpc_cmds = "srvinfo;enumdomusers;enumdomgroups;querydispinfo;netshareenumall"
    cmd = ["rpcclient", "-U", "", "-N", host, "-c", rpc_cmds]

    def finding_pred(stdout: str, parsed: Any) -> str | None:
        users = parsed if isinstance(parsed, list) else _parse_enumdomusers(stdout)
        if users:
            return f"Null session enumerated {len(users)} domain user(s) via rpcclient"
        if "netshareenum" in stdout.lower() or "share" in stdout.lower():
            if "NT_STATUS_ACCESS_DENIED" not in stdout:
                return "Null session rpcclient returned share/domain info"
        return None

    item = _run_external(
        "rpcclient-null-enum",
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="rpcclient",
        finding_pred=finding_pred,
        parse=_parse_enumdomusers,
    )
    users = (item.get("raw") or {}).get("parsed") or []
    if users and not dry_run:
        render_table(users, title="rpcclient enumdomusers (user / RID)")
    return item, users if isinstance(users, list) else []


def _check_enum4linux(host: str, timeout: int, dry_run: bool) -> dict[str, Any]:
    cmd = ["enum4linux-ng", "-A", host]
    return _run_external(
        "enum4linux-ng",
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="enum4linux-ng",
    )


def _check_nmap_enum(host: str, timeout: int, dry_run: bool) -> dict[str, Any]:
    cmd = [
        "nmap",
        "-Pn",
        "-p",
        "139,445",
        "--script",
        NMAP_ENUM_SCRIPTS,
        host,
    ]

    def finding_pred(stdout: str, _parsed: Any) -> str | None:
        if re.search(r"Anonymous access|account_used:\s*guest|READ|WRITE", stdout, re.I):
            if "Anonymous access: <none>" in stdout:
                return None
            return "nmap smb-enum-* reported anonymous/guest share or user info"
        return None

    return _run_external(
        "nmap-smb-enum-null",
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        tool="nmap",
        finding_pred=finding_pred,
    )


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


def _collect_shares(checks: list[dict[str, Any]]) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for item in checks:
        parsed = (item.get("raw") or {}).get("parsed") or []
        if not isinstance(parsed, list):
            continue
        for share in parsed:
            if "share" not in share:
                continue
            key = share["share"]
            prev = merged.get(key, {})
            merged[key] = {**prev, **share}
    return list(merged.values())


def run(args: argparse.Namespace) -> int:
    """Execute SMB enumeration for the resolved target."""
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
    user: str | None = args.user
    password: str | None = args.password
    domain: str | None = args.domain

    console.print(
        f"[bold]SMB enum[/bold] → {target} (prefer :{port})"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )

    # Warn once about missing external tools; individual checks skip as needed.
    require_tools(["nmap", "smbclient", "smbmap", "rpcclient", "enum4linux-ng"])

    checks: list[dict[str, Any]] = []

    # 1. nmap discovery / security mode / protocols
    checks.append(_check_nmap_discovery(target, port, timeout, dry_run))

    # 2. smbclient null session share list
    checks.append(_check_smbclient(target, port, timeout, dry_run))

    # 3. smbmap null + guest
    checks.append(
        _check_smbmap(
            target,
            port,
            timeout,
            dry_run,
            user="",
            password="",
            check_name="smbmap-null",
        )
    )
    checks.append(
        _check_smbmap(
            target,
            port,
            timeout,
            dry_run,
            user="guest",
            password="",
            check_name="smbmap-guest",
        )
    )

    # 4. rpcclient null enum (+ users/RIDs)
    rpc_item, users = _check_rpcclient(target, timeout, dry_run)
    checks.append(rpc_item)

    # 5. enum4linux-ng (optional)
    checks.append(_check_enum4linux(target, timeout, dry_run))

    # 6. nmap share/user enum (null session scripts)
    checks.append(_check_nmap_enum(target, timeout, dry_run))

    # Authenticated repeats when credentials provided (no brute force).
    if user is not None:
        console.print(
            f"[bold]Authenticated checks[/bold] as "
            f"{(domain + chr(92)) if domain else ''}{user}"
        )
        checks.append(
            _check_smbclient(
                target,
                port,
                timeout,
                dry_run,
                user=user,
                password=password or "",
                domain=domain,
            )
        )
        checks.append(
            _check_smbmap(
                target,
                port,
                timeout,
                dry_run,
                user=user,
                password=password or "",
                domain=domain,
                check_name="smbmap-auth",
            )
        )

    shares = _collect_shares(checks)
    findings = [c for c in checks if c.get("status") == "finding"]

    data: dict[str, Any] = {
        "port": port,
        "timeout": timeout,
        "dry_run": dry_run,
        "auth": {
            "user": user,
            "domain": domain,
            "password_set": bool(password),
        },
        "checks": checks,
        "shares": shares,
        "users": users,
        "findings": [
            {"check": f["check"], "summary": f["summary"]} for f in findings
        ],
    }

    if shares and not dry_run:
        render_table(shares, title="Aggregated SMB shares")
    if users and not dry_run:
        render_table(users, title="Enumerated users / RIDs")

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
        prog="smb_enum.py",
        description=(
            "SMB enumeration (null/guest/optional auth): discovery, shares, users. "
            "Enumeration only — no exploitation or credential brute force."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
