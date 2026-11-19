#!/usr/bin/env python3
"""MySQL/MSSQL enumeration: nmap, handshake/version, empty-password check, optional auth queries."""

from __future__ import annotations

import argparse
import json
import re
import socket
import struct
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import load_latest, render_table, save_report
from core.runner import check_root, require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "db"
DEFAULT_TIMEOUT = 30
DEFAULT_PORT = 3306  # common-flag default; engine selects real ports
MYSQL_PORT = 3306
MSSQL_PORT = 1433
SQLBROWSER_PORT = 1434


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
        help="Database host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="Database host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=(
            f"Override engine TCP port (default hint: {DEFAULT_PORT}). "
            "MySQL default 3306, MSSQL 1433; SQL Browser stays 1434/udp."
        ),
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
        help="Print planned actions without connecting",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use target from the latest discovery/db report when omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path for JSON report (writes sibling .md too)",
    )
    parser.add_argument(
        "--engine",
        choices=("mysql", "mssql", "all"),
        default="all",
        help="Database engine(s) to enumerate (default: all)",
    )
    parser.add_argument(
        "--user",
        default=None,
        help="Optional username for authenticated checks (required with --password)",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Optional password for authenticated checks (required with --user)",
    )
    parser.add_argument(
        "--domain",
        default=None,
        help="Optional Windows domain for MSSQL/NTLM login via impacket",
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
            if port in {3306, 1433, 1434} or any(
                s in service for s in ("mysql", "ms-sql", "mssql", "sql")
            ):
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


def _has_creds(user: str | None, password: str | None) -> bool:
    return user is not None and password is not None


def _resolve_ports(args: argparse.Namespace) -> dict[str, int]:
    """Return engine → TCP port mapping for selected engines."""
    ports: dict[str, int] = {}
    if args.engine in {"mysql", "all"}:
        # --port overrides only when a single engine is selected.
        ports["mysql"] = args.port if args.engine == "mysql" else MYSQL_PORT
    if args.engine in {"mssql", "all"}:
        ports["mssql"] = args.port if args.engine == "mssql" else MSSQL_PORT
    return ports


# --- MySQL helpers -----------------------------------------------------------

def _parse_mysql_handshake(packet: bytes) -> dict[str, Any]:
    """Parse MySQL initial handshake packet (post length/seq header)."""
    if len(packet) < 5:
        return {}
    # Optional: include length header
    body = packet
    if packet[3] == 0 and len(packet) > 4:
        # length-prefixed: skip 3 length + 1 seq
        body = packet[4:]
    if not body:
        return {}
    protocol = body[0]
    rest = body[1:]
    try:
        end = rest.index(0)
    except ValueError:
        return {"protocol": protocol, "version": rest.decode("utf-8", errors="replace")}
    version = rest[:end].decode("utf-8", errors="replace")
    return {"protocol": protocol, "version": version}


def _mysql_handshake(host: str, port: int, timeout: float) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        header = sock.recv(4)
        if len(header) < 4:
            return {"error": "short header"}
        length = struct.unpack("<I", header[:3] + b"\x00")[0]
        seq = header[3]
        body = b""
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                break
            body += chunk
    info = _parse_mysql_handshake(body)
    info["packet_length"] = length
    info["sequence"] = seq
    return info


def _check_mysql_nmap(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
    user: str | None,
    password: str | None,
) -> dict[str, Any]:
    check = "mysql-nmap"
    scripts = ["mysql-info", "mysql-empty-password"]
    script_args: list[str] = []
    if _has_creds(user, password):
        scripts.extend(["mysql-variables", "mysql-audit"])
        script_args.append(f"mysqluser={user}")
        # nmap uses mysqlpass
        script_args.append(f"mysqlpass={password}")

    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-p",
        str(port),
        "--script",
        ",".join(scripts),
    ]
    if script_args:
        cmd.extend(["--script-args", ",".join(script_args)])
    cmd.append(host)
    pretty = " ".join(cmd)

    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, pretty, "skipped", "dry-run — not executed", raw={"dry_run": True})
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
    findings: list[str] = []
    if re.search(r"account_found|empty password|root account has empty password", completed.stdout, re.I):
        findings.append("nmap mysql-empty-password indicated empty password")
    if findings:
        item = _result(check, pretty, "finding", "; ".join(findings), raw=raw)
    else:
        item = _result(
            check, pretty, "ok", f"nmap completed (rc={completed.returncode})", raw=raw
        )
    _print_status(item)
    return item


def _check_mysql_handshake(
    host: str, port: int, timeout: float, dry_run: bool
) -> dict[str, Any]:
    check = "mysql-handshake"
    cmd = f"TCP {host}:{port} MySQL greeting (unauthenticated handshake)"

    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
        item = _result(check, cmd, "skipped", "dry-run — not executed", raw={"dry_run": True})
        _print_status(item)
        return item

    try:
        info = _mysql_handshake(host, port, timeout)
        version = info.get("version") or ""
        raw = info
        if version:
            console.print(f"[green]MySQL version[/green]: {version}")
            item = _result(
                check,
                cmd,
                "finding",
                f"Server version from handshake: {version}",
                raw=raw,
            )
        else:
            item = _result(check, cmd, "ok", "Handshake received (version not parsed)", raw=raw)
        _print_status(item)
        return item
    except OSError as exc:
        item = _result(check, cmd, "fail", f"Handshake failed: {exc}")
        _print_status(item)
        return item


def _check_mysql_empty_root(
    host: str, port: int, timeout: float, dry_run: bool
) -> dict[str, Any]:
    """Single configuration check: root with empty password (not brute force)."""
    check = "mysql-empty-root"
    cmd = f"pymysql connect root@ {host}:{port} password='' (single attempt)"

    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
        item = _result(check, cmd, "skipped", "dry-run — not executed", raw={"dry_run": True})
        _print_status(item)
        return item

    try:
        import pymysql
    except ImportError:
        item = _result(check, cmd, "skipped", "pymysql not installed — check skipped")
        _print_status(item)
        return item

    conn = None
    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user="root",
            password="",
            connect_timeout=max(1, int(timeout)),
            read_timeout=max(1, int(timeout)),
            write_timeout=max(1, int(timeout)),
        )
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION()")
            version = cur.fetchone()
        raw = {"login": True, "version": version}
        item = _result(
            check,
            cmd,
            "finding",
            "root with empty password accepted (misconfiguration)",
            raw=raw,
        )
        _print_status(item)
        return item
    except Exception as exc:  # noqa: BLE001 — auth failure is expected
        item = _result(
            check,
            cmd,
            "ok",
            f"root/empty rejected or unreachable ({type(exc).__name__})",
            raw={"login": False, "error": str(exc)[:300]},
        )
        _print_status(item)
        return item
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def _check_mysql_auth(
    host: str,
    port: int,
    timeout: float,
    dry_run: bool,
    user: str | None,
    password: str | None,
) -> dict[str, Any]:
    check = "mysql-auth-queries"
    cmd = (
        f"pymysql {user}@{host}:{port} → VERSION / SHOW DATABASES / "
        "mysql.user / SHOW GRANTS"
    )

    if not _has_creds(user, password):
        item = _result(
            check,
            cmd,
            "skipped",
            "No --user/--password — skipping authenticated MySQL queries",
        )
        _print_status(item)
        return item

    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
        item = _result(
            check, cmd, "skipped", "dry-run — not executed", raw={"dry_run": True, "user": user}
        )
        _print_status(item)
        return item

    try:
        import pymysql
    except ImportError:
        item = _result(check, cmd, "skipped", "pymysql not installed — check skipped")
        _print_status(item)
        return item

    conn = None
    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password or "",
            connect_timeout=max(1, int(timeout)),
            read_timeout=max(1, int(timeout)),
            write_timeout=max(1, int(timeout)),
        )
        data: dict[str, Any] = {}
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            data["version"] = cur.fetchone()
            cur.execute("SHOW DATABASES")
            data["databases"] = [r[0] for r in cur.fetchall()]
            try:
                cur.execute("SELECT user, host FROM mysql.user")
                data["users"] = [{"user": r[0], "host": r[1]} for r in cur.fetchall()]
            except Exception as exc:  # noqa: BLE001
                data["users_error"] = str(exc)[:200]
            try:
                cur.execute("SHOW GRANTS")
                data["grants"] = [r[0] for r in cur.fetchall()]
            except Exception as exc:  # noqa: BLE001
                data["grants_error"] = str(exc)[:200]

        if data.get("databases"):
            render_table(
                [{"database": d} for d in data["databases"]],
                title=f"MySQL databases ({user}@{host})",
            )
        if data.get("users"):
            render_table(data["users"][:50], title="MySQL users")
        if data.get("grants"):
            render_table(
                [{"grant": g} for g in data["grants"]],
                title="MySQL grants",
            )

        item = _result(
            check,
            cmd,
            "finding",
            f"Authenticated MySQL access as {user} "
            f"({len(data.get('databases') or [])} database(s))",
            raw=data,
        )
        _print_status(item)
        return item
    except Exception as exc:  # noqa: BLE001
        item = _result(
            check,
            cmd,
            "fail",
            f"Auth queries failed: {exc}",
            raw={"error": str(exc)[:300]},
        )
        _print_status(item)
        return item
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


# --- MSSQL helpers -----------------------------------------------------------

def _parse_ntlm_info(stdout: str) -> dict[str, str]:
    info: dict[str, str] = {}
    patterns = {
        "hostname": r"(?:NetBIOS_Computer_Name|Target_Name|Computer name):\s*(\S+)",
        "domain": r"(?:NetBIOS_Domain_Name|DNS_Domain_Name|Domain):\s*(\S+)",
        "dns_hostname": r"DNS_Computer_Name:\s*(\S+)",
        "os_version": r"(?:Product_Version|OS Version|Windows Version):\s*([^\n]+)",
    }
    for key, pat in patterns.items():
        match = re.search(pat, stdout, re.I)
        if match:
            info[key] = match.group(1).strip()
    # Fallback looser parse for nmap ms-sql-ntlm-info
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        left, right = line.split(":", 1)
        key = left.strip().lower().replace(" ", "_")
        val = right.strip()
        if "computer" in key and "dns" not in key and "hostname" not in info:
            info["hostname"] = val
        if "domain" in key and "dns" in key:
            info["domain"] = val
        if "product_version" in key or "os" in key:
            info.setdefault("os_version", val)
    return info


def _check_mssql_nmap(
    host: str, port: int, timeout: int, dry_run: bool
) -> dict[str, Any]:
    check = "mssql-nmap"
    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-p",
        str(port),
        "--script",
        "ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password",
        host,
    ]
    pretty = " ".join(cmd)

    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, pretty, "skipped", "dry-run — not executed", raw={"dry_run": True})
        _print_status(item)
        return item

    if not tool_available("nmap"):
        require_tools(["nmap"])
        item = _result(check, pretty, "skipped", "nmap not installed — check skipped")
        _print_status(item)
        return item

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    ntlm = _parse_ntlm_info(completed.stdout)
    raw = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "ntlm": ntlm,
    }
    if completed.stdout.strip():
        console.print(completed.stdout.rstrip())
    if ntlm:
        render_table(
            [{"field": k, "value": v} for k, v in ntlm.items()],
            title="MSSQL NTLM info",
        )

    findings: list[str] = []
    if re.search(r"empty password|sa account.*empty|Login Success", completed.stdout, re.I):
        findings.append("nmap ms-sql-empty-password indicated empty password")
    if ntlm:
        findings.append(
            "NTLM disclosed: "
            + ", ".join(f"{k}={v}" for k, v in ntlm.items())
        )

    if findings:
        item = _result(check, pretty, "finding", "; ".join(findings), raw=raw)
    else:
        item = _result(
            check, pretty, "ok", f"nmap completed (rc={completed.returncode})", raw=raw
        )
    _print_status(item)
    return item


def _check_sqlbrowser(
    host: str, timeout: int, dry_run: bool
) -> dict[str, Any]:
    check = "mssql-sqlbrowser"
    cmd = [
        "nmap",
        "-Pn",
        "-sU",
        "-p",
        str(SQLBROWSER_PORT),
        "--script",
        "ms-sql-info",
        host,
    ]
    pretty = " ".join(cmd)

    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, pretty, "skipped", "dry-run — not executed", raw={"dry_run": True})
        _print_status(item)
        return item

    if not tool_available("nmap"):
        item = _result(check, pretty, "skipped", "nmap not installed — check skipped")
        _print_status(item)
        return item

    if not check_root():
        item = _result(
            check,
            pretty,
            "skipped",
            "Root required for nmap -sU SQL Browser (1434/udp) — skipped",
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
    if re.search(r"Instance|tcp:\d+|Named Pipe", completed.stdout, re.I):
        item = _result(
            check,
            pretty,
            "finding",
            "SQL Browser returned instance information",
            raw=raw,
        )
    else:
        item = _result(
            check, pretty, "ok", f"nmap SQL Browser completed (rc={completed.returncode})", raw=raw
        )
    _print_status(item)
    return item


def _mssql_query_impacket(
    host: str,
    port: int,
    user: str,
    password: str,
    domain: str | None,
    timeout: int,
) -> dict[str, Any]:
    """Run read-only MSSQL queries via impacket TDS (no xp_cmdshell)."""
    from impacket import tds

    ms_sql = tds.MSSQL(host, port)
    ms_sql.connect()
    # login(database, username, password, domain, hashes, useWindowsAuth=...)
    domain_name = domain or ""
    # Prefer SQL auth unless domain provided
    if domain:
        ms_sql.login("", user, password, domain_name, None, True)
    else:
        ms_sql.login("", user, password, domain_name, None, False)

    results: dict[str, Any] = {}

    def _run(sql: str) -> list[Any]:
        rows: list[Any] = []
        # sqlQuery returns list of row dicts/lists depending on impacket version
        out = ms_sql.sql_query(sql)
        return out if out is not None else rows

    try:
        results["version"] = _run("SELECT @@version")
        results["databases"] = _run("SELECT name FROM sys.databases")
        results["principals"] = _run("SELECT name FROM sys.server_principals")
    finally:
        try:
            ms_sql.disconnect()
        except Exception:  # noqa: BLE001
            pass
    return results


def _mssql_query_cli(
    host: str,
    port: int,
    user: str,
    password: str,
    domain: str | None,
    timeout: int,
) -> dict[str, Any]:
    """Fallback: impacket-mssqlclient batch queries (read-only)."""
    if domain:
        target = f"{domain}/{user}:{password}@{host}"
        extra = ["-windows-auth"]
    else:
        target = f"{user}:{password}@{host}"
        extra = []
    queries = (
        "SELECT @@version;"
        "SELECT name FROM sys.databases;"
        "SELECT name FROM sys.server_principals;"
    )
    cmd = [
        "impacket-mssqlclient",
        target,
        "-port",
        str(port),
        *extra,
        "-q",
        queries,
    ]
    # Some builds use mssqlclient.py
    if not tool_available("impacket-mssqlclient"):
        if tool_available("mssqlclient.py"):
            cmd[0] = "mssqlclient.py"
        else:
            raise FileNotFoundError("impacket-mssqlclient not found")

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": " ".join(cmd[:2] + ["***"] + cmd[3:]),
    }


def _check_mssql_auth(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
    user: str | None,
    password: str | None,
    domain: str | None,
) -> dict[str, Any]:
    check = "mssql-auth-queries"
    cmd = (
        f"impacket TDS {user}@{host}:{port} → @@version / sys.databases / "
        "sys.server_principals (no xp_cmdshell)"
    )

    if not _has_creds(user, password):
        item = _result(
            check,
            cmd,
            "skipped",
            "No --user/--password — skipping authenticated MSSQL queries",
        )
        _print_status(item)
        return item

    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
        run_cmd(
            [
                "impacket-mssqlclient",
                f"{user}:***@{host}",
                "-port",
                str(port),
                "-q",
                "SELECT @@version",
            ],
            timeout=timeout,
            dry_run=True,
        )
        item = _result(
            check, cmd, "skipped", "dry-run — not executed", raw={"dry_run": True, "user": user}
        )
        _print_status(item)
        return item

    raw: dict[str, Any] = {}
    try:
        raw = _mssql_query_impacket(
            host, port, user or "", password or "", domain, timeout
        )
        # Normalize tabular display
        databases = raw.get("databases") or []
        principals = raw.get("principals") or []

        def _names(rows: Any) -> list[str]:
            names: list[str] = []
            if not isinstance(rows, list):
                return names
            for row in rows:
                if isinstance(row, dict):
                    val = row.get("name") or next(iter(row.values()), None)
                    if val is not None:
                        names.append(str(val))
                elif isinstance(row, (list, tuple)) and row:
                    names.append(str(row[0]))
                else:
                    names.append(str(row))
            return names

        db_names = _names(databases)
        principal_names = _names(principals)
        if db_names:
            render_table([{"database": n} for n in db_names], title="MSSQL databases")
        if principal_names:
            render_table(
                [{"principal": n} for n in principal_names[:50]],
                title="MSSQL server_principals",
            )
        item = _result(
            check,
            cmd,
            "finding",
            f"Authenticated MSSQL access as {user} "
            f"({len(db_names)} database(s))",
            raw={
                "version": raw.get("version"),
                "databases": db_names,
                "principals": principal_names,
            },
        )
        _print_status(item)
        return item
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]impacket TDS failed[/yellow]: {exc} — trying CLI")
        try:
            cli = _mssql_query_cli(
                host, port, user or "", password or "", domain, timeout
            )
            raw = cli
            if cli.get("stdout"):
                console.print(str(cli["stdout"])[:4000])
            if cli.get("returncode", 1) == 0 or "@@version" in str(cli.get("stdout", "")):
                item = _result(
                    check,
                    cmd,
                    "finding",
                    f"Authenticated MSSQL access via CLI as {user}",
                    raw=cli,
                )
            else:
                item = _result(
                    check,
                    cmd,
                    "fail",
                    f"MSSQL auth queries failed: {exc}",
                    raw={"tds_error": str(exc)[:300], "cli": cli},
                )
            _print_status(item)
            return item
        except Exception as exc2:  # noqa: BLE001
            item = _result(
                check,
                cmd,
                "fail",
                f"MSSQL auth queries failed: {exc2}",
                raw={"error": str(exc2)[:300], "tds_error": str(exc)[:300]},
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
    """Execute MySQL/MSSQL enumeration for the resolved target."""
    target = _resolve_target(args)
    if not target:
        console.print(
            "[red]Target required[/red]: pass positional TARGET, -t/--target, "
            "or --latest with an existing report."
        )
        return 2

    if (args.user and args.password is None) or (args.password is not None and not args.user):
        console.print(
            "[red]Auth flags[/red]: provide both --user and --password, or neither. "
            "Unauthenticated mode is the default."
        )
        return 2

    ports = _resolve_ports(args)
    timeout = float(args.timeout)
    dry_run = bool(args.dry_run)

    console.print(
        f"[bold]DB enum[/bold] → {target} engine={args.engine} ports={ports}"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )

    require_tools(["nmap", "impacket-mssqlclient"])

    checks: list[dict[str, Any]] = []

    if "mysql" in ports:
        mysql_port = ports["mysql"]
        checks.append(
            _check_mysql_nmap(
                target, mysql_port, int(timeout), dry_run, args.user, args.password
            )
        )
        checks.append(_check_mysql_handshake(target, mysql_port, timeout, dry_run))
        checks.append(_check_mysql_empty_root(target, mysql_port, timeout, dry_run))
        checks.append(
            _check_mysql_auth(
                target, mysql_port, timeout, dry_run, args.user, args.password
            )
        )

    if "mssql" in ports:
        mssql_port = ports["mssql"]
        checks.append(_check_mssql_nmap(target, mssql_port, int(timeout), dry_run))
        checks.append(_check_sqlbrowser(target, int(timeout), dry_run))
        checks.append(
            _check_mssql_auth(
                target,
                mssql_port,
                int(timeout),
                dry_run,
                args.user,
                args.password,
                args.domain,
            )
        )

    findings = [c for c in checks if c.get("status") == "finding"]
    ntlm = {}
    for c in checks:
        if c.get("check") == "mssql-nmap":
            ntlm = (c.get("raw") or {}).get("ntlm") or {}

    data: dict[str, Any] = {
        "port": args.port,
        "ports": ports,
        "engine": args.engine,
        "timeout": timeout,
        "dry_run": dry_run,
        "auth": {
            "user": args.user,
            "password_set": args.password is not None,
            "domain": args.domain,
        },
        "ntlm": ntlm,
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
        prog="db_enum.py",
        description=(
            "MySQL/MSSQL enumeration (nmap, handshake, empty-password config check, "
            "optional auth queries). Default is unauthenticated. No xp_cmdshell, "
            "no credential brute force."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
