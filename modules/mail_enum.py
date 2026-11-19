#!/usr/bin/env python3
"""IMAP/POP3 enumeration: banner, capabilities, TLS certs, nmap (no anonymous login)."""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import load_latest, render_table, save_report
from core.runner import require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "mail"
DEFAULT_TIMEOUT = 30
DEFAULT_PORT = 143  # common-flag default; overridden by --protocol/--ports
IMAP_PORTS = (143, 993)
POP3_PORTS = (110, 995)
ALL_PORTS = (110, 143, 993, 995)
IMPLICIT_TLS_PORTS = {993, 995}
NMAP_SCRIPTS = (
    "imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info"
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
        help="Mail host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="Mail host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=(
            f"Single port hint (default: {DEFAULT_PORT}). "
            "Prefer --ports or --protocol for multi-port scans."
        ),
    )
    parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated port list override (e.g. 143,993)",
    )
    parser.add_argument(
        "--protocol",
        choices=("imap", "pop3", "all"),
        default="all",
        help="Protocols to enumerate (default: all)",
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
        help="Use target from the latest discovery/mail report when omitted",
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
        help="Optional username — only with --password; enables LIST/STAT (no anon login)",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Optional password — only with --user; enables LIST/STAT (no anon login)",
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
            if port in ALL_PORTS or any(
                s in service for s in ("imap", "pop3", "imaps", "pop3s")
            ):
                host = entry.get("host") or report.get("target")
                if host:
                    return str(host)
    return None


def _resolve_ports(args: argparse.Namespace) -> list[int]:
    if args.ports:
        ports: list[int] = []
        for part in str(args.ports).split(","):
            part = part.strip()
            if not part:
                continue
            ports.append(int(part))
        return sorted(set(ports))

    protocol = args.protocol
    if protocol == "imap":
        base = list(IMAP_PORTS)
    elif protocol == "pop3":
        base = list(POP3_PORTS)
    else:
        base = list(ALL_PORTS)

    # If user explicitly changed --port from default and didn't pass --ports,
    # include that port (keeps common --port flag useful).
    if args.port and args.port not in base:
        base.append(args.port)
    return sorted(set(base))


def _protocol_for_port(port: int) -> str:
    if port in IMAP_PORTS or port in {143, 993}:
        return "imap"
    if port in POP3_PORTS or port in {110, 995}:
        return "pop3"
    # Heuristic fallback
    if port in {143, 993}:
        return "imap"
    return "pop3"


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


def _recv_pop3(sock: socket.socket, timeout: float, multiline: bool = False) -> str:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        if multiline:
            normalized = text.replace("\r\n", "\n")
            if "\n.\n" in normalized or normalized.rstrip().endswith("\n."):
                break
            if text.startswith("-ERR"):
                break
        else:
            if text.startswith(("+OK", "-ERR")) and ("\n" in text or len(text) > 3):
                break
        if len(b"".join(chunks)) > 65536:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def _recv_imap(sock: socket.socket, timeout: float, tag: str | None = None) -> str:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        if tag is None and text.startswith("*"):
            # untagged greeting
            if "\n" in text or len(text) > 5:
                break
        if tag and re.search(rf"^{re.escape(tag)} (OK|NO|BAD)", text, re.M | re.I):
            break
        if len(b"".join(chunks)) > 65536:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def _connect(
    host: str, port: int, timeout: float
) -> tuple[socket.socket, str]:
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    if port in IMPLICIT_TLS_PORTS:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock: socket.socket = ctx.wrap_socket(raw, server_hostname=host)
    else:
        sock = raw

    proto = _protocol_for_port(port)
    if proto == "imap":
        banner = _recv_imap(sock, timeout, tag=None)
    else:
        banner = _recv_pop3(sock, timeout, multiline=False)
    return sock, banner


def _close(sock: socket.socket | None, port: int, timeout: float) -> None:
    if sock is None:
        return
    try:
        if _protocol_for_port(port) == "imap":
            sock.sendall(b"a9 LOGOUT\r\n")
            _recv_imap(sock, timeout, tag="a9")
        else:
            sock.sendall(b"QUIT\r\n")
            _recv_pop3(sock, timeout, multiline=False)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _capability_findings(proto: str, capabilities: str) -> list[str]:
    """Findings for cleartext login risk / missing STARTTLS."""
    caps = capabilities.upper()
    findings: list[str] = []
    if proto == "imap":
        login_disabled = "LOGINDISABLED" in caps
        has_starttls = "STARTTLS" in caps
        # LOGIN allowed without TLS if LOGINDISABLED absent on cleartext port context
        if not login_disabled:
            findings.append(
                "IMAP LOGIN available (LOGINDISABLED absent) — cleartext login risk on non-TLS"
            )
        if not has_starttls:
            findings.append("IMAP STARTTLS not advertised")
    else:
        # POP3: USER/PASS in CAPA without STLS
        has_user = bool(re.search(r"\bUSER\b", caps))
        has_stls = "STLS" in caps or "STARTTLS" in caps
        if has_user and not has_stls:
            findings.append(
                "POP3 USER advertised without STLS — cleartext auth risk"
            )
        if not has_stls:
            findings.append("POP3 STLS/STARTTLS not advertised")
    return findings


def _check_banner_caps(
    host: str,
    port: int,
    timeout: float,
    dry_run: bool,
) -> dict[str, Any]:
    proto = _protocol_for_port(port)
    check = f"banner-caps-{proto}-{port}"
    if proto == "imap":
        cmd = f"TCP{'/SSL' if port in IMPLICIT_TLS_PORTS else ''} {host}:{port} → banner + a1 CAPABILITY + LOGOUT"
    else:
        cmd = f"TCP{'/SSL' if port in IMPLICIT_TLS_PORTS else ''} {host}:{port} → banner + CAPA + QUIT"

    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
        item = _result(
            check, cmd, "skipped", "dry-run — not executed", raw={"dry_run": True, "port": port}
        )
        _print_status(item)
        return item

    sock: socket.socket | None = None
    try:
        sock, banner = _connect(host, port, timeout)
        if proto == "imap":
            sock.sendall(b"a1 CAPABILITY\r\n")
            caps_raw = _recv_imap(sock, timeout, tag="a1")
        else:
            sock.sendall(b"CAPA\r\n")
            caps_raw = _recv_pop3(sock, timeout, multiline=True)

        raw = {
            "port": port,
            "protocol": proto,
            "implicit_tls": port in IMPLICIT_TLS_PORTS,
            "banner": banner.strip(),
            "capabilities_raw": caps_raw.strip(),
        }
        console.print(f"[green]Banner[/green] :{port}: {banner.strip().splitlines()[0][:160] if banner.strip() else '(empty)'}")

        findings = []
        # Cleartext-login findings only meaningful on non-implicit-TLS ports
        if port not in IMPLICIT_TLS_PORTS:
            findings.extend(_capability_findings(proto, caps_raw))
        else:
            # Still note missing STARTTLS is N/A; check LOGINDISABLED absence is less critical on TLS
            if proto == "imap" and "LOGINDISABLED" not in caps_raw.upper():
                # On 993, LOGIN over TLS is expected — not a finding by itself
                pass

        if findings:
            item = _result(check, cmd, "finding", "; ".join(findings), raw=raw)
        else:
            item = _result(
                check,
                cmd,
                "ok",
                f"{proto.upper()} :{port} banner/capabilities ok",
                raw=raw,
            )
        _print_status(item)
        return item
    except OSError as exc:
        item = _result(
            check, cmd, "fail", f"Connect failed on :{port}: {exc}", raw={"port": port}
        )
        _print_status(item)
        return item
    finally:
        _close(sock, port, timeout)


def _parse_openssl_dates(blob: str) -> tuple[datetime | None, datetime | None]:
    not_before = not_after = None
    m1 = re.search(r"notBefore=([^\n]+)", blob, re.I)
    m2 = re.search(r"notAfter=([^\n]+)", blob, re.I)
    for match, setter in ((m1, "before"), (m2, "after")):
        if not match:
            continue
        raw = match.group(1).strip()
        parsed: datetime | None = None
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError):
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
                try:
                    parsed = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
        if setter == "before":
            not_before = parsed
        else:
            not_after = parsed
    return not_before, not_after


def _parse_openssl_cert(blob: str) -> dict[str, Any]:
    subject = issuer = ""
    sub_m = re.search(r"subject=([^\n]+)", blob, re.I)
    iss_m = re.search(r"issuer=([^\n]+)", blob, re.I)
    if sub_m:
        subject = sub_m.group(1).strip()
    if iss_m:
        issuer = iss_m.group(1).strip()

    sans: list[str] = []
    san_block = re.search(
        r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", blob, re.I
    )
    if san_block:
        sans = [p.strip() for p in san_block.group(1).split(",") if p.strip()]
    # Also DNS from openssl -brief sometimes absent; try DNS: lines
    for m in re.finditer(r"DNS:([^\s,]+)", blob):
        val = f"DNS:{m.group(1)}"
        if val not in sans:
            sans.append(val)

    cn = ""
    cn_m = re.search(r"CN\s*=\s*([^,/]+)", subject, re.I)
    if cn_m:
        cn = cn_m.group(1).strip()

    not_before, not_after = _parse_openssl_dates(blob)
    proto_m = re.search(r"Protocol\s*:\s*([^\n]+)", blob, re.I)
    cipher_m = re.search(r"Cipher\s*:\s*([^\n]+)", blob, re.I)
    # Newer openssl: "Negotiated TLS1.3 ..." / "NEW  / TLSv1.3, ..."
    if not proto_m:
        proto_m = re.search(r"(TLSv1\.\d|SSL\w*)", blob)
    if not cipher_m:
        cipher_m = re.search(r"Cipher\s+is\s+(\S+)", blob, re.I)

    verify_m = re.search(r"verify return code:\s*(\d+)\s*\(([^)]*)\)", blob, re.I)
    verify_code = int(verify_m.group(1)) if verify_m else None
    verify_text = verify_m.group(2).strip() if verify_m else ""

    self_signed = False
    if subject and issuer and subject == issuer:
        self_signed = True
    if verify_code in {18, 19} or re.search(r"self.?signed", verify_text, re.I):
        self_signed = True
    if re.search(r"self.?signed", blob, re.I):
        self_signed = True

    now = datetime.now(timezone.utc)
    expired = False
    if not_after is not None:
        end = not_after if not_after.tzinfo else not_after.replace(tzinfo=timezone.utc)
        expired = end < now

    return {
        "cn": cn,
        "subject": subject,
        "san": sans,
        "issuer": issuer,
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "protocol": (proto_m.group(1).strip() if proto_m else ""),
        "cipher": (cipher_m.group(1).strip() if cipher_m else ""),
        "verify_code": verify_code,
        "verify_text": verify_text,
        "self_signed": self_signed,
        "expired": expired,
    }


def _openssl_cmd(host: str, port: int) -> list[str]:
    if port in IMPLICIT_TLS_PORTS:
        return [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:{port}",
            "-servername",
            host,
            "-showcerts",
        ]
    proto = _protocol_for_port(port)
    starttls = "imap" if proto == "imap" else "pop3"
    return [
        "openssl",
        "s_client",
        "-starttls",
        starttls,
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-showcerts",
    ]


def _check_tls_cert(
    host: str, port: int, timeout: int, dry_run: bool
) -> dict[str, Any]:
    check = f"tls-cert-{port}"
    cmd = _openssl_cmd(host, port)
    pretty = " ".join(cmd)

    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(
            check, pretty, "skipped", "dry-run — not executed", raw={"dry_run": True, "port": port}
        )
        _print_status(item)
        return item

    if not tool_available("openssl"):
        item = _result(
            check, pretty, "skipped", "openssl not installed — check skipped", raw={"port": port}
        )
        _print_status(item)
        return item

    try:
        proc = subprocess.run(
            cmd,
            input="Q\n",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        blob = proc.stdout + "\n" + proc.stderr
        cert = _parse_openssl_cert(blob)
        raw = {"port": port, "returncode": proc.returncode, **cert, "openssl_tail": blob[-3000:]}
        findings: list[str] = []
        if cert["expired"]:
            findings.append("certificate expired")
        if cert["self_signed"]:
            findings.append("certificate self-signed")

        rows = [
            {"field": "CN", "value": cert["cn"]},
            {"field": "SAN", "value": ", ".join(cert["san"])},
            {"field": "issuer", "value": cert["issuer"]},
            {
                "field": "validity",
                "value": f"{cert['not_before'] or '?'} → {cert['not_after'] or '?'}",
            },
            {"field": "protocol", "value": cert["protocol"]},
            {"field": "cipher", "value": cert["cipher"]},
        ]
        if cert["cn"] or cert["issuer"] or cert["protocol"]:
            render_table(rows, title=f"TLS cert :{port}")

        if findings:
            item = _result(check, pretty, "finding", "; ".join(findings), raw=raw)
        elif cert["cn"] or cert["issuer"]:
            item = _result(
                check,
                pretty,
                "ok",
                f"TLS cert ok (CN={cert['cn'] or 'n/a'})",
                raw=raw,
            )
        else:
            item = _result(
                check, pretty, "fail", "Could not parse TLS certificate", raw=raw
            )
        _print_status(item)
        return item
    except (OSError, subprocess.TimeoutExpired) as exc:
        item = _result(check, pretty, "fail", f"openssl failed: {exc}", raw={"port": port})
        _print_status(item)
        return item


def _check_nmap(host: str, ports: list[int], timeout: int, dry_run: bool) -> dict[str, Any]:
    check = "nmap-mail"
    port_list = ",".join(str(p) for p in ports) if ports else "110,143,993,995"
    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-p",
        port_list,
        "--script",
        NMAP_SCRIPTS,
        host,
    ]
    pretty = " ".join(cmd)

    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(
            check,
            pretty,
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "tool_available": tool_available("nmap")},
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
        "duration": completed.duration,
    }
    findings: list[str] = []
    out = completed.stdout
    if re.search(r"NTLMSSP|Target_Name|Product_Version", out, re.I):
        findings.append("NTLM info disclosed via imap/pop3 nmap scripts")
    if re.search(r"LOGINDISABLED", out, re.I) is None and re.search(
        r"imap-capabilities", out, re.I
    ):
        if re.search(r"\bLOGIN\b", out, re.I) and not re.search(
            r"STARTTLS", out, re.I
        ):
            findings.append("nmap capabilities suggest LOGIN without STARTTLS")
    if completed.stdout.strip():
        console.print(completed.stdout.rstrip())

    if findings:
        item = _result(check, pretty, "finding", "; ".join(findings), raw=raw)
    elif completed.returncode not in (0, 1) and not completed.stdout.strip():
        item = _result(
            check, pretty, "fail", f"nmap failed (rc={completed.returncode})", raw=raw
        )
    else:
        item = _result(
            check, pretty, "ok", f"nmap completed (rc={completed.returncode})", raw=raw
        )
    _print_status(item)
    return item


def _check_auth_list_stat(
    host: str,
    ports: list[int],
    timeout: float,
    dry_run: bool,
    user: str | None,
    password: str | None,
) -> dict[str, Any]:
    check = "auth-list-stat"
    cmd = "IMAP LOGIN+LIST / POP3 USER+PASS+STAT (only with explicit --user/--password)"

    if not user or password is None:
        item = _result(
            check,
            cmd,
            "skipped",
            "No --user/--password — skipping login (never attempts anonymous auth)",
        )
        _print_status(item)
        return item

    if dry_run:
        console.print(
            f"[cyan]\\[dry-run][/cyan] authenticated LIST/STAT as {user} on ports {ports}"
        )
        item = _result(
            check,
            cmd,
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "user": user},
        )
        _print_status(item)
        return item

    results: list[dict[str, Any]] = []
    for port in ports:
        proto = _protocol_for_port(port)
        sock: socket.socket | None = None
        try:
            sock, _banner = _connect(host, port, timeout)
            if proto == "imap":
                # Quote password safely for IMAP LOGIN
                login_cmd = f'a2 LOGIN "{user}" "{password}"\r\n'
                sock.sendall(login_cmd.encode("utf-8", errors="replace"))
                login_reply = _recv_imap(sock, timeout, tag="a2")
                mailboxes: list[str] = []
                if re.search(r"^a2 OK", login_reply, re.M | re.I):
                    sock.sendall(b'a3 LIST "" "*"\r\n')
                    list_reply = _recv_imap(sock, timeout, tag="a3")
                    for line in list_reply.splitlines():
                        if line.upper().startswith("* LIST"):
                            mailboxes.append(line.strip())
                    results.append(
                        {
                            "port": port,
                            "protocol": proto,
                            "ok": True,
                            "mailboxes": mailboxes,
                            "login_reply": login_reply.strip()[:300],
                        }
                    )
                    render_table(
                        [{"mailbox": m} for m in mailboxes[:50]],
                        title=f"IMAP LIST :{port}",
                    )
                else:
                    results.append(
                        {
                            "port": port,
                            "protocol": proto,
                            "ok": False,
                            "login_reply": login_reply.strip()[:300],
                        }
                    )
            else:
                sock.sendall(f"USER {user}\r\n".encode())
                user_reply = _recv_pop3(sock, timeout)
                sock.sendall(f"PASS {password}\r\n".encode())
                pass_reply = _recv_pop3(sock, timeout)
                stat_reply = ""
                ok = pass_reply.startswith("+OK")
                if ok:
                    sock.sendall(b"STAT\r\n")
                    stat_reply = _recv_pop3(sock, timeout)
                results.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "ok": ok,
                        "user_reply": user_reply.strip()[:200],
                        "pass_reply": pass_reply.strip()[:200],
                        "stat": stat_reply.strip()[:200],
                    }
                )
                if ok and stat_reply:
                    console.print(f"[green]POP3 STAT[/green] :{port}: {stat_reply.strip()}")
        except OSError as exc:
            results.append({"port": port, "protocol": proto, "ok": False, "error": str(exc)})
        finally:
            _close(sock, port, timeout)

    ok_count = sum(1 for r in results if r.get("ok"))
    raw = {"user": user, "results": results}
    if ok_count:
        item = _result(
            check,
            cmd,
            "finding",
            f"Authenticated access on {ok_count}/{len(ports)} port(s)",
            raw=raw,
        )
    else:
        item = _result(
            check,
            cmd,
            "fail",
            "Login failed on all attempted ports",
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
    """Execute IMAP/POP3 enumeration for the resolved target."""
    target = _resolve_target(args)
    if not target:
        console.print(
            "[red]Target required[/red]: pass positional TARGET, -t/--target, "
            "or --latest with an existing report."
        )
        return 2

    if (args.user and args.password is None) or (args.password is not None and not args.user):
        console.print(
            "[red]Auth flags[/red]: provide both --user and --password, or neither "
            "(never attempts anonymous login)."
        )
        return 2

    ports = _resolve_ports(args)
    timeout = float(args.timeout)
    dry_run = bool(args.dry_run)

    console.print(
        f"[bold]MAIL enum[/bold] → {target} ports={ports} protocol={args.protocol}"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )

    require_tools(["nmap", "openssl"])

    checks: list[dict[str, Any]] = []
    for port in ports:
        checks.append(_check_banner_caps(target, port, timeout, dry_run))
        checks.append(_check_tls_cert(target, port, int(timeout), dry_run))

    checks.append(_check_nmap(target, ports, int(timeout), dry_run))
    checks.append(
        _check_auth_list_stat(
            target, ports, timeout, dry_run, args.user, args.password
        )
    )

    findings = [c for c in checks if c.get("status") == "finding"]
    data: dict[str, Any] = {
        "port": args.port,
        "ports": ports,
        "protocol": args.protocol,
        "timeout": timeout,
        "dry_run": dry_run,
        "auth": {
            "user": args.user,
            "password_set": args.password is not None,
        },
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
        prog="mail_enum.py",
        description=(
            "IMAP/POP3 enumeration (banner, capabilities, TLS certs, nmap). "
            "Never attempts anonymous login; LIST/STAT only with explicit --user/--password."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
