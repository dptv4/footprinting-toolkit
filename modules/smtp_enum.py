#!/usr/bin/env python3
"""SMTP enumeration: banner, EHLO, nmap, open-relay probe, optional user enum, STARTTLS cert."""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import load_latest, render_table, save_report
from core.runner import require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "smtp"
DEFAULT_PORT = 25
DEFAULT_TIMEOUT = 30
DEFAULT_DELAY = 0.2
NMAP_PORTS = "25,465,587"
NMAP_SCRIPTS = "smtp-commands,smtp-open-relay,smtp-ntlm-info"
# External domains for open-relay probe only (no DATA / no delivery).
RELAY_FROM = "probe@example.com"
RELAY_TO = "probe@example.org"

_VERSIONISH_RE = re.compile(
    r"(postfix|exim|sendmail|exchange|microsoft.?esmpt|courier|opensmtpd|"
    r"haraka|mailenable|lotus|domino|zimbra|kerio|qmail|"
    r"\b\d+\.\d+(?:\.\d+)?\b)",
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
        help="SMTP host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="SMTP host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"SMTP port (default: {DEFAULT_PORT}; nmap also probes 465,587)",
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
        help="Use target from the latest discovery/smtp report when omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path for JSON report (writes sibling .md too)",
    )
    parser.add_argument(
        "--userlist",
        default=None,
        help="Optional user list file for VRFY/EXPN/RCPT enum (no built-in list)",
    )
    parser.add_argument(
        "--method",
        choices=("vrfy", "expn", "rcpt", "all"),
        default="all",
        help="User enumeration method when --userlist is set (default: all)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"Delay between user-enum attempts in seconds (default: {DEFAULT_DELAY})",
    )
    parser.add_argument(
        "--ehlo-host",
        default="footprinting.local",
        help="Hostname sent in EHLO/HELO (default: footprinting.local)",
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
            if port in {25, 465, 587} or service in {"smtp", "smtps", "submission"}:
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


def _recv_smtp(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    sock.settimeout(timeout)
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        # SMTP multiline: last line is "NNN <sp>..."
        lines = text.splitlines()
        if lines and re.match(r"^\d{3} ", lines[-1]):
            break
        if len(b"".join(chunks)) > 65536:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def _send_smtp(sock: socket.socket, command: str, timeout: float) -> str:
    payload = (command.rstrip("\r\n") + "\r\n").encode("utf-8", errors="replace")
    sock.sendall(payload)
    return _recv_smtp(sock, timeout)


def _smtp_quit(sock: socket.socket | None, timeout: float) -> None:
    if sock is None:
        return
    try:
        _send_smtp(sock, "QUIT", timeout)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _connect(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit_tls: bool = False,
) -> tuple[socket.socket, str]:
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    if implicit_tls or port == 465:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock: socket.socket = ctx.wrap_socket(raw, server_hostname=host)
        banner = _recv_smtp(sock, timeout)
        return sock, banner
    banner = _recv_smtp(raw, timeout)
    return raw, banner


def _parse_ehlo_extensions(reply: str) -> list[str]:
    exts: list[str] = []
    for line in reply.splitlines():
        # 250-STARTTLS / 250 AUTH LOGIN PLAIN
        match = re.match(r"^250[\s\-](.+)$", line.strip())
        if not match:
            continue
        token = match.group(1).strip()
        if token.lower().startswith("hello") or "pleased to meet" in token.lower():
            continue
        exts.append(token)
    return exts


def _banner_reveals_software(banner: str) -> str | None:
    cleaned = banner.strip()
    if not cleaned:
        return None
    if _VERSIONISH_RE.search(cleaned):
        return f"Banner discloses software/version: {cleaned.splitlines()[0][:160]}"
    return None


def _check_banner_ehlo(
    host: str,
    port: int,
    timeout: float,
    dry_run: bool,
    ehlo_host: str,
) -> dict[str, Any]:
    check = "banner-ehlo"
    cmd = f"TCP {host}:{port} → banner + EHLO {ehlo_host} + QUIT"

    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
        item = _result(
            check,
            cmd,
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True},
        )
        _print_status(item)
        return item

    sock: socket.socket | None = None
    try:
        sock, banner = _connect(host, port, timeout)
        ehlo = _send_smtp(sock, f"EHLO {ehlo_host}", timeout)
        if not ehlo.startswith("250"):
            # Some servers want HELO fallback
            ehlo = _send_smtp(sock, f"HELO {ehlo_host}", timeout)
        extensions = _parse_ehlo_extensions(ehlo)
        raw = {
            "banner": banner.strip(),
            "ehlo": ehlo.strip(),
            "extensions": extensions,
        }
        if extensions:
            render_table(
                [{"extension": e} for e in extensions],
                title=f"SMTP EHLO extensions ({host}:{port})",
            )
        finding = _banner_reveals_software(banner)
        if finding:
            item = _result(check, cmd, "finding", finding, raw=raw)
        else:
            item = _result(
                check,
                cmd,
                "ok",
                f"Banner/EHLO ok ({len(extensions)} extension line(s))",
                raw=raw,
            )
        _print_status(item)
        return item
    except OSError as exc:
        item = _result(check, cmd, "fail", f"Connection failed: {exc}")
        _print_status(item)
        return item
    finally:
        _smtp_quit(sock, timeout)


def _check_nmap(host: str, timeout: int, dry_run: bool) -> dict[str, Any]:
    check = "nmap-smtp"
    cmd = [
        "nmap",
        "-Pn",
        "-p",
        NMAP_PORTS,
        "-sV",
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
    if re.search(r"open.?relay|Relayering allowed|Server is an open relay", out, re.I):
        findings.append("nmap smtp-open-relay indicates open relay")
    if re.search(r"NTLMSSP|Target_Name|Product_Version", out, re.I):
        findings.append("smtp-ntlm-info disclosed NTLM details")
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


def _check_open_relay(
    host: str,
    port: int,
    timeout: float,
    dry_run: bool,
    ehlo_host: str,
) -> dict[str, Any]:
    """Probe open relay with MAIL FROM/RCPT TO only — never send DATA."""
    check = "open-relay"
    cmd = (
        f"EHLO → MAIL FROM:<{RELAY_FROM}> → RCPT TO:<{RELAY_TO}> → RSET/QUIT "
        f"(no DATA) @ {host}:{port}"
    )

    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
        item = _result(
            check, cmd, "skipped", "dry-run — not executed", raw={"dry_run": True}
        )
        _print_status(item)
        return item

    sock: socket.socket | None = None
    try:
        sock, _banner = _connect(host, port, timeout)
        _send_smtp(sock, f"EHLO {ehlo_host}", timeout)
        mail = _send_smtp(sock, f"MAIL FROM:<{RELAY_FROM}>", timeout)
        rcpt = _send_smtp(sock, f"RCPT TO:<{RELAY_TO}>", timeout)
        # Abort transaction — never DATA.
        rset = _send_smtp(sock, "RSET", timeout)
        raw = {
            "mail_from": RELAY_FROM,
            "rcpt_to": RELAY_TO,
            "mail_reply": mail.strip(),
            "rcpt_reply": rcpt.strip(),
            "rset_reply": rset.strip(),
            "data_sent": False,
        }
        mail_ok = mail.startswith("250")
        rcpt_ok = rcpt.startswith("250")
        if mail_ok and rcpt_ok:
            item = _result(
                check,
                cmd,
                "finding",
                "Possible open relay: MAIL FROM/RCPT TO accepted for external domains "
                "(DATA not sent)",
                raw=raw,
            )
        else:
            item = _result(
                check,
                cmd,
                "ok",
                f"Relay probe rejected (MAIL={mail[:3]}, RCPT={rcpt[:3]})",
                raw=raw,
            )
        _print_status(item)
        return item
    except OSError as exc:
        item = _result(check, cmd, "fail", f"Relay probe failed: {exc}")
        _print_status(item)
        return item
    finally:
        _smtp_quit(sock, timeout)


def _cmd_appears_enabled(reply: str) -> bool:
    """Heuristic: command exists (even if user unknown) vs unimplemented."""
    code = reply[:3]
    if code in {"250", "251", "252"}:
        return True
    if code in {"502", "500"}:
        return False
    if re.search(r"not available|disabled|not support|unrecognized|command", reply, re.I):
        return False
    # 550 user unknown ⇒ command is implemented
    if code == "550":
        return True
    return False


def _probe_vrfy_expn(sock: socket.socket, timeout: float) -> dict[str, Any]:
    """Return whether VRFY/EXPN appear enabled."""
    vrfy = _send_smtp(sock, "VRFY root", timeout)
    expn = _send_smtp(sock, "EXPN root", timeout)
    return {
        "vrfy": _cmd_appears_enabled(vrfy),
        "expn": _cmd_appears_enabled(expn),
        "vrfy_raw": vrfy,
        "expn_raw": expn,
    }


def _user_exists_reply(method: str, reply: str) -> bool:
    code = reply[:3]
    if method in {"vrfy", "expn"}:
        return code in {"250", "251", "252"}
    # RCPT TO
    return code == "250"


def _check_user_enum(
    host: str,
    port: int,
    timeout: float,
    dry_run: bool,
    ehlo_host: str,
    userlist: str | None,
    method: str,
    delay: float,
) -> dict[str, Any]:
    check = "user-enum"
    cmd = f"VRFY/EXPN/RCPT with --userlist ({method}), delay={delay}s @ {host}:{port}"

    if not userlist:
        item = _result(
            check,
            cmd,
            "skipped",
            "--userlist not provided (no built-in user list)",
        )
        _print_status(item)
        return item

    path = Path(userlist)
    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd} file={path}")
        item = _result(
            check,
            cmd,
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "userlist": str(path), "method": method},
        )
        _print_status(item)
        return item

    if not path.is_file():
        item = _result(check, cmd, "fail", f"Userlist not found: {path}")
        _print_status(item)
        return item

    users = [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not users:
        item = _result(check, cmd, "skipped", "Userlist is empty")
        _print_status(item)
        return item

    sock: socket.socket | None = None
    try:
        sock, _banner = _connect(host, port, timeout)
        _send_smtp(sock, f"EHLO {ehlo_host}", timeout)
        caps = _probe_vrfy_expn(sock, timeout)
        vrfy_on = bool(caps.get("vrfy"))
        expn_on = bool(caps.get("expn"))

        methods: list[str]
        if method == "all":
            methods = ["vrfy", "expn", "rcpt"]
        else:
            methods = [method]

        # Skip VRFY/EXPN when disabled; always allow RCPT path.
        active: list[str] = []
        skipped_methods: list[str] = []
        for m in methods:
            if m == "vrfy" and not vrfy_on:
                skipped_methods.append("vrfy")
                console.print(
                    "[yellow]VRFY disabled/unavailable[/yellow] — skipping VRFY enum"
                )
                continue
            if m == "expn" and not expn_on:
                skipped_methods.append("expn")
                console.print(
                    "[yellow]EXPN disabled/unavailable[/yellow] — skipping EXPN enum"
                )
                continue
            active.append(m)

        if not active:
            item = _result(
                check,
                cmd,
                "skipped",
                "No usable enum methods (VRFY/EXPN disabled; RCPT not selected)",
                raw={"caps": caps, "skipped_methods": skipped_methods},
            )
            _print_status(item)
            return item

        hits: list[dict[str, str]] = []
        attempts = 0
        for user in users:
            for m in active:
                attempts += 1
                if m == "vrfy":
                    reply = _send_smtp(sock, f"VRFY {user}", timeout)
                elif m == "expn":
                    reply = _send_smtp(sock, f"EXPN {user}", timeout)
                else:
                    _send_smtp(sock, f"MAIL FROM:<probe@{ehlo_host}>", timeout)
                    reply = _send_smtp(sock, f"RCPT TO:<{user}>", timeout)
                    _send_smtp(sock, "RSET", timeout)
                if _user_exists_reply(m, reply):
                    hits.append(
                        {
                            "user": user,
                            "method": m,
                            "code": reply[:3],
                            "reply": reply.splitlines()[0][:160],
                        }
                    )
                    console.print(
                        f"[magenta]found[/magenta] {user} via {m.upper()}: {reply[:3]}"
                    )
                if delay > 0:
                    time.sleep(delay)

        raw = {
            "caps": {
                "vrfy": vrfy_on,
                "expn": expn_on,
                "vrfy_raw": caps.get("vrfy_raw"),
                "expn_raw": caps.get("expn_raw"),
            },
            "methods": active,
            "skipped_methods": skipped_methods,
            "attempts": attempts,
            "hits": hits,
        }
        if hits:
            render_table(hits, title="SMTP user enumeration hits")
            item = _result(
                check,
                cmd,
                "finding",
                f"Enumerated {len(hits)} hit(s) across {attempts} attempt(s)",
                raw=raw,
            )
        else:
            item = _result(
                check,
                cmd,
                "ok",
                f"No users confirmed ({attempts} attempt(s))",
                raw=raw,
            )
        _print_status(item)
        return item
    except OSError as exc:
        item = _result(check, cmd, "fail", f"User enum failed: {exc}")
        _print_status(item)
        return item
    finally:
        _smtp_quit(sock, timeout)


def _extensions_from_checks(checks: list[dict[str, Any]]) -> list[str]:
    for item in checks:
        if item.get("check") == "banner-ehlo":
            return list((item.get("raw") or {}).get("extensions") or [])
    return []


def _has_starttls(extensions: list[str]) -> bool:
    return any(e.upper().startswith("STARTTLS") for e in extensions)


def _check_starttls_cert(
    host: str,
    port: int,
    timeout: int,
    dry_run: bool,
    extensions: list[str],
) -> dict[str, Any]:
    check = "starttls-cert"
    cmd = [
        "openssl",
        "s_client",
        "-starttls",
        "smtp",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
    ]
    pretty = " ".join(cmd)

    if port == 465:
        # Implicit TLS — use plain s_client without -starttls
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:{port}",
            "-servername",
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
            raw={"dry_run": True},
        )
        _print_status(item)
        return item

    if port != 465 and not _has_starttls(extensions):
        item = _result(
            check,
            pretty,
            "skipped",
            "STARTTLS not advertised in EHLO — skipping cert check",
        )
        _print_status(item)
        return item

    if not tool_available("openssl"):
        require_tools(["openssl"])
        item = _result(
            check, pretty, "skipped", "openssl not installed — check skipped"
        )
        _print_status(item)
        return item

    import subprocess

    try:
        proc = subprocess.run(
            cmd,
            input="Q\n",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        item = _result(check, pretty, "fail", f"openssl failed: {exc}")
        _print_status(item)
        return item

    blob = stdout + "\n" + stderr
    subject = ""
    issuer = ""
    dates = ""
    sub_m = re.search(r"subject=([^\n]+)", blob, re.I)
    iss_m = re.search(r"issuer=([^\n]+)", blob, re.I)
    not_before = re.search(r"notBefore=([^\n]+)", blob, re.I)
    not_after = re.search(r"notAfter=([^\n]+)", blob, re.I)
    if sub_m:
        subject = sub_m.group(1).strip()
    if iss_m:
        issuer = iss_m.group(1).strip()
    if not_before or not_after:
        dates = f"{not_before.group(1).strip() if not_before else '?'} → {not_after.group(1).strip() if not_after else '?'}"

    raw = {
        "returncode": rc,
        "subject": subject,
        "issuer": issuer,
        "validity": dates,
        "stdout": stdout[-4000:],
        "stderr": stderr[-2000:],
    }
    if subject or issuer:
        render_table(
            [
                {"field": "subject", "value": subject},
                {"field": "issuer", "value": issuer},
                {"field": "validity", "value": dates},
            ],
            title=f"SMTP TLS certificate ({host}:{port})",
        )
        item = _result(
            check,
            pretty,
            "finding",
            f"TLS cert: {subject or '(no subject)'}",
            raw=raw,
        )
    elif "CONNECTED" in blob:
        item = _result(
            check, pretty, "ok", "Connected via TLS but cert fields not parsed", raw=raw
        )
    else:
        item = _result(check, pretty, "fail", "openssl s_client did not connect", raw=raw)
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
    """Execute SMTP enumeration for the resolved target."""
    target = _resolve_target(args)
    if not target:
        console.print(
            "[red]Target required[/red]: pass positional TARGET, -t/--target, "
            "or --latest with an existing report."
        )
        return 2

    port: int = args.port
    timeout = float(args.timeout)
    dry_run = bool(args.dry_run)
    ehlo_host: str = args.ehlo_host

    console.print(
        f"[bold]SMTP enum[/bold] → {target}:{port}"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )

    require_tools(["nmap", "openssl"])

    checks: list[dict[str, Any]] = []
    checks.append(_check_banner_ehlo(target, port, timeout, dry_run, ehlo_host))
    checks.append(_check_nmap(target, int(timeout), dry_run))
    checks.append(_check_open_relay(target, port, timeout, dry_run, ehlo_host))
    checks.append(
        _check_user_enum(
            target,
            port,
            timeout,
            dry_run,
            ehlo_host,
            args.userlist,
            args.method,
            float(args.delay),
        )
    )
    extensions = _extensions_from_checks(checks)
    # In dry-run, still attempt openssl dry-run for STARTTLS path visibility.
    if dry_run:
        extensions = extensions or ["STARTTLS"]
    checks.append(
        _check_starttls_cert(target, port, int(timeout), dry_run, extensions)
    )

    findings = [c for c in checks if c.get("status") == "finding"]
    data: dict[str, Any] = {
        "port": port,
        "timeout": timeout,
        "dry_run": dry_run,
        "ehlo_host": ehlo_host,
        "userlist": args.userlist,
        "method": args.method,
        "delay": args.delay,
        "checks": checks,
        "extensions": extensions if not dry_run else [],
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
        prog="smtp_enum.py",
        description=(
            "SMTP enumeration (banner, EHLO, nmap, open-relay probe, optional user enum, "
            "STARTTLS cert). Enumeration only — no credential brute force; open-relay "
            "probe never sends DATA."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
