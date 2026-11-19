#!/usr/bin/env python3
"""Remote management enumeration: SSH, RDP, WinRM, RPC, rsync, r-services."""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import load_latest, render_table, save_report
from core.runner import require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "remote"
DEFAULT_PORT = 22
DEFAULT_TIMEOUT = 60

DEFAULT_SERVICES = ("ssh", "rdp", "winrm", "rpc", "rsync", "rservices")
DEFAULT_PORTS: dict[str, list[int]] = {
    "ssh": [22],
    "rdp": [3389],
    "winrm": [5985, 5986],
    "rpc": [135],
    "rsync": [873],
    "rservices": [512, 513, 514],
}

_WEAK_SSH_ALGO_RE = re.compile(
    r"(ssh-dss|dsa|diffie-hellman-group1|diffie-hellman-group-exchange-sha1|"
    r"hmac-md5|arcfour|3des-cbc|aes\d+-cbc|ssh-rsa@openssh\.com)",
    re.I,
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
        help="Host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="Host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Single-port hint (default: {DEFAULT_PORT}); prefer --ports/--services",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated port override applied across selected services",
    )
    parser.add_argument(
        "--services",
        default=",".join(DEFAULT_SERVICES),
        help=(
            "Comma-separated services to run: "
            "ssh,rdp,winrm,rpc,rsync,rservices (default: all)"
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
        help="Use target/open ports from the latest discovery report when available",
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
        help="Optional username for WinRM access check via netexec/nxc",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Optional password for WinRM access check via netexec/nxc",
    )


def _resolve_target(args: argparse.Namespace) -> str | None:
    target = args.target_flag or args.target
    if target:
        return target
    if not args.latest:
        return None
    for module in ("discovery", MODULE_NAME):
        report = load_latest(module)
        if report and report.get("target"):
            return str(report["target"])
    return None


def _discovery_open_ports(args: argparse.Namespace) -> set[int] | None:
    """Return open ports from latest discovery report, or None if unavailable."""
    if not args.latest:
        return None
    report = load_latest("discovery")
    if not report:
        return None
    data = report.get("data") or {}
    entries = data.get("ports") or data.get("open_ports") or []
    open_ports: set[int] = set()
    for entry in entries:
        try:
            port = int(entry.get("port", -1))
        except (TypeError, ValueError, AttributeError):
            continue
        state = str(entry.get("state", "open")).lower()
        if port > 0 and state in {"open", "open|filtered", ""}:
            open_ports.add(port)
    return open_ports or None


def _parse_services(raw: str) -> list[str]:
    wanted = [s.strip().lower() for s in raw.split(",") if s.strip()]
    unknown = [s for s in wanted if s not in DEFAULT_PORTS]
    if unknown:
        console.print(f"[yellow]Unknown services ignored[/yellow]: {', '.join(unknown)}")
    return [s for s in wanted if s in DEFAULT_PORTS] or list(DEFAULT_SERVICES)


def _parse_ports_override(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            ports.append(int(part))
    return sorted(set(ports))


def _service_ports(
    service: str,
    ports_override: list[int] | None,
    open_ports: set[int] | None,
) -> list[int]:
    base = list(ports_override) if ports_override else list(DEFAULT_PORTS[service])
    if open_ports is None:
        return base
    filtered = [p for p in base if p in open_ports]
    return filtered


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


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _banner_grab(host: str, port: int, timeout: float) -> str:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        try:
            data = sock.recv(256)
        except socket.timeout:
            # Some SSH banners need a nudge
            sock.sendall(b"\r\n")
            data = sock.recv(256)
    return data.decode("utf-8", errors="replace").strip()


# --- SSH --------------------------------------------------------------------

def enum_ssh(
    host: str,
    ports: list[int],
    timeout: int,
    dry_run: bool,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for port in ports:
        # 1. Banner
        check = f"ssh-banner-{port}"
        cmd = f"TCP banner {host}:{port}"
        if dry_run:
            console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
            item = _result(check, cmd, "skipped", "dry-run — not executed", raw={"port": port})
            _print_status(item)
            checks.append(item)
        else:
            try:
                banner = _banner_grab(host, port, float(timeout))
                raw = {"port": port, "banner": banner}
                findings = []
                if re.search(r"SSH-1\.|protocol 1", banner, re.I):
                    findings.append("SSH protocol 1 advertised")
                if findings:
                    item = _result(check, cmd, "finding", "; ".join(findings) + f" — {banner[:80]}", raw=raw)
                else:
                    item = _result(
                        check,
                        cmd,
                        "ok" if banner else "fail",
                        f"Banner: {banner[:120] or '(empty)'}",
                        raw=raw,
                    )
                _print_status(item)
                checks.append(item)
            except OSError as exc:
                item = _result(check, cmd, "fail", f"Banner failed: {exc}", raw={"port": port})
                _print_status(item)
                checks.append(item)

        # 2. ssh-audit
        check = f"ssh-audit-{port}"
        audit_cmd = ["ssh-audit", host, "-p", str(port)]
        if dry_run:
            run_cmd(audit_cmd, timeout=timeout, dry_run=True)
            item = _result(check, audit_cmd, "skipped", "dry-run — not executed")
            _print_status(item)
            checks.append(item)
        elif not tool_available("ssh-audit"):
            require_tools(["ssh-audit"])
            item = _result(check, audit_cmd, "skipped", "ssh-audit not installed — skipped")
            _print_status(item)
            checks.append(item)
        else:
            completed = run_cmd(audit_cmd, timeout=timeout, dry_run=False)
            raw = {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
            if completed.stdout.strip():
                console.print(completed.stdout.rstrip()[:4000])
            findings = []
            if _WEAK_SSH_ALGO_RE.search(completed.stdout):
                findings.append("weak algorithms reported by ssh-audit")
            if re.search(r"password", completed.stdout, re.I) and re.search(
                r"available|enabled|yes", completed.stdout, re.I
            ):
                findings.append("password authentication indicated")
            if findings:
                item = _result(check, audit_cmd, "finding", "; ".join(findings), raw=raw)
            else:
                item = _result(
                    check,
                    audit_cmd,
                    "ok",
                    f"ssh-audit completed (rc={completed.returncode})",
                    raw=raw,
                )
            _print_status(item)
            checks.append(item)

        # 3. nmap scripts
        check = f"ssh-nmap-{port}"
        nmap_cmd = [
            "nmap",
            "-Pn",
            "-p",
            str(port),
            "--script",
            "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
            host,
        ]
        if dry_run:
            run_cmd(nmap_cmd, timeout=timeout, dry_run=True)
            item = _result(check, nmap_cmd, "skipped", "dry-run — not executed")
            _print_status(item)
            checks.append(item)
        elif not tool_available("nmap"):
            item = _result(check, nmap_cmd, "skipped", "nmap not installed — skipped")
            _print_status(item)
            checks.append(item)
        else:
            completed = run_cmd(nmap_cmd, timeout=timeout, dry_run=False)
            raw = {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
            if completed.stdout.strip():
                console.print(completed.stdout.rstrip())
            findings = []
            if re.search(r"password", completed.stdout, re.I):
                findings.append("password auth method present")
            if _WEAK_SSH_ALGO_RE.search(completed.stdout):
                findings.append("weak SSH algorithms in ssh2-enum-algos")
            if re.search(r"SSH-1|protocol 1", completed.stdout, re.I):
                findings.append("SSH protocol 1 indicated")
            if findings:
                item = _result(check, nmap_cmd, "finding", "; ".join(findings), raw=raw)
            else:
                item = _result(
                    check,
                    nmap_cmd,
                    "ok",
                    f"nmap completed (rc={completed.returncode})",
                    raw=raw,
                )
            _print_status(item)
            checks.append(item)
    return checks


# --- RDP --------------------------------------------------------------------

def _parse_rdp_ntlm(stdout: str) -> dict[str, str]:
    info: dict[str, str] = {}
    patterns = {
        "hostname": r"(?:Target_Name|NetBIOS_Computer_Name|Computer name):\s*(\S+)",
        "domain": r"(?:NetBIOS_Domain_Name|DNS_Domain_Name|Domain name):\s*(\S+)",
        "os_version": r"(?:Product_Version|OS Version|Windows Version):\s*([^\n]+)",
        "dns_hostname": r"DNS_Computer_Name:\s*(\S+)",
    }
    for key, pat in patterns.items():
        match = re.search(pat, stdout, re.I)
        if match:
            info[key] = match.group(1).strip()
    return info


def enum_rdp(
    host: str,
    ports: list[int],
    timeout: int,
    dry_run: bool,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for port in ports:
        check = f"rdp-nmap-{port}"
        cmd = [
            "nmap",
            "-Pn",
            "-sV",
            "-p",
            str(port),
            "--script",
            "rdp-enum-encryption,rdp-ntlm-info",
            host,
        ]
        if dry_run:
            run_cmd(cmd, timeout=timeout, dry_run=True)
            item = _result(check, cmd, "skipped", "dry-run — not executed")
            _print_status(item)
            checks.append(item)
            continue
        if not tool_available("nmap"):
            item = _result(check, cmd, "skipped", "nmap not installed — skipped")
            _print_status(item)
            checks.append(item)
            continue

        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        ntlm = _parse_rdp_ntlm(completed.stdout)
        raw = {
            "port": port,
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
                title=f"RDP NTLM :{port}",
            )

        findings: list[str] = []
        # NLA detection
        nla_off = bool(
            re.search(
                r"NLA:\s*(Disabled|False|No)|CredSSP.*not|Security layer:\s*RDP",
                completed.stdout,
                re.I,
            )
        )
        nla_on = bool(re.search(r"NLA:\s*(Enabled|True|Yes)|CredSSP", completed.stdout, re.I))
        if nla_off or (not nla_on and re.search(r"rdp-enum-encryption|Security layer", completed.stdout, re.I)):
            if nla_off or not nla_on:
                findings.append("NLA appears disabled / not required")
        if ntlm:
            findings.append(
                "NTLM info: " + ", ".join(f"{k}={v}" for k, v in ntlm.items())
            )

        if findings:
            item = _result(check, cmd, "finding", "; ".join(findings), raw=raw)
        else:
            item = _result(
                check, cmd, "ok", f"nmap completed (rc={completed.returncode})", raw=raw
            )
        _print_status(item)
        checks.append(item)
    return checks


# --- WinRM ------------------------------------------------------------------

def _wsman_probe(host: str, port: int, timeout: float) -> dict[str, Any]:
    scheme = "https" if port == 5986 else "http"
    url = f"{scheme}://{host}:{port}/wsman"
    headers = {
        "Content-Type": "application/soap+xml;charset=UTF-8",
        "User-Agent": "footprinting-toolkit",
    }
    # Prefer requests if present
    try:
        import requests

        resp = requests.post(url, data=b"", headers=headers, timeout=timeout, verify=False)
        return {"url": url, "status_code": resp.status_code, "tool": "requests"}
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "error": str(exc), "tool": "requests"}

    req = urllib.request.Request(url, data=b"", headers=headers, method="POST")
    ctx = None
    if scheme == "https":
        import ssl

        ctx = ssl._create_unverified_context()  # noqa: S323 — enum only
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"url": url, "status_code": getattr(resp, "status", 200), "tool": "urllib"}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status_code": exc.code, "tool": "urllib"}
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "error": str(exc), "tool": "urllib"}


def enum_winrm(
    host: str,
    ports: list[int],
    timeout: int,
    dry_run: bool,
    user: str | None,
    password: str | None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for port in ports:
        check = f"winrm-wsman-{port}"
        cmd = f"POST {('https' if port == 5986 else 'http')}://{host}:{port}/wsman"
        if dry_run:
            console.print(f"[cyan]\\[dry-run][/cyan] {cmd}")
            item = _result(check, cmd, "skipped", "dry-run — not executed")
            _print_status(item)
            checks.append(item)
        else:
            probe = _wsman_probe(host, port, float(timeout))
            code = probe.get("status_code")
            # 401/405 (and sometimes 200/500) indicate WinRM listener
            active = code in {401, 405, 200, 500}
            if active:
                item = _result(
                    check,
                    cmd,
                    "finding",
                    f"WinRM/WSMAN appears active (HTTP {code})",
                    raw=probe,
                )
            elif probe.get("error"):
                item = _result(
                    check, cmd, "fail", f"WSMAN probe failed: {probe['error']}", raw=probe
                )
            else:
                item = _result(
                    check, cmd, "ok", f"WSMAN HTTP {code}", raw=probe
                )
            _print_status(item)
            checks.append(item)

    # nmap once for selected ports
    check = "winrm-nmap"
    port_list = ",".join(str(p) for p in ports) if ports else "5985,5986"
    cmd = ["nmap", "-Pn", "-sV", "-p", port_list, host]
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, cmd, "skipped", "dry-run — not executed")
        _print_status(item)
        checks.append(item)
    elif not tool_available("nmap"):
        item = _result(check, cmd, "skipped", "nmap not installed — skipped")
        _print_status(item)
        checks.append(item)
    else:
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        raw = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        if completed.stdout.strip():
            console.print(completed.stdout.rstrip())
        item = _result(
            check, cmd, "ok", f"nmap completed (rc={completed.returncode})", raw=raw
        )
        _print_status(item)
        checks.append(item)

    # Optional netexec / nxc access check
    check = "winrm-nxc-auth"
    if not user or password is None:
        item = _result(
            check,
            "nxc winrm TARGET -u -p",
            "skipped",
            "No --user/--password — skipping WinRM auth check",
        )
        _print_status(item)
        checks.append(item)
        return checks

    nxc = "nxc" if tool_available("nxc") else (
        "netexec" if tool_available("netexec") else None
    )
    cmd = [nxc or "nxc", "winrm", host, "-u", user, "-p", password]
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, cmd, "skipped", "dry-run — not executed", raw={"user": user})
        _print_status(item)
        checks.append(item)
        return checks
    if not nxc:
        require_tools(["nxc", "netexec"])
        item = _result(check, cmd, "skipped", "nxc/netexec not installed — skipped")
        _print_status(item)
        checks.append(item)
        return checks

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    raw = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "user": user,
    }
    if completed.stdout.strip():
        console.print(completed.stdout.rstrip())
    if re.search(r"\(Pwn3d!\)|\[.\]\s*\+|Successfully logged on|Login successful", completed.stdout, re.I):
        item = _result(
            check, cmd, "finding", f"WinRM access succeeded as {user}", raw=raw
        )
    else:
        item = _result(
            check,
            cmd,
            "ok",
            f"WinRM auth check finished (rc={completed.returncode})",
            raw=raw,
        )
    _print_status(item)
    checks.append(item)
    return checks


# --- RPC / WMI --------------------------------------------------------------

def enum_rpc(
    host: str,
    ports: list[int],
    timeout: int,
    dry_run: bool,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    port = ports[0] if ports else 135

    check = f"rpc-nmap-{port}"
    cmd = [
        "nmap",
        "-Pn",
        "-p",
        str(port),
        "--script",
        "msrpc-enum",
        host,
    ]
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, cmd, "skipped", "dry-run — not executed")
        _print_status(item)
        checks.append(item)
    elif not tool_available("nmap"):
        item = _result(check, cmd, "skipped", "nmap not installed — skipped")
        _print_status(item)
        checks.append(item)
    else:
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        raw = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        if completed.stdout.strip():
            console.print(completed.stdout.rstrip())
        item = _result(
            check, cmd, "ok", f"nmap msrpc-enum completed (rc={completed.returncode})", raw=raw
        )
        _print_status(item)
        checks.append(item)

    check = "rpc-rpcdump"
    rpcdump = (
        "impacket-rpcdump"
        if tool_available("impacket-rpcdump")
        else ("rpcdump.py" if tool_available("rpcdump.py") else None)
    )
    cmd = [rpcdump or "impacket-rpcdump", host]
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, cmd, "skipped", "dry-run — not executed")
        _print_status(item)
        checks.append(item)
        return checks
    if not rpcdump:
        require_tools(["impacket-rpcdump"])
        item = _result(check, cmd, "skipped", "impacket-rpcdump not installed — skipped")
        _print_status(item)
        checks.append(item)
        return checks

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    raw = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.stdout.strip():
        console.print(completed.stdout.rstrip()[:5000])
    findings = []
    if re.search(r"MS-RPRN|IRemotePrinter", completed.stdout, re.I):
        findings.append("MS-RPRN (PrintNightmare-related) endpoint present")
    if re.search(r"MS-EFSR|efsrpc|lsarpc.*efsr", completed.stdout, re.I):
        findings.append("MS-EFSR (PetitPotam-related) endpoint present")
    if findings:
        item = _result(check, cmd, "finding", "; ".join(findings), raw=raw)
    else:
        item = _result(
            check, cmd, "ok", f"rpcdump completed (rc={completed.returncode})", raw=raw
        )
    _print_status(item)
    checks.append(item)
    return checks


# --- rsync ------------------------------------------------------------------

def enum_rsync(
    host: str,
    ports: list[int],
    timeout: int,
    dry_run: bool,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    port = ports[0] if ports else 873

    check = f"rsync-nmap-{port}"
    cmd = [
        "nmap",
        "-Pn",
        "-p",
        str(port),
        "--script",
        "rsync-list-modules",
        host,
    ]
    modules: list[str] = []
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, cmd, "skipped", "dry-run — not executed")
        _print_status(item)
        checks.append(item)
    elif not tool_available("nmap"):
        item = _result(check, cmd, "skipped", "nmap not installed — skipped")
        _print_status(item)
        checks.append(item)
    else:
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        raw = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        if completed.stdout.strip():
            console.print(completed.stdout.rstrip())
        # nmap rsync-list-modules: "module_name    comment"
        flat: list[str] = []
        for m in re.finditer(
            r"(?:Module\s*[:=]\s*)?([A-Za-z0-9_\-]+)\s{2,}(.+)?",
            completed.stdout,
        ):
            name = m.group(1)
            if name.lower() not in {"module", "name", "rsync"}:
                flat.append(name)
        modules = sorted(set(flat))
        raw["modules"] = modules
        if modules:
            item = _result(
                check,
                cmd,
                "finding",
                f"rsync modules via nmap: {', '.join(modules)}",
                raw=raw,
            )
        else:
            item = _result(
                check, cmd, "ok", f"nmap completed (rc={completed.returncode})", raw=raw
            )
        _print_status(item)
        checks.append(item)

    check = "rsync-list-only"
    list_cmd = ["rsync", "--list-only", f"rsync://{host}:{port}/"]
    if dry_run:
        run_cmd(list_cmd, timeout=timeout, dry_run=True)
        run_cmd(
            ["rsync", "--list-only", f"rsync://{host}:{port}/<module>/"],
            timeout=timeout,
            dry_run=True,
        )
        item = _result(check, list_cmd, "skipped", "dry-run — not executed")
        _print_status(item)
        checks.append(item)
        return checks

    if not tool_available("rsync"):
        require_tools(["rsync"])
        item = _result(check, list_cmd, "skipped", "rsync not installed — skipped")
        _print_status(item)
        checks.append(item)
        return checks

    completed = run_cmd(list_cmd, timeout=timeout, dry_run=False)
    raw: dict[str, Any] = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "modules": [],
        "listings": {},
    }
    # Parse module names from rsync --list-only root
    root_modules = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if parts:
            # last token often module name, or first column
            name = parts[-1].strip().strip("/")
            if name and not name.startswith(".") and re.match(r"^[A-Za-z0-9_\-]+$", name):
                root_modules.append(name)
    if not root_modules and modules:
        root_modules = modules
    raw["modules"] = sorted(set(root_modules))

    for mod in raw["modules"]:
        mod_cmd = ["rsync", "--list-only", f"rsync://{host}:{port}/{mod}/"]
        mod_res = run_cmd(mod_cmd, timeout=timeout, dry_run=False)
        raw["listings"][mod] = mod_res.stdout[:4000]
        if mod_res.stdout.strip():
            console.print(f"[green]rsync://{host}/{mod}/[/green]")
            console.print(mod_res.stdout.rstrip()[:2000])

    if raw["modules"]:
        render_table([{"module": m} for m in raw["modules"]], title="rsync modules")
        item = _result(
            check,
            list_cmd,
            "finding",
            f"Listed {len(raw['modules'])} rsync module(s) (no download)",
            raw=raw,
        )
    else:
        item = _result(
            check,
            list_cmd,
            "ok",
            "No rsync modules listed",
            raw=raw,
        )
    _print_status(item)
    checks.append(item)
    return checks


# --- r-services -------------------------------------------------------------

def enum_rservices(
    host: str,
    ports: list[int],
    timeout: int,
    dry_run: bool,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    port_list = ",".join(str(p) for p in ports) if ports else "512-514"

    check = "rservices-nmap"
    cmd = ["nmap", "-Pn", "-sV", "-p", port_list, host]
    open_found: list[int] = []
    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(check, cmd, "skipped", "dry-run — not executed")
        _print_status(item)
        checks.append(item)
    elif not tool_available("nmap"):
        item = _result(check, cmd, "skipped", "nmap not installed — skipped")
        _print_status(item)
        checks.append(item)
    else:
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        raw = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        if completed.stdout.strip():
            console.print(completed.stdout.rstrip())
        for match in re.finditer(
            r"(\d+)/tcp\s+open\s+(\S+)", completed.stdout, re.I
        ):
            open_found.append(int(match.group(1)))
        raw["open_ports"] = open_found
        if open_found:
            names = []
            for p in open_found:
                names.append(
                    {512: "rexec", 513: "rlogin", 514: "rsh"}.get(p, str(p))
                )
            item = _result(
                check,
                cmd,
                "finding",
                f"Legacy r-service port(s) open: {', '.join(f'{n}({p})' for n, p in zip(names, open_found))}",
                raw=raw,
            )
        else:
            item = _result(
                check, cmd, "ok", "No r-service ports reported open", raw=raw
            )
        _print_status(item)
        checks.append(item)

    # rusers / rwho
    for tool, tool_cmd in (
        ("rusers", ["rusers", "-l", host]),
        ("rwho", ["rwho"]),
    ):
        check = f"rservices-{tool}"
        if dry_run:
            run_cmd(tool_cmd, timeout=timeout, dry_run=True)
            item = _result(check, tool_cmd, "skipped", "dry-run — not executed")
            _print_status(item)
            checks.append(item)
            continue
        if not tool_available(tool):
            require_tools([tool])
            item = _result(check, tool_cmd, "skipped", f"{tool} not installed — skipped")
            _print_status(item)
            checks.append(item)
            continue
        completed = run_cmd(tool_cmd, timeout=timeout, dry_run=False)
        raw = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        if completed.stdout.strip():
            console.print(completed.stdout.rstrip())
            item = _result(
                check,
                tool_cmd,
                "finding",
                f"{tool} returned data",
                raw=raw,
            )
        else:
            item = _result(
                check,
                tool_cmd,
                "ok",
                f"{tool} no output (rc={completed.returncode})",
                raw=raw,
            )
        _print_status(item)
        checks.append(item)
    return checks


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


def _summarize(
    service: str,
    ports: list[int],
    checks: list[dict[str, Any]],
    skipped_reason: str | None = None,
) -> dict[str, str]:
    if skipped_reason:
        return {
            "service": service,
            "port": ",".join(str(p) for p in ports) or "-",
            "estado": "skipped",
            "hallazgos": skipped_reason,
        }
    findings = [c["summary"] for c in checks if c.get("status") == "finding"]
    fails = [c for c in checks if c.get("status") == "fail"]
    if findings:
        estado = "finding"
        hallazgos = "; ".join(findings)[:200]
    elif fails and not checks:
        estado = "fail"
        hallazgos = "no checks"
    elif fails and all(c.get("status") in {"fail", "skipped"} for c in checks):
        estado = "fail/skipped"
        hallazgos = fails[0]["summary"][:200] if fails else ""
    else:
        estado = "ok"
        hallazgos = f"{len(checks)} check(s)"
    return {
        "service": service,
        "port": ",".join(str(p) for p in ports) or "-",
        "estado": estado,
        "hallazgos": hallazgos,
    }


def run(args: argparse.Namespace) -> int:
    """Execute remote-management enumeration for selected services."""
    target = _resolve_target(args)
    if not target:
        console.print(
            "[red]Target required[/red]: pass positional TARGET, -t/--target, "
            "or --latest with an existing report."
        )
        return 2

    if (args.user and args.password is None) or (args.password is not None and not args.user):
        console.print(
            "[red]Auth flags[/red]: provide both --user and --password for WinRM, or neither."
        )
        return 2

    services = _parse_services(args.services)
    ports_override = _parse_ports_override(args.ports)
    open_ports = _discovery_open_ports(args)
    dry_run = bool(args.dry_run)
    timeout = int(args.timeout)

    console.print(
        f"[bold]Remote enum[/bold] → {target} services={services}"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )
    if open_ports is not None:
        console.print(
            f"[green]--latest[/green]: filtering to discovery open ports "
            f"({len(open_ports)} ports)"
        )

    require_tools(
        [
            "nmap",
            "ssh-audit",
            "rsync",
            "impacket-rpcdump",
            "nxc",
            "rusers",
            "rwho",
        ]
    )

    all_checks: list[dict[str, Any]] = []
    summary_rows: list[dict[str, str]] = []
    per_service: dict[str, Any] = {}

    runners = {
        "ssh": lambda ports: enum_ssh(target, ports, timeout, dry_run),
        "rdp": lambda ports: enum_rdp(target, ports, timeout, dry_run),
        "winrm": lambda ports: enum_winrm(
            target, ports, timeout, dry_run, args.user, args.password
        ),
        "rpc": lambda ports: enum_rpc(target, ports, timeout, dry_run),
        "rsync": lambda ports: enum_rsync(target, ports, timeout, dry_run),
        "rservices": lambda ports: enum_rservices(target, ports, timeout, dry_run),
    }

    for service in services:
        ports = _service_ports(service, ports_override, open_ports)
        if not ports:
            reason = "ports closed / not in discovery report — service omitted"
            console.print(f"[yellow]Skip {service}[/yellow]: {reason}")
            skipped = _result(
                f"{service}-omit",
                f"{service} ports",
                "skipped",
                reason,
            )
            _print_status(skipped)
            all_checks.append(skipped)
            summary_rows.append(_summarize(service, [], [], reason))
            per_service[service] = {"ports": [], "checks": [skipped]}
            continue

        # Quick closed-port skip when not using discovery filter and not dry-run
        if not dry_run and open_ports is None and service in {"ssh", "rdp", "rpc", "rsync"}:
            live = [p for p in ports if _tcp_open(target, p, min(3.0, float(timeout)))]
            if not live:
                reason = f"TCP closed on {ports} — service omitted"
                console.print(f"[yellow]Skip {service}[/yellow]: {reason}")
                skipped = _result(
                    f"{service}-omit",
                    f"tcp {ports}",
                    "skipped",
                    reason,
                )
                _print_status(skipped)
                all_checks.append(skipped)
                summary_rows.append(_summarize(service, ports, [], reason))
                per_service[service] = {"ports": ports, "checks": [skipped]}
                continue
            ports = live

        console.print(f"[bold]→ {service}[/bold] ports={ports}")
        checks = runners[service](ports)
        all_checks.extend(checks)
        summary_rows.append(_summarize(service, ports, checks))
        per_service[service] = {"ports": ports, "checks": checks}

    render_table(summary_rows, title="Remote enumeration summary")

    findings = [c for c in all_checks if c.get("status") == "finding"]
    data: dict[str, Any] = {
        "port": args.port,
        "ports_override": ports_override,
        "services": services,
        "timeout": timeout,
        "dry_run": dry_run,
        "discovery_open_ports": sorted(open_ports) if open_ports else None,
        "auth": {
            "user": args.user,
            "password_set": args.password is not None,
        },
        "summary": summary_rows,
        "services_detail": per_service,
        "checks": all_checks,
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
        prog="remote_enum.py",
        description=(
            "Remote management enumeration (SSH, RDP, WinRM, RPC, rsync, r-services). "
            "Enumeration only — WinRM auth check requires explicit credentials."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
