#!/usr/bin/env python3
"""DNS enumeration: dig records, CHAOS version, AXFR, wordlist subs, reverse, nmap."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from core.parser import load_latest, render_table, save_report
from core.runner import check_root, require_tools, run_cmd, tool_available

console = Console(stderr=True)

MODULE_NAME = "dns"
DEFAULT_PORT = 53
DEFAULT_TIMEOUT = 60
DEFAULT_THREADS = 20
RECORD_TYPES = ("NS", "MX", "TXT", "SOA", "A", "AAAA", "ANY")
# External name used only to probe open recursion (not brute force).
RECURSION_PROBE_NAME = "example.com"
NMAP_SCRIPTS = "dns-nsid,dns-recursion,dns-zone-transfer"

_ANSWER_RE = re.compile(
    r"^(?P<name>\S+)\s+(?:\d+\s+)?IN\s+(?P<rtype>NS|MX|TXT|SOA|A|AAAA|CNAME|PTR|ANY)\s+(?P<data>.+)$",
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
        help="DNS server host / IP (positional)",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        default=None,
        help="DNS server host / IP (flag form)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"DNS port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Command / query timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned commands without connecting",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use DNS server from the latest discovery/dns report when omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path for JSON report (writes sibling .md too)",
    )
    parser.add_argument(
        "--domain",
        default=None,
        help="Domain to enumerate (required unless --dry-run)",
    )
    parser.add_argument(
        "--nameserver",
        default=None,
        help="Nameserver for dig queries (default: TARGET)",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Optional subdomain wordlist (no built-in list)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Thread pool size for subdomain resolution (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--reverse",
        default=None,
        metavar="CIDR",
        help="Optional reverse lookup CIDR (e.g. 10.10.10.0/28)",
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
            if port == 53 or service in {"domain", "dns"}:
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


def _dig_cmd(
    nameserver: str,
    *query_parts: str,
    port: int = DEFAULT_PORT,
) -> list[str]:
    cmd = ["dig", f"@{nameserver}", "-p", str(port), *query_parts, "+noall", "+answer"]
    return cmd


def _parse_dig_answers(stdout: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        match = _ANSWER_RE.match(stripped)
        if match:
            records.append(
                {
                    "name": match.group("name").rstrip("."),
                    "type": match.group("rtype").upper(),
                    "data": match.group("data").strip().strip('"'),
                }
            )
            continue
        # dig +short style leftover
        if stripped:
            records.append({"name": "", "type": "", "data": stripped.strip('"')})
    return records


def _run_dig(
    check: str,
    cmd: list[str],
    *,
    timeout: int,
    dry_run: bool,
    finding_pred: Any | None = None,
) -> dict[str, Any]:
    pretty = " ".join(cmd)
    available = tool_available("dig")

    if dry_run:
        run_cmd(cmd, timeout=timeout, dry_run=True)
        summary = (
            "dig not installed — check skipped"
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
        item = _result(check, pretty, "skipped", "dig not installed — check skipped")
        _print_status(item)
        return item

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    records = _parse_dig_answers(completed.stdout)
    raw: dict[str, Any] = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "duration": completed.duration,
        "records": records,
    }

    if completed.returncode not in (0, 1) and not completed.stdout.strip():
        item = _result(
            check,
            pretty,
            "fail",
            f"dig failed (rc={completed.returncode})",
            raw=raw,
        )
        _print_status(item)
        return item

    finding_summary = finding_pred(completed.stdout, records) if finding_pred else None
    if isinstance(finding_summary, str) and finding_summary:
        item = _result(check, pretty, "finding", finding_summary, raw=raw)
        _print_status(item)
        return item

    item = _result(
        check,
        pretty,
        "ok",
        f"dig completed (rc={completed.returncode}, {len(records)} answer line(s))",
        raw=raw,
    )
    _print_status(item)
    return item


def _check_record_types(
    nameserver: str,
    domain: str,
    port: int,
    timeout: int,
    dry_run: bool,
) -> tuple[dict[str, Any], dict[str, list[dict[str, str]]]]:
    """Query NS/MX/TXT/SOA/A/AAAA/ANY; one table row per type."""
    grouped: dict[str, list[dict[str, str]]] = {t: [] for t in RECORD_TYPES}
    rows: list[dict[str, str]] = []
    raw_by_type: dict[str, Any] = {}
    commands: list[str] = []

    if not tool_available("dig") and not dry_run:
        item = _result(
            "dig-records",
            f"dig @{nameserver} {domain} <TYPE>",
            "skipped",
            "dig not installed — check skipped",
        )
        _print_status(item)
        return item, grouped

    for rtype in RECORD_TYPES:
        cmd = _dig_cmd(nameserver, domain, rtype, port=port)
        commands.append(" ".join(cmd))
        if dry_run:
            run_cmd(cmd, timeout=timeout, dry_run=True)
            rows.append({"type": rtype, "count": "0", "sample": "(dry-run)"})
            continue

        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        records = _parse_dig_answers(completed.stdout)
        # Prefer typed records; fall back to attaching dig lines under this type.
        typed = [r for r in records if r.get("type") == rtype or not r.get("type")]
        for rec in typed:
            if not rec.get("type"):
                rec = {**rec, "type": rtype, "name": domain}
            grouped[rtype].append(rec)
        raw_by_type[rtype] = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "records": grouped[rtype],
        }
        sample = "; ".join(r["data"] for r in grouped[rtype][:3]) or "(none)"
        rows.append(
            {
                "type": rtype,
                "count": str(len(grouped[rtype])),
                "sample": sample[:120],
            }
        )

    if dry_run:
        item = _result(
            "dig-records",
            " ; ".join(commands),
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "types": list(RECORD_TYPES)},
        )
        _print_status(item)
        return item, grouped

    render_table(rows, title=f"DNS records @ {nameserver} → {domain}")
    item = _result(
        "dig-records",
        " ; ".join(commands),
        "ok",
        f"Queried {len(RECORD_TYPES)} record types",
        raw={"by_type": raw_by_type, "grouped": grouped},
    )
    _print_status(item)
    return item, grouped


def _chaos_reveals_version(stdout: str, records: list[dict[str, str]]) -> str | None:
    """Return finding text if CHAOS TXT discloses version/hostname."""
    for rec in records:
        payload = rec.get("data", "").strip()
        if payload and not payload.startswith(";"):
            return f"CHAOS version/hostname disclosed: {payload[:160]}"
    match = re.search(r'version\.bind.*"([^"]+)"', stdout, re.I)
    if match:
        return f"CHAOS version.bind disclosed: {match.group(1)}"
    match = re.search(r'hostname\.bind.*"([^"]+)"', stdout, re.I)
    if match:
        return f"CHAOS hostname.bind disclosed: {match.group(1)}"
    return None


def _check_chaos_version(
    nameserver: str, port: int, timeout: int, dry_run: bool
) -> dict[str, Any]:
    checks_raw: dict[str, Any] = {}
    findings: list[str] = []
    commands: list[str] = []

    for qname in ("version.bind", "hostname.bind"):
        cmd = [
            "dig",
            f"@{nameserver}",
            "-p",
            str(port),
            qname,
            "CHAOS",
            "TXT",
            "+noall",
            "+answer",
            "+comments",
        ]
        commands.append(" ".join(cmd))
        if dry_run:
            run_cmd(cmd, timeout=timeout, dry_run=True)
            continue
        if not tool_available("dig"):
            item = _result(
                "chaos-version",
                " ; ".join(commands),
                "skipped",
                "dig not installed — check skipped",
            )
            _print_status(item)
            return item

        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        records = _parse_dig_answers(completed.stdout)
        checks_raw[qname] = {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "records": records,
        }
        hit = _chaos_reveals_version(completed.stdout, records)
        if hit:
            findings.append(hit)

    if dry_run:
        item = _result(
            "chaos-version",
            " ; ".join(commands),
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True},
        )
        _print_status(item)
        return item

    if findings:
        item = _result(
            "chaos-version",
            " ; ".join(commands),
            "finding",
            "; ".join(findings),
            raw=checks_raw,
        )
    else:
        item = _result(
            "chaos-version",
            " ; ".join(commands),
            "ok",
            "No CHAOS version/hostname disclosure observed",
            raw=checks_raw,
        )
    _print_status(item)
    return item


def _ns_hosts_from_grouped(grouped: dict[str, list[dict[str, str]]]) -> list[str]:
    hosts: list[str] = []
    for rec in grouped.get("NS", []):
        data = rec.get("data", "").strip().rstrip(".")
        # NS data may be "ns1.example.com." or "10 ns1.example.com."
        parts = data.split()
        host = parts[-1].rstrip(".") if parts else ""
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _check_axfr(
    target: str,
    domain: str,
    nameserver: str,
    port: int,
    timeout: int,
    dry_run: bool,
    grouped: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    ns_list = _ns_hosts_from_grouped(grouped)
    servers = []
    for host in [*ns_list, target, nameserver]:
        if host and host not in servers:
            servers.append(host)

    if dry_run and not servers:
        servers = [nameserver or target, "<ns-from-dig>"]

    commands: list[str] = []
    transfers: dict[str, Any] = {}
    success: list[str] = []

    if not tool_available("dig") and not dry_run:
        item = _result(
            "axfr",
            f"dig AXFR @{target} {domain}",
            "skipped",
            "dig not installed — check skipped",
        )
        _print_status(item)
        return item

    for ns in servers:
        cmd = [
            "dig",
            f"@{ns}",
            "-p",
            str(port),
            "AXFR",
            domain,
            "+noall",
            "+answer",
        ]
        commands.append(" ".join(cmd))
        if dry_run:
            run_cmd(cmd, timeout=timeout, dry_run=True)
            continue

        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        records = _parse_dig_answers(completed.stdout)
        # AXFR success typically returns many records / Transfer failed absent
        failed = bool(
            re.search(
                r"Transfer failed|connection refused|timed out|NOTAUTH|REFUSED",
                completed.stdout + completed.stderr,
                re.I,
            )
        )
        ok_transfer = (not failed) and len(records) > 0 and completed.returncode == 0
        transfers[ns] = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "records": records,
            "success": ok_transfer,
        }
        if ok_transfer:
            success.append(ns)

    if dry_run:
        item = _result(
            "axfr",
            " ; ".join(commands),
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "servers": servers},
        )
        _print_status(item)
        return item

    if success:
        all_records = []
        for ns in success:
            all_records.extend(transfers[ns].get("records") or [])
        item = _result(
            "axfr",
            " ; ".join(commands),
            "finding",
            f"CRITICAL: zone transfer succeeded against: {', '.join(success)} "
            f"({len(all_records)} record line(s))",
            raw={"transfers": transfers, "records": all_records},
        )
    else:
        item = _result(
            "axfr",
            " ; ".join(commands),
            "ok",
            f"AXFR denied/failed on {len(servers)} server(s)",
            raw={"transfers": transfers},
        )
    _print_status(item)
    return item


def _resolve_subdomains_dnspython(
    target: str,
    domain: str,
    port: int,
    wordlist: Path,
    threads: int,
    timeout: int,
) -> list[dict[str, str]]:
    """Resolve wordlist subdomains with dnspython only (import dns here)."""
    # Local import keeps top-level free of the `dns` package name clash risk.
    import dns.exception
    import dns.resolver

    words = [
        line.strip()
        for line in wordlist.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not words:
        return []

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [target]
    resolver.port = port
    resolver.lifetime = max(1, timeout)

    found: list[dict[str, str]] = []

    def _one(word: str) -> dict[str, str] | None:
        fqdn = f"{word}.{domain}".strip(".")
        try:
            answers = resolver.resolve(fqdn, "A")
            addrs = [rdata.to_text() for rdata in answers]
            return {"subdomain": fqdn, "type": "A", "data": ", ".join(addrs)}
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.resolver.LifetimeXDOMAIN,
        ):
            return None
        except Exception:  # noqa: BLE001 — keep pool resilient
            return None

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(_one, w): w for w in words}
        for fut in as_completed(futures):
            hit = fut.result()
            if hit:
                found.append(hit)
                console.print(f"[green]sub[/green] {hit['subdomain']} → {hit['data']}")

    return sorted(found, key=lambda r: r["subdomain"])


def _check_subdomains(
    target: str,
    domain: str,
    port: int,
    timeout: int,
    dry_run: bool,
    wordlist: str | None,
    threads: int,
) -> dict[str, Any]:
    check = "subdomains-wordlist"
    if not wordlist:
        item = _result(
            check,
            "dnspython resolve <word>.DOMAIN @TARGET",
            "skipped",
            "--wordlist not provided (no built-in list)",
        )
        _print_status(item)
        return item

    path = Path(wordlist)
    cmd_desc = (
        f"dnspython ThreadPoolExecutor(threads={threads}) "
        f"wordlist={path} → *.{domain} @{target}:{port}"
    )

    if dry_run:
        console.print(f"[cyan]\\[dry-run][/cyan] {cmd_desc}")
        item = _result(
            check,
            cmd_desc,
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "wordlist": str(path), "threads": threads},
        )
        _print_status(item)
        return item

    if not path.is_file():
        item = _result(check, cmd_desc, "fail", f"Wordlist not found: {path}")
        _print_status(item)
        return item

    try:
        found = _resolve_subdomains_dnspython(
            target, domain, port, path, threads, timeout
        )
    except ImportError as exc:
        item = _result(
            check,
            cmd_desc,
            "skipped",
            f"dnspython not installed — {exc}",
        )
        _print_status(item)
        return item

    if found:
        render_table(found, title=f"Subdomains ({domain})")
        item = _result(
            check,
            cmd_desc,
            "finding",
            f"Resolved {len(found)} subdomain(s) from wordlist",
            raw={"subdomains": found},
        )
    else:
        item = _result(
            check,
            cmd_desc,
            "ok",
            "No wordlist subdomains resolved",
            raw={"subdomains": []},
        )
    _print_status(item)
    return item


def _check_reverse(
    nameserver: str,
    port: int,
    timeout: int,
    dry_run: bool,
    cidr: str | None,
) -> dict[str, Any]:
    check = "reverse-cidr"
    if not cidr:
        item = _result(
            check,
            "dig -x <ip> @NS",
            "skipped",
            "--reverse not set",
        )
        _print_status(item)
        return item

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        item = _result(check, f"dig -x @ {cidr}", "fail", f"Invalid CIDR: {exc}")
        _print_status(item)
        return item

    hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
    # Safety cap for enumeration scope
    max_hosts = 256
    if len(hosts) > max_hosts:
        item = _result(
            check,
            f"dig -x <ip> @{nameserver} for {cidr}",
            "skipped",
            f"CIDR too large ({len(hosts)} hosts > {max_hosts}); narrow the range",
        )
        _print_status(item)
        return item

    if dry_run:
        sample = hosts[0] if hosts else network.network_address
        run_cmd(
            ["dig", f"@{nameserver}", "-p", str(port), "-x", str(sample), "+short"],
            timeout=timeout,
            dry_run=True,
        )
        item = _result(
            check,
            f"dig -x <ip> @{nameserver} for {cidr} ({len(hosts)} hosts)",
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True, "cidr": cidr, "host_count": len(hosts)},
        )
        _print_status(item)
        return item

    if not tool_available("dig"):
        item = _result(check, "dig -x", "skipped", "dig not installed — check skipped")
        _print_status(item)
        return item

    hits: list[dict[str, str]] = []
    for ip in hosts:
        cmd = ["dig", f"@{nameserver}", "-p", str(port), "-x", str(ip), "+short"]
        completed = run_cmd(cmd, timeout=timeout, dry_run=False)
        ptr = completed.stdout.strip()
        if ptr:
            hits.append({"ip": str(ip), "ptr": ptr.replace("\n", ", ")})

    if hits:
        render_table(hits, title=f"Reverse DNS ({cidr})")
        item = _result(
            check,
            f"dig -x <ip> @{nameserver} for {cidr}",
            "finding",
            f"PTR hits: {len(hits)}/{len(hosts)}",
            raw={"cidr": cidr, "hits": hits},
        )
    else:
        item = _result(
            check,
            f"dig -x <ip> @{nameserver} for {cidr}",
            "ok",
            f"No PTRs in {cidr}",
            raw={"cidr": cidr, "hits": []},
        )
    _print_status(item)
    return item


def _check_open_recursion(
    nameserver: str, port: int, timeout: int, dry_run: bool, domain: str
) -> dict[str, Any]:
    """Probe recursion with dig against an external name (not credential attacks)."""
    probe = RECURSION_PROBE_NAME
    if domain.lower().rstrip(".") == probe:
        probe = "www.google.com"

    cmd = [
        "dig",
        f"@{nameserver}",
        "-p",
        str(port),
        probe,
        "A",
        "+recurse",
        "+noall",
        "+answer",
        "+comments",
    ]

    def finding_pred(stdout: str, records: list[dict[str, str]]) -> str | None:
        has_answers = bool(records) or bool(
            re.search(r"\bNOERROR\b", stdout)
            and re.search(r"ANSWER:\s*[1-9]", stdout)
        )
        if has_answers:
            return f"Open recursion suspected (resolved {probe} via {nameserver})"
        return None

    return _run_dig(
        "open-recursion",
        cmd,
        timeout=timeout,
        dry_run=dry_run,
        finding_pred=finding_pred,
    )


def _check_nmap(
    target: str,
    domain: str,
    port: int,
    timeout: int,
    dry_run: bool,
) -> dict[str, Any]:
    check = "nmap-dns"
    script_args = f"dns-zone-transfer.domain={domain}"
    base = [
        "nmap",
        "-Pn",
        "-p",
        str(port),
        "--script",
        NMAP_SCRIPTS,
        "--script-args",
        script_args,
        target,
    ]

    if dry_run:
        # Show the privileged form the operator would run.
        cmd = ["nmap", "-sU", "-sT", *base[1:]]
        run_cmd(cmd, timeout=timeout, dry_run=True)
        item = _result(
            check,
            " ".join(cmd),
            "skipped",
            "dry-run — not executed",
            raw={"dry_run": True},
        )
        _print_status(item)
        return item

    if not tool_available("nmap"):
        require_tools(["nmap"])
        item = _result(check, "nmap …", "skipped", "nmap not installed — check skipped")
        _print_status(item)
        return item

    if check_root():
        cmd = ["nmap", "-sU", "-sT", *base[1:]]
    else:
        # TCP-only fallback when UDP scan is unavailable without root.
        console.print(
            "[yellow]No root[/yellow]: running nmap -sT only (skipping -sU)."
        )
        cmd = ["nmap", "-sT", *base[1:]]

    completed = run_cmd(cmd, timeout=timeout, dry_run=False)
    raw = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "duration": completed.duration,
    }
    stdout = completed.stdout
    findings: list[str] = []
    if re.search(r"recursion|Recursion enabled|ra: True", stdout, re.I):
        findings.append("nmap reports DNS recursion")
    if re.search(r"zone transfer|AXFR", stdout, re.I) and not re.search(
        r"failed|NOTAUTH|refused", stdout, re.I
    ):
        findings.append("nmap dns-zone-transfer indicated success")
    if re.search(r"nsid|NSID:", stdout, re.I):
        findings.append("DNS NSID disclosed")

    if findings:
        item = _result(check, cmd, "finding", "; ".join(findings), raw=raw)
    elif completed.returncode not in (0, 1) and not stdout.strip():
        item = _result(
            check, cmd, "fail", f"nmap failed (rc={completed.returncode})", raw=raw
        )
    else:
        item = _result(
            check, cmd, "ok", f"nmap completed (rc={completed.returncode})", raw=raw
        )
    if completed.stdout.strip():
        console.print(completed.stdout.rstrip())
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
    """Execute DNS enumeration against the resolved DNS server target."""
    target = _resolve_target(args)
    if not target:
        console.print(
            "[red]Target required[/red]: DNS server via positional TARGET, "
            "-t/--target, or --latest."
        )
        return 2

    dry_run = bool(args.dry_run)
    domain = args.domain
    if not domain and not dry_run:
        console.print(
            "[red]--domain is required[/red] unless --dry-run "
            "(TARGET is the DNS server, not the domain)."
        )
        return 2
    if not domain:
        domain = "example.com"
        console.print(
            f"[cyan]\\[dry-run][/cyan] --domain omitted; using placeholder `{domain}`"
        )

    nameserver = args.nameserver or target
    port: int = args.port
    timeout: int = args.timeout

    console.print(
        f"[bold]DNS enum[/bold] → server {target}:{port}, domain {domain}, "
        f"nameserver {nameserver}"
        + (" [cyan](dry-run)[/cyan]" if dry_run else "")
    )

    require_tools(["dig", "nmap"])

    checks: list[dict[str, Any]] = []
    records_item, grouped = _check_record_types(
        nameserver, domain, port, timeout, dry_run
    )
    checks.append(records_item)
    checks.append(_check_chaos_version(nameserver, port, timeout, dry_run))
    checks.append(
        _check_axfr(target, domain, nameserver, port, timeout, dry_run, grouped)
    )
    sub_item = _check_subdomains(
        target,
        domain,
        port,
        timeout,
        dry_run,
        args.wordlist,
        args.threads,
    )
    checks.append(sub_item)
    checks.append(_check_reverse(nameserver, port, timeout, dry_run, args.reverse))
    checks.append(_check_open_recursion(nameserver, port, timeout, dry_run, domain))
    checks.append(_check_nmap(target, domain, port, timeout, dry_run))

    subdomains = (sub_item.get("raw") or {}).get("subdomains") or []
    findings = [c for c in checks if c.get("status") == "finding"]

    data: dict[str, Any] = {
        "port": port,
        "timeout": timeout,
        "dry_run": dry_run,
        "domain": domain,
        "nameserver": nameserver,
        "wordlist": args.wordlist,
        "threads": args.threads,
        "reverse": args.reverse,
        "checks": checks,
        "records_by_type": grouped,
        "subdomains": subdomains,
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
        prog="dns_enum.py",
        description=(
            "DNS enumeration (dig records, CHAOS, AXFR, wordlist subs, reverse, nmap). "
            "TARGET is the DNS server. Enumeration only — no exploitation."
        ),
    )
    register_parser(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
