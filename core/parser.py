#!/usr/bin/env python3
"""Report persistence, rich tables, and nmap XML helpers."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from rich.console import Console
from rich.table import Table

console = Console()

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"

_UNSAFE_CHARS = re.compile(r"[^\w.\-]+", re.UNICODE)


def _safe_token(value: str) -> str:
    cleaned = _UNSAFE_CHARS.sub("_", value.strip()).strip("._-")
    return cleaned or "unknown"


def _ensure_reports_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _data_to_markdown(module: str, target: str, data: Mapping[str, Any], stamp: str) -> str:
    lines = [
        f"# Report: `{module}`",
        "",
        f"- **target:** `{target}`",
        f"- **timestamp:** `{stamp}`",
        "",
        "## Data",
        "",
        "```json",
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        "```",
        "",
    ]
    return "\n".join(lines)


def save_report(module: str, target: str, data: Mapping[str, Any]) -> Path:
    """Write ``reports/<module>_<target>_<timestamp>.json`` and matching ``.md``.

    Returns the path to the JSON report.
    """
    reports = _ensure_reports_dir()
    stamp = _timestamp()
    stem = f"{_safe_token(module)}_{_safe_token(target)}_{stamp}"
    json_path = reports / f"{stem}.json"
    md_path = reports / f"{stem}.md"

    payload = {
        "module": module,
        "target": target,
        "timestamp": stamp,
        "data": data,
    }
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(
        _data_to_markdown(module, target, data, stamp),
        encoding="utf-8",
    )
    console.print(f"[green]Saved report[/green]: {json_path.relative_to(REPO_ROOT)}")
    return json_path


def load_latest(module: str | None = None) -> dict[str, Any] | None:
    """Load the newest JSON report, optionally filtered by *module*.

    Used by ``--latest`` to chain modules (e.g. open ports from discovery).
    Returns ``None`` when no matching report exists.
    """
    reports = _ensure_reports_dir()
    pattern = f"{_safe_token(module)}_*.json" if module else "*.json"
    candidates = sorted(
        reports.glob(pattern),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        console.print(
            "[yellow]No reports found[/yellow]"
            + (f" for module `{module}`" if module else "")
            + "."
        )
        return None

    path = candidates[0]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]Failed to load[/red] {path.name}: {exc}")
        return None

    if not isinstance(payload, dict):
        console.print(f"[red]Invalid report format[/red]: {path.name}")
        return None

    console.print(f"[green]Loaded latest[/green]: {path.relative_to(REPO_ROOT)}")
    return payload


def render_table(
    results: Sequence[Mapping[str, Any]] | Iterable[Mapping[str, Any]],
    *,
    title: str | None = None,
) -> None:
    """Render *results* as a rich table (keys of the first row = columns)."""
    rows = list(results)
    if not rows:
        console.print("[dim]No results to display.[/dim]")
        return

    columns = list(rows[0].keys())
    table = Table(title=title, show_header=True, header_style="bold")
    for col in columns:
        table.add_column(str(col))

    for row in rows:
        table.add_row(*(str(row.get(col, "")) for col in columns))

    console.print(table)


def extract_open_ports(nmap_xml: str | Path) -> list[dict[str, Any]]:
    """Parse nmap XML and return open ports for module chaining.

    Each item: ``{"host", "port", "protocol", "service", "product", "version"}``.
    """
    if isinstance(nmap_xml, Path) or (
        isinstance(nmap_xml, str) and Path(nmap_xml).is_file()
    ):
        text = Path(nmap_xml).read_text(encoding="utf-8", errors="replace")
    else:
        text = str(nmap_xml)

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        console.print(f"[red]Invalid nmap XML[/red]: {exc}")
        return []

    open_ports: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        host_addr = addr_el.get("addr") if addr_el is not None else "unknown"

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            open_ports.append(
                {
                    "host": host_addr,
                    "port": int(port_el.get("portid", "0")),
                    "protocol": port_el.get("protocol", ""),
                    "service": (service_el.get("name") if service_el is not None else "")
                    or "",
                    "product": (service_el.get("product") if service_el is not None else "")
                    or "",
                    "version": (service_el.get("version") if service_el is not None else "")
                    or "",
                }
            )

    return open_ports
