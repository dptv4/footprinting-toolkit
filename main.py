#!/usr/bin/env python3
"""Unified entrypoint: discover modules/*_enum.py and dispatch via subparsers."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from rich.console import Console

console = Console(stderr=True)

ROOT = Path(__file__).resolve().parent
MODULES_DIR = ROOT / "modules"


def _load_module(path: Path) -> ModuleType:
    """Import a module file from *path* under a stable package-like name."""
    mod_name = f"modules.{path.stem}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


def discover_modules() -> dict[str, ModuleType]:
    """Map CLI subcommand name → loaded module (``ftp`` → ``ftp_enum.py``)."""
    found: dict[str, ModuleType] = {}
    if not MODULES_DIR.is_dir():
        return found

    for path in sorted(MODULES_DIR.glob("*_enum.py")):
        cmd = path.stem.removesuffix("_enum")
        try:
            module = _load_module(path)
        except Exception as exc:  # noqa: BLE001 — discovery must not crash the CLI
            console.print(f"[yellow]Skipping[/yellow] {path.name}: {exc}")
            continue

        if not callable(getattr(module, "register_parser", None)):
            console.print(
                f"[yellow]Skipping[/yellow] {path.name}: missing register_parser()"
            )
            continue
        if not callable(getattr(module, "run", None)):
            console.print(f"[yellow]Skipping[/yellow] {path.name}: missing run()")
            continue

        found[cmd] = module

    return found


def build_parser(modules: dict[str, ModuleType]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "footprinting-toolkit — authorized enumeration only. "
            "Modules are auto-discovered from modules/*_enum.py."
        ),
    )
    subparsers = parser.add_subparsers(
        dest="module",
        required=True,
        metavar="MODULE",
        help="enumeration module (e.g. ftp)",
    )

    for name, module in modules.items():
        doc = (module.__doc__ or f"{name} enumeration").strip().splitlines()[0]
        sub = subparsers.add_parser(name, help=doc, description=doc)
        module.register_parser(sub)
        sub.set_defaults(_module_run=module.run)

    return parser


def main(argv: list[str] | None = None) -> int:
    modules = discover_modules()
    if not modules:
        console.print("[red]No modules found[/red] in modules/*_enum.py")
        return 1

    parser = build_parser(modules)
    args = parser.parse_args(argv)
    run = getattr(args, "_module_run", None)
    if not callable(run):
        parser.error("internal error: no run() bound for this module")
    return int(run(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
