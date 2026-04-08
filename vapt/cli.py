"""CLI argument parsing and configuration."""

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """
╦  ╦╔═╗╔═╗╔╦╗  ╔═╗╦ ╦╦╔╦╗╔═╗
╚╗╔╝╠═╣╠═╝ ║   ╚═╗║ ║║ ║ ║╣
 ╚╝ ╩ ╩╩   ╩   ╚═╝╚═╝╩ ╩ ╚═╝
  Vulnerability Assessment & Penetration Testing
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vapt",
        description="VAPT Test Suite — Standalone Security Scanner",
    )
    parser.add_argument(
        "--config", "-c", required=True,
        help="Path to YAML config file",
    )
    parser.add_argument(
        "--target", "-t", action="append", default=[],
        help="Override/add target URL (repeatable)",
    )
    parser.add_argument(
        "--active", action="store_true",
        help="Enable active/dangerous tests (injection, brute force)",
    )
    parser.add_argument(
        "--skip", type=lambda s: [x.strip() for x in s.split(",") if x.strip()], default=[],
        help="Comma-separated scanner categories to skip",
    )
    parser.add_argument(
        "--only", type=lambda s: [x.strip() for x in s.split(",") if x.strip()], default=[],
        help="Run only these scanner categories",
    )
    parser.add_argument(
        "--severity", choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity to report (default: info)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        help="Override report output directory",
    )
    parser.add_argument(
        "--format", "-f", type=lambda s: s.split(","), default=None,
        help="Output formats: html,pdf (comma-separated)",
    )
    parser.add_argument(
        "--timeout", type=int, default=None,
        help="Per-request timeout in seconds",
    )
    parser.add_argument(
        "--rate-limit", type=float, default=None,
        help="Requests per second per target",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output during scanning",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Only show findings and final score",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be tested without executing",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s 1.0.0",
    )
    return parser.parse_args(argv)


def show_banner():
    console.print(Panel(Text(BANNER, style="bold cyan"), border_style="blue"))


def confirm_scan(targets: list, active: bool, scanners: list[str]) -> bool:
    """Ask user to confirm before scanning."""
    mode = "[bold red]ACTIVE[/bold red] (injection, brute force enabled)" if active else "[bold green]PASSIVE[/bold green] (safe, no payloads)"

    console.print()
    console.print(f"  [bold]Targets:[/bold]   {len(targets)}")
    for t in targets:
        name = getattr(t, 'name', '') or getattr(t, 'url', str(t))
        url = getattr(t, 'url', str(t))
        console.print(f"               • {name} ({url})")
    console.print(f"  [bold]Mode:[/bold]      {mode}")
    console.print(f"  [bold]Scanners:[/bold]  {len(scanners)} ({', '.join(scanners)})")
    console.print()

    try:
        answer = console.input("  [bold yellow]Proceed with scan? [Y/n]:[/bold yellow] ").strip().lower()
        return answer in ("", "y", "yes")
    except (KeyboardInterrupt, EOFError):
        return False
