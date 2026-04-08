#!/usr/bin/env python3
"""VAPT Test Suite — Main Entry Point.

Usage:
    python run_vapt.py --config config.yaml              # Passive scan
    python run_vapt.py --config config.yaml --active      # Full scan
    python run_vapt.py --config config.yaml --dry-run     # Preview only
"""

import asyncio
import sys

from vapt.cli import parse_args, show_banner, confirm_scan, console
from vapt.config import load_config
from vapt.tools import ToolRegistry
from vapt.runner import VaptRunner


def main():
    args = parse_args()
    show_banner()

    # Load config (only pass config-relevant CLI overrides)
    cli_overrides = {}
    if args.target:
        cli_overrides["extra_targets"] = args.target
    if args.timeout is not None:
        cli_overrides.setdefault("settings", {})["timeout"] = args.timeout
    if args.rate_limit is not None:
        cli_overrides.setdefault("settings", {})["rate_limit"] = args.rate_limit
    if args.output_dir:
        cli_overrides.setdefault("reporting", {})["output_dir"] = args.output_dir
    if args.format:
        cli_overrides.setdefault("reporting", {})["formats"] = args.format
    try:
        config = load_config(args.config, cli_overrides if cli_overrides else None)
    except Exception as e:
        console.print(f"[bold red]Config error:[/bold red] {e}")
        sys.exit(1)

    # Check tools
    tools = ToolRegistry()
    if not args.quiet:
        console.print("[bold]Tool Detection:[/bold]")
        for line in tools.summary_lines():
            console.print(line)
        console.print()

    # Determine active scanners
    from vapt.scanners import import_all_scanners, all_scanners
    import_all_scanners()

    available = all_scanners()
    skip = set(args.skip or config.get("scanners", {}).get("skip", []))
    only = set(args.only) if args.only else None

    selected = []
    for scanner_cls in available:
        if scanner_cls.name in skip:
            continue
        if only and scanner_cls.name not in only:
            continue
        if scanner_cls.active and not args.active:
            continue
        selected.append(scanner_cls)

    scanner_names = [s.name for s in selected]
    targets = config["targets"]

    # Dry run
    if args.dry_run:
        console.print("[bold]Dry run — no tests will be executed.[/bold]")
        console.print(f"  Targets: {len(targets)}")
        console.print(f"  Scanners: {', '.join(scanner_names)}")
        console.print(f"  Active mode: {'YES' if args.active else 'NO'}")
        if not args.active:
            skipped_active = [s.name for s in available if s.active]
            if skipped_active:
                console.print(f"  [dim]Skipped (requires --active): {', '.join(skipped_active)}[/dim]")
        sys.exit(0)

    # Confirm
    if not args.quiet:
        if not confirm_scan(targets, args.active, scanner_names):
            console.print("[yellow]Scan cancelled.[/yellow]")
            sys.exit(0)

    # Run
    runner = VaptRunner(
        config=config,
        tools=tools,
        scanner_classes=selected,
        args=args,
    )
    asyncio.run(runner.run())

    # CI/CD: exit 1 if critical/high findings found
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for result in getattr(runner, 'results', {}).values():
        for f in result.get("findings", []):
            sev = (f.severity if hasattr(f, 'severity') else f.get("severity", "Info")).lower()
            if sev_rank.get(sev, 4) <= 1:
                sys.exit(1)


if __name__ == "__main__":
    main()
