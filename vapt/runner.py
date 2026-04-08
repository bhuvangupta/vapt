"""Wave-based VAPT orchestration engine."""

import asyncio
import os
import time
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table as RichTable
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from vapt.config import load_config
from vapt.models.finding import Finding
from vapt.models.target import TargetConfig
from vapt.scoring.posture import calculate_posture_score
from vapt.tools import ToolRegistry
from vapt.utils import AsyncHttpClient
from vapt.scanners.base import BaseScanner


console = Console()


class VaptRunner:
    def __init__(self, config: dict, tools: ToolRegistry, scanner_classes: list, args):
        self.config = config
        self.tools = tools
        self.scanner_classes = scanner_classes
        self.args = args
        self.settings = config.get("settings", {})
        self.results = {}

    async def run(self):
        """Run the full VAPT suite against all targets."""
        targets = self.config["targets"]
        all_results = {}

        for i, target in enumerate(targets, 1):
            console.print(f"\n[bold]Target {i}/{len(targets)}: {target.name or target.url}[/bold]")
            console.print("=" * 60)

            results = await self._scan_target(target)
            all_results[target.url] = results

        self.results = all_results

        # Generate reports for each target
        for target in targets:
            results = all_results.get(target.url, {})
            findings = results.get("findings", [])
            scanner_results = results.get("scanner_results", [])

            posture = calculate_posture_score(findings)

            self._print_summary(target, posture, findings)
            await self._generate_reports(target, findings, posture, scanner_results)

    async def _scan_target(self, target: TargetConfig) -> dict:
        """Execute wave-based scanning against a single target."""
        findings = []
        scanner_results = []
        context = {}

        # Organize scanners into waves
        wave1 = []  # Recon: recon, ssl_tls, headers
        wave2 = []  # Scanning: network, webapp
        wave3 = []  # Testing: injection, auth, authz, api, logic, cloud, websocket, graphql

        wave1_names = {"recon", "ssl_tls", "headers"}
        wave2_names = {"network", "webapp"}

        for cls in self.scanner_classes:
            if cls.name in wave1_names:
                wave1.append(cls)
            elif cls.name in wave2_names:
                wave2.append(cls)
            else:
                wave3.append(cls)

        # Wave 1 — Reconnaissance
        if wave1:
            console.print("\n [bold cyan]Wave 1 — Reconnaissance[/bold cyan]")
            w1_findings, w1_results = await self._run_wave(wave1, target, context)
            findings.extend(w1_findings)
            scanner_results.extend(w1_results)

        # Wave 2 — Scanning
        if wave2:
            console.print("\n [bold cyan]Wave 2 — Scanning[/bold cyan]")
            w2_findings, w2_results = await self._run_wave(wave2, target, context)
            findings.extend(w2_findings)
            scanner_results.extend(w2_results)

        # Wave 3 — Testing
        if wave3:
            console.print("\n [bold cyan]Wave 3 — Testing[/bold cyan]")
            w3_findings, w3_results = await self._run_wave(wave3, target, context)
            findings.extend(w3_findings)
            scanner_results.extend(w3_results)

        # Re-number findings globally to avoid ID collisions across scanners
        for i, finding in enumerate(findings, 1):
            finding.id = f"FINDING-{i:03d}"

        return {"findings": findings, "scanner_results": scanner_results}

    def _http_kwargs(self, target: TargetConfig) -> dict:
        """Common kwargs for per-scanner HTTP clients."""
        return dict(
            timeout=self.settings.get("timeout", 10),
            rate_limit=self.settings.get("rate_limit", 2.0),
            user_agent=self.settings.get("user_agent", "VAPT-Scanner/1.0"),
            follow_redirects=self.settings.get("follow_redirects", True),
            target=target,
        )

    async def _run_wave(self, scanner_classes: list, target: TargetConfig, context: dict):
        """Run a wave of scanners in parallel.

        Each scanner gets its own HTTP client so cookie jars / auth state
        cannot bleed between parallel scanners (e.g. AuthScanner logging in
        should not cause AuthzScanner's forced-browsing tests to silently
        become authenticated).
        """
        findings = []
        results = []

        tasks = []
        clients: list[AsyncHttpClient] = []
        for cls in scanner_classes:
            client = AsyncHttpClient(**self._http_kwargs(target))
            await client.__aenter__()
            clients.append(client)
            scanner = cls(target, client, self.tools, self.settings, context)
            tasks.append(self._run_scanner(scanner))

        try:
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for client in clients:
                await client.__aexit__(None, None, None)

            for cls, result in zip(scanner_classes, results_list):
                if isinstance(result, Exception):
                    console.print(f"  [red]✗ {cls.name}: {result}[/red]")
                    results.append({"name": cls.name, "findings_count": 0, "duration": 0, "error": str(result)})
                else:
                    scanner_findings, duration = result
                    findings.extend(scanner_findings)
                    # Merge scanner context
                    if hasattr(scanner_classes, '__iter__'):
                        pass  # context already merged in _run_scanner

                    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
                    for f in scanner_findings:
                        sev = f.severity if hasattr(f, 'severity') else f.get("severity", "Info")
                        counts[sev] = counts.get(sev, 0) + 1

                    count_str = " ".join(
                        f"{v}{k[0]}" for k, v in counts.items() if v > 0
                    ) or "clean"

                    console.print(
                        f"  [green]✓[/green] {cls.name:.<20s} "
                        f"{len(scanner_findings)} findings ({count_str}) [{duration:.1f}s]"
                    )
                    results.append({
                        "name": cls.name,
                        "findings_count": len(scanner_findings),
                        "duration": duration,
                    })

        return findings, results

    async def _run_scanner(self, scanner: BaseScanner) -> tuple:
        """Run a single scanner, return (findings, duration)."""
        start = time.monotonic()
        try:
            scanner_findings = await scanner.scan()
            duration = time.monotonic() - start
            # Merge context from scanner back to shared context
            if hasattr(scanner, 'context') and scanner.context:
                # scanner.context is shared by reference, so updates propagate
                pass
            return (scanner_findings, duration)
        except Exception as e:
            duration = time.monotonic() - start
            raise

    def _print_summary(self, target: TargetConfig, posture, findings):
        """Print summary to terminal."""
        console.print(f"\n[bold]Results for {target.name or target.url}[/bold]")
        console.print("─" * 60)

        # Score with color
        score = posture.overall_score
        if score >= 70:
            color = "green"
        elif score >= 50:
            color = "yellow"
        elif score >= 30:
            color = "red"
        else:
            color = "bold red"

        console.print(f"  Security Posture Score: [{color}]{score}/100 ({posture.rating})[/{color}]")
        console.print(f"  Total Findings: {posture.total_findings}")

        # Severity breakdown
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.severity if hasattr(f, 'severity') else f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        sev_parts = []
        sev_colors = {"Critical": "red", "High": "dark_orange", "Medium": "yellow", "Low": "blue", "Info": "dim"}
        for sev, count in counts.items():
            if count > 0:
                c = sev_colors[sev]
                sev_parts.append(f"[{c}]{count} {sev}[/{c}]")
        if sev_parts:
            console.print(f"  Breakdown: {', '.join(sev_parts)}")

        # Category scores table
        table = RichTable(title="Category Scores", show_lines=False)
        table.add_column("Category", style="bold")
        table.add_column("Weight", justify="center")
        table.add_column("Score", justify="center")

        for cat in posture.categories:
            score_style = "green" if cat.raw_score >= 70 else "yellow" if cat.raw_score >= 50 else "red"
            table.add_row(cat.name, f"{cat.weight:.0%}", f"[{score_style}]{cat.raw_score:.0f}/100[/{score_style}]")

        console.print(table)

    async def _generate_reports(self, target, findings, posture, scanner_results):
        """Generate report files."""
        formats = self.config.get("reporting", {}).get("formats", ["html", "pdf"])
        output_dir = self.config.get("reporting", {}).get("output_dir", "./reports")

        # Sanitize target for directory name
        safe_name = target.domain.replace(".", "-")
        date_str = datetime.now().strftime("%Y%m%d")
        report_dir = os.path.join(output_dir, f"VAPT-{safe_name}-{date_str}")
        os.makedirs(report_dir, exist_ok=True)

        authorization = self.config.get("authorization", {})
        tools_used = [t.name for t in self.tools.report().get("core", []) if t.available]
        tools_used += [t.name for t in self.tools.report().get("recommended", []) if t.available]

        finding_dicts = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]

        if "html" in formats:
            from vapt.reports.html_report import generate_html_report, export_findings_json
            html_path = os.path.join(report_dir, "report.html")
            generate_html_report(
                findings=findings, posture_score=posture,
                target_name=target.name or target.url,
                target_url=target.url, authorization=authorization,
                tools_used=tools_used, scanner_results=scanner_results,
                active_mode=self.args.active, output_path=html_path,
            )
            console.print(f"  [green]✓[/green] HTML report: {html_path}")

            # Always export JSON alongside
            json_path = os.path.join(report_dir, "findings.json")
            export_findings_json(findings, posture, json_path)
            console.print(f"  [green]✓[/green] JSON export: {json_path}")

        if "pdf" in formats:
            from vapt.reports.pdf_report import generate_pdf_report, HAS_REPORTLAB
            if HAS_REPORTLAB:
                pdf_path = os.path.join(report_dir, "report.pdf")
                generate_pdf_report(
                    findings=findings, posture_score=posture,
                    target_name=target.name or target.url,
                    target_url=target.url, authorization=authorization,
                    tools_used=tools_used, scanner_results=scanner_results,
                    active_mode=self.args.active, output_path=pdf_path,
                )
                console.print(f"  [green]✓[/green] PDF report:  {pdf_path}")
            else:
                console.print("  [yellow]⚠ PDF skipped (install reportlab: pip install reportlab)[/yellow]")

        console.print(f"\n  [bold]Reports saved to: {report_dir}/[/bold]")
