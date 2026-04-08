"""OWASP ZAP integration scanner.

Connects to a running ZAP instance via its REST API to perform:
- Spider/crawl (discovers all endpoints)
- Active scan (deep injection testing with ZAP's engine)
- Imports ZAP alerts as VAPT findings

Requires:
- OWASP ZAP running in daemon mode: zap.sh -daemon -port 8080
- Python package: pip install python-owasp-zap-v2.4

If ZAP is not running, this scanner is silently skipped.
"""

from __future__ import annotations

import asyncio
import time

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding

try:
    from zapv2 import ZAPv2
    HAS_ZAP = True
except ImportError:
    HAS_ZAP = False

# ZAP alert risk → our severity + CVSS
ZAP_RISK_MAP = {
    "Informational": ("Info", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "Low":           ("Low", 3.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Medium":        ("Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "High":          ("High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
}

# ZAP CWE → OWASP Top 10 mapping (common ones)
CWE_TO_OWASP = {
    "79": "A03:2021 -- Injection",
    "89": "A03:2021 -- Injection",
    "90": "A03:2021 -- Injection",
    "78": "A03:2021 -- Injection",
    "94": "A03:2021 -- Injection",
    "611": "A03:2021 -- Injection",
    "22": "A01:2021 -- Broken Access Control",
    "284": "A01:2021 -- Broken Access Control",
    "352": "A01:2021 -- Broken Access Control",
    "614": "A02:2021 -- Cryptographic Failures",
    "319": "A02:2021 -- Cryptographic Failures",
    "326": "A02:2021 -- Cryptographic Failures",
    "16": "A05:2021 -- Security Misconfiguration",
    "200": "A05:2021 -- Security Misconfiguration",
    "693": "A05:2021 -- Security Misconfiguration",
}


@register_scanner
class ZapScanner(BaseScanner):
    """OWASP ZAP integration — spider + active scan + alert import."""

    name = "zap"
    category = "injection"  # ZAP primarily finds injection + misconfig issues
    weight = 0.0            # findings feed into existing categories
    active = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._zap: ZAPv2 | None = None
        self._zap_api_key = self.settings.get("zap_api_key", "")
        self._zap_host = self.settings.get("zap_host", "http://localhost:8080")
        self._zap_spider_timeout = self.settings.get("zap_spider_timeout", 120)
        self._zap_scan_timeout = self.settings.get("zap_scan_timeout", 300)

    async def scan(self) -> list[Finding]:
        if not HAS_ZAP:
            self.log("ZAP SDK not installed (pip install python-owasp-zap-v2.4)")
            return self.findings

        # Connect to ZAP
        try:
            self._zap = ZAPv2(
                apikey=self._zap_api_key,
                proxies={"http": self._zap_host, "https": self._zap_host},
            )
            # Test connection
            self._zap.core.version
        except Exception:
            self.log("ZAP not running — skipping. Start with: zap.sh -daemon -port 8080")
            return self.findings

        target = self.target.url

        # Run ZAP spider + active scan in a thread (ZAP SDK is synchronous)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._run_zap_scan, target)

        return self.findings

    def _run_zap_scan(self, target: str) -> None:
        """Run ZAP spider and active scan (blocking, called via executor)."""
        zap = self._zap

        # ── 1. Spider ────────────────────────────────────────────────────
        self.log(f"ZAP: Starting spider on {target}")
        scan_id = zap.spider.scan(target)

        start = time.monotonic()
        while int(zap.spider.status(scan_id)) < 100:
            if time.monotonic() - start > self._zap_spider_timeout:
                self.log("ZAP: Spider timeout, proceeding with partial results")
                zap.spider.stop(scan_id)
                break
            time.sleep(2)

        spider_results = zap.spider.results(scan_id)
        discovered_urls = len(spider_results) if spider_results else 0
        self.log(f"ZAP: Spider found {discovered_urls} URLs")

        # Store discovered URLs in context for other scanners
        if spider_results:
            self.context.setdefault("zap_discovered_urls", [])
            self.context["zap_discovered_urls"].extend(spider_results)

        # ── 2. Active Scan ───────────────────────────────────────────────
        self.log(f"ZAP: Starting active scan on {target}")
        scan_id = zap.ascan.scan(target)

        start = time.monotonic()
        while int(zap.ascan.status(scan_id)) < 100:
            if time.monotonic() - start > self._zap_scan_timeout:
                self.log("ZAP: Active scan timeout, collecting partial results")
                zap.ascan.stop(scan_id)
                break
            time.sleep(5)

        # ── 3. Collect Alerts ────────────────────────────────────────────
        alerts = zap.core.alerts(baseurl=target)
        self.log(f"ZAP: Found {len(alerts)} alerts")

        # Deduplicate by (alert name + URL)
        seen: set[str] = set()

        for alert in alerts:
            key = f"{alert.get('alert', '')}|{alert.get('url', '')}"
            if key in seen:
                continue
            seen.add(key)

            risk = alert.get("risk", "Informational")
            severity, cvss_score, cvss_vector = ZAP_RISK_MAP.get(
                risk, ("Info", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
            )

            cwe_id = alert.get("cweid", "")
            cwe_str = f"CWE-{cwe_id}" if cwe_id and cwe_id != "-1" else ""
            owasp = CWE_TO_OWASP.get(cwe_id, "")

            # Determine category from CWE
            category = "injection"
            if cwe_id in ("614", "319", "326", "295"):
                category = "ssl"
            elif cwe_id in ("16", "200", "693"):
                category = "headers"
            elif cwe_id in ("22", "284", "352", "639"):
                category = "authorization"

            self.add_finding(
                title=f"[ZAP] {alert.get('alert', 'Unknown')}",
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_id=cwe_str,
                cwe_name=alert.get("name", alert.get("alert", "")),
                owasp=owasp,
                category=category,
                url=alert.get("url", self.target.url),
                parameter=alert.get("param", ""),
                confidence="confirmed" if alert.get("confidence") == "High" else "tentative",
                description=alert.get("description", ""),
                steps_to_reproduce=[
                    f"ZAP detected this issue at: {alert.get('url', '')}",
                    f"Method: {alert.get('method', 'GET')}",
                    f"Parameter: {alert.get('param', 'N/A')}",
                    f"Attack: {alert.get('attack', 'N/A')}",
                ],
                evidence_request=f"{alert.get('method', 'GET')} {alert.get('url', '')}",
                evidence_response=alert.get("evidence", "")[:2000],
                impact=alert.get("description", ""),
                remediation=alert.get("solution", ""),
                references=[
                    ref for ref in alert.get("reference", "").split("\n") if ref.strip()
                ],
            )
