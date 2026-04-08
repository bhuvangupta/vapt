"""Reconnaissance scanner — passive information gathering."""

from __future__ import annotations

import json
import re

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding
from vapt.utils import run_command


@register_scanner
class ReconScanner(BaseScanner):
    name = "recon"
    category = "recon"
    weight = 0.03
    active = False

    async def scan(self) -> list[Finding]:
        domain = self.target.domain
        base_url = self.target.base_url

        tests = [
            self._dns_records(domain),
            self._subdomain_enumeration(domain),
            self._tech_fingerprinting(base_url),
            self._whois_lookup(domain),
            self._endpoint_discovery(base_url),
            self._google_dork_suggestions(domain),
        ]

        for coro in tests:
            try:
                await coro
            except Exception as exc:
                self.log(f"Recon test failed: {exc}")

        return self.findings

    # ------------------------------------------------------------------
    # 1. DNS Records
    # ------------------------------------------------------------------

    async def _dns_records(self, domain: str) -> None:
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA"]
        dns_results: dict[str, list[str]] = {}

        for rtype in record_types:
            rc, stdout, stderr = await run_command(
                ["dig", "+short", domain, rtype], timeout=15
            )
            records = [
                line.strip() for line in stdout.strip().splitlines() if line.strip()
            ]
            dns_results[rtype] = records

        # Store in context for other scanners
        self.context["dns_records"] = dns_results

        # Check for SPF, DKIM, DMARC in TXT records
        txt_records = dns_results.get("TXT", [])
        txt_blob = " ".join(txt_records).lower()

        missing_email_security: list[str] = []
        if "v=spf1" not in txt_blob:
            missing_email_security.append("SPF")
        if "v=dkim1" not in txt_blob:
            # DKIM is usually on a selector subdomain, but check TXT anyway
            missing_email_security.append("DKIM")

        # DMARC lives at _dmarc.<domain>
        rc, dmarc_out, _ = await run_command(
            ["dig", "+short", f"_dmarc.{domain}", "TXT"], timeout=15
        )
        if "v=dmarc1" not in dmarc_out.lower():
            missing_email_security.append("DMARC")

        if missing_email_security:
            self.add_finding(
                title=f"Missing email security records: {', '.join(missing_email_security)}",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-16",
                cwe_name="Configuration",
                owasp="A05:2021 -- Security Misconfiguration",
                url=domain,
                description=(
                    f"The domain {domain} is missing the following email security "
                    f"DNS records: {', '.join(missing_email_security)}. These records "
                    "help prevent email spoofing and phishing attacks."
                ),
                impact="Attackers may forge emails appearing to originate from this domain.",
                remediation=(
                    "Configure SPF, DKIM, and DMARC TXT records for the domain. "
                    "SPF limits which servers can send email for the domain, DKIM adds "
                    "cryptographic signatures, and DMARC defines the policy for handling "
                    "failures."
                ),
                references=[
                    "https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/",
                ],
                evidence_response="\n".join(
                    f"{rtype}: {', '.join(recs) or '(none)'}"
                    for rtype, recs in dns_results.items()
                ),
            )

    # ------------------------------------------------------------------
    # 2. Subdomain Enumeration
    # ------------------------------------------------------------------

    async def _subdomain_enumeration(self, domain: str) -> None:
        subdomains: set[str] = set()

        # crt.sh certificate transparency logs
        try:
            resp = await self.http.get(
                f"https://crt.sh/?q=%.{domain}&output=json", timeout=20
            )
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and name.endswith(domain) and "*" not in name:
                            subdomains.add(name)
        except Exception as exc:
            self.log(f"crt.sh query failed: {exc}")

        # subfinder if available
        if self.tools.available("subfinder"):
            try:
                rc, stdout, stderr = await run_command(
                    ["subfinder", "-d", domain, "-silent"], timeout=60
                )
                if rc == 0:
                    for line in stdout.strip().splitlines():
                        sub = line.strip().lower()
                        if sub:
                            subdomains.add(sub)
            except Exception as exc:
                self.log(f"subfinder failed: {exc}")

        # Store discovered subdomains in context
        self.context["subdomains"] = sorted(subdomains)

        if subdomains:
            self.add_finding(
                title=f"Discovered {len(subdomains)} subdomains via passive enumeration",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A01:2021 -- Broken Access Control",
                url=domain,
                description=(
                    f"Passive subdomain enumeration discovered {len(subdomains)} "
                    f"unique subdomains for {domain}."
                ),
                evidence_response="\n".join(sorted(subdomains)[:50]),
                impact="Subdomains may expose additional attack surface.",
                remediation=(
                    "Ensure all subdomains are inventoried and secured. "
                    "Decommission unused subdomains to reduce attack surface."
                ),
                references=["https://crt.sh/"],
            )

    # ------------------------------------------------------------------
    # 3. Tech Fingerprinting
    # ------------------------------------------------------------------

    async def _tech_fingerprinting(self, base_url: str) -> None:
        resp = await self.http.get(base_url)
        headers = resp.headers
        technologies: dict[str, str] = {}

        header_map = {
            "server": "Server",
            "x-powered-by": "X-Powered-By",
            "x-generator": "X-Generator",
            "via": "Via",
            "x-aspnet-version": "X-AspNet-Version",
        }

        for hdr_key, label in header_map.items():
            value = headers.get(hdr_key)
            if value:
                technologies[label] = value

        # Parse HTML meta tags for generator info
        html = resp.text
        meta_generators = re.findall(
            r'<meta\s+[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        for gen in meta_generators:
            technologies["Meta Generator"] = gen

        self.context["technologies"] = technologies

        # Check if Server header reveals version info (digits suggest version)
        server_header = headers.get("server", "")
        if server_header and re.search(r"\d+\.\d+", server_header):
            self.add_finding(
                title="Server header discloses software version",
                severity="Low",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=base_url,
                description=(
                    f"The Server HTTP header discloses version information: "
                    f"'{server_header}'. This helps attackers identify specific "
                    "software versions and search for known vulnerabilities."
                ),
                evidence_response=f"Server: {server_header}",
                impact=(
                    "Version disclosure allows targeted exploitation of known "
                    "vulnerabilities in the identified software version."
                ),
                remediation=(
                    "Configure the web server to suppress or genericize the Server "
                    "header. For example, in Nginx use 'server_tokens off;' and in "
                    "Apache use 'ServerTokens Prod'."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                ],
            )

        # Report X-Powered-By if present (info disclosure)
        powered_by = headers.get("x-powered-by")
        if powered_by:
            self.add_finding(
                title="X-Powered-By header discloses technology stack",
                severity="Low",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=base_url,
                description=(
                    f"The X-Powered-By header reveals: '{powered_by}'. "
                    "This information aids attackers in fingerprinting the technology stack."
                ),
                evidence_response=f"X-Powered-By: {powered_by}",
                impact="Technology disclosure enables targeted attacks.",
                remediation="Remove the X-Powered-By header from HTTP responses.",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
                ],
            )

    # ------------------------------------------------------------------
    # 4. WHOIS Lookup
    # ------------------------------------------------------------------

    async def _whois_lookup(self, domain: str) -> None:
        rc, stdout, stderr = await run_command(["whois", domain], timeout=30)
        if rc != 0 or not stdout.strip():
            self.log(f"WHOIS lookup failed: {stderr}")
            return

        whois_data: dict[str, str] = {}
        lines = stdout.splitlines()

        patterns = {
            "registrar": re.compile(r"Registrar:\s*(.+)", re.IGNORECASE),
            "creation_date": re.compile(r"Creation Date:\s*(.+)", re.IGNORECASE),
            "expiration_date": re.compile(r"(?:Registry Expiry|Expiration) Date:\s*(.+)", re.IGNORECASE),
            "updated_date": re.compile(r"Updated Date:\s*(.+)", re.IGNORECASE),
            "nameservers": re.compile(r"Name Server:\s*(.+)", re.IGNORECASE),
        }

        nameservers: list[str] = []
        for line in lines:
            for key, pattern in patterns.items():
                match = pattern.search(line)
                if match:
                    if key == "nameservers":
                        nameservers.append(match.group(1).strip())
                    else:
                        whois_data[key] = match.group(1).strip()

        if nameservers:
            whois_data["nameservers"] = ", ".join(nameservers)

        self.context["whois"] = whois_data

        # Check for WHOIS privacy
        whois_lower = stdout.lower()
        privacy_indicators = [
            "whois privacy",
            "privacy protect",
            "redacted for privacy",
            "data protected",
            "contact privacy",
            "whoisguard",
            "domains by proxy",
            "privacyguardian",
            "withheldforprivacy",
        ]
        has_privacy = any(indicator in whois_lower for indicator in privacy_indicators)

        if not has_privacy:
            self.add_finding(
                title="WHOIS privacy protection not detected",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A01:2021 -- Broken Access Control",
                url=domain,
                description=(
                    f"WHOIS records for {domain} do not appear to use privacy "
                    "protection. Registrant details (name, email, phone, address) "
                    "may be publicly visible."
                ),
                evidence_response=stdout[:2000],
                impact=(
                    "Exposed registrant information can be used for social engineering, "
                    "phishing, and targeted attacks against domain administrators."
                ),
                remediation=(
                    "Enable WHOIS privacy protection through your domain registrar "
                    "to redact personal information from public WHOIS records."
                ),
                references=[
                    "https://www.icann.org/resources/pages/thick-whois-transition-policy-2017-02-01-en",
                ],
            )

    # ------------------------------------------------------------------
    # 5. Endpoint Discovery
    # ------------------------------------------------------------------

    async def _endpoint_discovery(self, base_url: str) -> None:
        discovered_paths: list[str] = []

        # robots.txt
        try:
            resp = await self.http.get(f"{base_url}/robots.txt")
            if resp.status_code == 200 and "user-agent" in resp.text.lower():
                self.context["robots_txt"] = resp.text
                disallow_paths = re.findall(
                    r"Disallow:\s*(.+)", resp.text, re.IGNORECASE
                )
                for path in disallow_paths:
                    path = path.strip()
                    if path and path != "/":
                        discovered_paths.append(path)
        except Exception as exc:
            self.log(f"robots.txt fetch failed: {exc}")

        # sitemap.xml
        try:
            resp = await self.http.get(f"{base_url}/sitemap.xml")
            if resp.status_code == 200 and "<?xml" in resp.text[:100]:
                urls = re.findall(r"<loc>\s*(.*?)\s*</loc>", resp.text)
                self.context["sitemap_urls"] = urls
        except Exception as exc:
            self.log(f"sitemap.xml fetch failed: {exc}")

        # security.txt
        security_txt_found = False
        for path in [
            "/.well-known/security.txt",
            "/security.txt",
        ]:
            try:
                resp = await self.http.get(f"{base_url}{path}")
                if resp.status_code == 200 and "contact:" in resp.text.lower():
                    security_txt_found = True
                    self.context["security_txt"] = resp.text
                    break
            except Exception:
                pass

        if not security_txt_found:
            self.add_finding(
                title="Missing security.txt file",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-1059",
                cwe_name="Insufficient Technical Documentation",
                owasp="A05:2021 -- Security Misconfiguration",
                url=f"{base_url}/.well-known/security.txt",
                description=(
                    "No security.txt file was found at the standard location "
                    "(/.well-known/security.txt). This file helps security researchers "
                    "report vulnerabilities responsibly."
                ),
                impact=(
                    "Security researchers may not have a clear channel to report "
                    "vulnerabilities, increasing the risk of public disclosure."
                ),
                remediation=(
                    "Create a security.txt file at /.well-known/security.txt with "
                    "at least a Contact field. See RFC 9116 for the specification."
                ),
                references=[
                    "https://securitytxt.org/",
                    "https://www.rfc-editor.org/rfc/rfc9116",
                ],
            )

        if discovered_paths:
            self.context["discovered_paths"] = discovered_paths

    # ------------------------------------------------------------------
    # 6. Google Dork Suggestions
    # ------------------------------------------------------------------

    async def _google_dork_suggestions(self, domain: str) -> None:
        dorks = [
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:doc OR filetype:docx OR filetype:xls',
            f'site:{domain} filetype:sql OR filetype:bak OR filetype:log',
            f'site:{domain} filetype:env OR filetype:config OR filetype:yml',
            f'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
            f'site:{domain} inurl:api OR inurl:v1 OR inurl:v2',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} ext:php intitle:phpinfo',
            f'site:{domain} inurl:wp-content OR inurl:wp-admin',
            f'site:{domain} "error" OR "warning" OR "fatal" filetype:log',
            f'site:{domain} "password" OR "secret" OR "api_key" filetype:env',
            f'site:{domain} inurl:".git"',
            f'"{domain}" password OR credentials OR leak',
        ]

        self.context["google_dorks"] = dorks
