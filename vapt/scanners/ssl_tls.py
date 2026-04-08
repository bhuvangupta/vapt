"""SSL/TLS scanner — certificate and protocol analysis."""

from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding
from vapt.utils import run_command


@register_scanner
class SSLScanner(BaseScanner):
    name = "ssl_tls"
    category = "ssl"
    weight = 0.10
    active = False

    async def scan(self) -> list[Finding]:
        domain = self.target.domain
        base_url = self.target.base_url

        tests = [
            self._certificate_analysis(domain),
            self._protocol_version_testing(domain),
            self._hsts_analysis(base_url),
            self._mixed_content(base_url),
            self._certificate_transparency(domain),
            self._cipher_suite_analysis(domain),
        ]

        for coro in tests:
            try:
                await coro
            except Exception as exc:
                self.log(f"SSL/TLS test failed: {exc}")

        return self.findings

    # ------------------------------------------------------------------
    # 1. Certificate Analysis
    # ------------------------------------------------------------------

    async def _certificate_analysis(self, domain: str) -> None:
        safe_domain = shlex.quote(domain)
        # Fetch certificate text via openssl s_client piped to x509
        rc, stdout, stderr = await run_command(
            [
                "bash", "-c",
                f"echo | openssl s_client -connect {safe_domain}:443 -servername {safe_domain} "
                f"2>/dev/null | openssl x509 -noout -text 2>/dev/null",
            ],
            timeout=30,
        )

        if rc != 0 or not stdout.strip():
            self.log(f"Certificate retrieval failed for {domain}: {stderr}")
            return

        cert_text = stdout
        self.context["certificate_text"] = cert_text

        # Extract issuer
        issuer_match = re.search(r"Issuer:\s*(.+)", cert_text)
        issuer = issuer_match.group(1).strip() if issuer_match else "Unknown"

        # Extract subject
        subject_match = re.search(r"Subject:\s*(.+)", cert_text)
        subject = subject_match.group(1).strip() if subject_match else "Unknown"

        # Extract SAN
        san_match = re.search(
            r"X509v3 Subject Alternative Name:\s*\n\s*(.+)", cert_text
        )
        san = san_match.group(1).strip() if san_match else ""

        # Extract validity dates
        not_before_match = re.search(r"Not Before:\s*(.+)", cert_text)
        not_after_match = re.search(r"Not After\s*:\s*(.+)", cert_text)

        not_before = not_before_match.group(1).strip() if not_before_match else ""
        not_after = not_after_match.group(1).strip() if not_after_match else ""

        # Extract key size
        key_size_match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", cert_text)
        key_size = int(key_size_match.group(1)) if key_size_match else 0

        # Extract signature algorithm
        sig_algo_match = re.search(r"Signature Algorithm:\s*(\S+)", cert_text)
        sig_algo = sig_algo_match.group(1) if sig_algo_match else "Unknown"

        # Store parsed cert info in context
        self.context["certificate_info"] = {
            "issuer": issuer,
            "subject": subject,
            "san": san,
            "not_before": not_before,
            "not_after": not_after,
            "key_size": key_size,
            "signature_algorithm": sig_algo,
        }

        cert_evidence = (
            f"Issuer: {issuer}\n"
            f"Subject: {subject}\n"
            f"SAN: {san}\n"
            f"Not Before: {not_before}\n"
            f"Not After: {not_after}\n"
            f"Key Size: {key_size} bits\n"
            f"Signature Algorithm: {sig_algo}"
        )

        # Check expiration
        if not_after:
            try:
                # openssl dates are like "Jan  1 00:00:00 2025 GMT"
                # Strip timezone name (always GMT from openssl) for cross-platform parsing
                date_str = re.sub(r'\s*(GMT|UTC)\s*$', '', not_after).strip()
                date_str = re.sub(r'\s+', ' ', date_str)
                expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_remaining = (expiry - now).days

                if days_remaining < 0:
                    self.add_finding(
                        title="SSL certificate has expired",
                        severity="Critical",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-295",
                        cwe_name="Improper Certificate Validation",
                        owasp="A02:2021 -- Cryptographic Failures",
                        url=f"https://{domain}",
                        description=(
                            f"The SSL certificate for {domain} expired "
                            f"{abs(days_remaining)} days ago on {not_after}. "
                            "Browsers will display security warnings and users may "
                            "be vulnerable to man-in-the-middle attacks."
                        ),
                        evidence_response=cert_evidence,
                        impact=(
                            "Expired certificates break trust and may lead users to "
                            "bypass security warnings. MITM attacks become trivial."
                        ),
                        remediation="Renew the SSL certificate immediately.",
                        references=[
                            "https://letsencrypt.org/",
                        ],
                    )
                elif days_remaining <= 30:
                    self.add_finding(
                        title=f"SSL certificate expires in {days_remaining} days",
                        severity="Medium",
                        cvss_score=5.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
                        cwe_id="CWE-295",
                        cwe_name="Improper Certificate Validation",
                        owasp="A02:2021 -- Cryptographic Failures",
                        url=f"https://{domain}",
                        description=(
                            f"The SSL certificate for {domain} expires on {not_after} "
                            f"({days_remaining} days remaining). Renew it before "
                            "expiration to avoid service disruption."
                        ),
                        evidence_response=cert_evidence,
                        impact="Certificate expiry will cause browser warnings and potential downtime.",
                        remediation="Renew the SSL certificate before expiration. Consider auto-renewal.",
                        references=[
                            "https://letsencrypt.org/docs/",
                        ],
                    )
            except ValueError:
                self.log(f"Could not parse certificate expiry date: {not_after}")

        # Check for self-signed certificate
        if issuer and subject:
            # Self-signed: issuer CN matches subject CN
            issuer_cn_match = re.search(r"CN\s*=\s*([^,/]+)", issuer)
            subject_cn_match = re.search(r"CN\s*=\s*([^,/]+)", subject)
            if issuer_cn_match and subject_cn_match:
                if issuer_cn_match.group(1).strip() == subject_cn_match.group(1).strip():
                    self.add_finding(
                        title="Self-signed SSL certificate detected",
                        severity="High",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-295",
                        cwe_name="Improper Certificate Validation",
                        owasp="A02:2021 -- Cryptographic Failures",
                        url=f"https://{domain}",
                        description=(
                            f"The SSL certificate for {domain} appears to be self-signed "
                            f"(issuer CN matches subject CN: '{subject_cn_match.group(1).strip()}'). "
                            "Self-signed certificates are not trusted by browsers and "
                            "provide no authentication guarantee."
                        ),
                        evidence_response=cert_evidence,
                        impact=(
                            "Self-signed certificates do not verify server identity, "
                            "making MITM attacks possible without detection."
                        ),
                        remediation=(
                            "Replace the self-signed certificate with one issued by a "
                            "trusted Certificate Authority. Let's Encrypt provides free "
                            "certificates."
                        ),
                        references=[
                            "https://letsencrypt.org/",
                        ],
                    )

        # Check for weak key size
        if key_size and key_size < 2048:
            self.add_finding(
                title=f"Weak SSL certificate key size ({key_size} bits)",
                severity="Medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-326",
                cwe_name="Inadequate Encryption Strength",
                owasp="A02:2021 -- Cryptographic Failures",
                url=f"https://{domain}",
                description=(
                    f"The SSL certificate for {domain} uses a {key_size}-bit key, "
                    "which is below the recommended minimum of 2048 bits. "
                    "Short keys are vulnerable to factoring attacks."
                ),
                evidence_response=cert_evidence,
                impact="Weak keys can be brute-forced, compromising all encrypted communications.",
                remediation="Regenerate the certificate with at least a 2048-bit RSA key or 256-bit ECC key.",
                references=[
                    "https://www.keylength.com/",
                ],
            )

    # ------------------------------------------------------------------
    # 2. Protocol Version Testing
    # ------------------------------------------------------------------

    async def _protocol_version_testing(self, domain: str) -> None:
        safe_domain = shlex.quote(domain)
        protocols = {
            "-ssl3": ("SSLv3", "High", 7.4, "CWE-326", "Inadequate Encryption Strength",
                      "SSLv3 is vulnerable to the POODLE attack and must be disabled."),
            "-tls1": ("TLS 1.0", "Medium", 5.9, "CWE-326", "Inadequate Encryption Strength",
                      "TLS 1.0 is deprecated (RFC 8996) and has known vulnerabilities including BEAST."),
            "-tls1_1": ("TLS 1.1", "Medium", 5.3, "CWE-326", "Inadequate Encryption Strength",
                        "TLS 1.1 is deprecated (RFC 8996) and should be disabled."),
            "-tls1_2": ("TLS 1.2", None, 0, None, None,
                        "TLS 1.2 is currently acceptable when configured with strong cipher suites."),
            "-tls1_3": ("TLS 1.3", None, 0, None, None,
                        "TLS 1.3 is the latest version with improved security and performance."),
        }

        protocol_results: dict[str, bool] = {}

        for flag, (name, *_) in protocols.items():
            rc, stdout, stderr = await run_command(
                [
                    "bash", "-c",
                    f"echo | openssl s_client -connect {safe_domain}:443 "
                    f"-servername {safe_domain} {flag} 2>&1",
                ],
                timeout=15,
            )
            # Connection successful if we see "Protocol  : TLS" or no handshake error
            combined = stdout + stderr
            connected = (
                "CONNECTED" in combined
                and "handshake failure" not in combined.lower()
                and "no protocols available" not in combined.lower()
                and "wrong ssl version" not in combined.lower()
                and "alert protocol version" not in combined.lower()
                and "ssl routines" not in combined.lower()
                and "errno" not in combined.lower()
            )
            protocol_results[name] = connected

        self.context["ssl_protocols"] = protocol_results

        # Generate findings for deprecated protocols that are enabled
        for flag, (name, severity, cvss, cwe_id, cwe_name, desc) in protocols.items():
            enabled = protocol_results.get(name, False)

            if name in ("SSLv3", "TLS 1.0", "TLS 1.1") and enabled and severity:
                self.add_finding(
                    title=f"Deprecated protocol {name} is enabled",
                    severity=severity,
                    cvss_score=cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    owasp="A02:2021 -- Cryptographic Failures",
                    url=f"https://{domain}",
                    description=(
                        f"{name} is enabled on {domain}. {desc} "
                        "Attackers can exploit known weaknesses in deprecated "
                        "protocols to decrypt or tamper with traffic."
                    ),
                    evidence_response=f"Protocol {name} ({flag}): Accepted",
                    impact=f"Connections using {name} are vulnerable to known cryptographic attacks.",
                    remediation=f"Disable {name} on the server and enforce TLS 1.2+ only.",
                    references=[
                        "https://www.rfc-editor.org/rfc/rfc8996",
                        "https://ssl-config.mozilla.org/",
                    ],
                )

        # TLS 1.2 not supported
        if not protocol_results.get("TLS 1.2", False):
            self.add_finding(
                title="TLS 1.2 is not supported",
                severity="Medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-326",
                cwe_name="Inadequate Encryption Strength",
                owasp="A02:2021 -- Cryptographic Failures",
                url=f"https://{domain}",
                description=(
                    f"TLS 1.2 is not supported by {domain}. TLS 1.2 is still the "
                    "most widely used secure protocol version and should be supported "
                    "for compatibility."
                ),
                evidence_response="Protocol TLS 1.2 (-tls1_2): Not accepted",
                impact="Lack of TLS 1.2 support may cause compatibility issues with older clients.",
                remediation="Enable TLS 1.2 alongside TLS 1.3.",
                references=[
                    "https://ssl-config.mozilla.org/",
                ],
            )

        # TLS 1.3 not supported (best practice)
        if not protocol_results.get("TLS 1.3", False):
            self.add_finding(
                title="TLS 1.3 is not supported",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-326",
                cwe_name="Inadequate Encryption Strength",
                owasp="A02:2021 -- Cryptographic Failures",
                url=f"https://{domain}",
                description=(
                    f"TLS 1.3 is not supported by {domain}. TLS 1.3 provides "
                    "improved security (no legacy cipher suites, mandatory forward "
                    "secrecy) and performance (reduced handshake latency)."
                ),
                evidence_response="Protocol TLS 1.3 (-tls1_3): Not accepted",
                impact="Missing TLS 1.3 means users do not benefit from the latest security and performance improvements.",
                remediation="Enable TLS 1.3 on the server for improved security.",
                references=[
                    "https://www.rfc-editor.org/rfc/rfc8446",
                    "https://ssl-config.mozilla.org/",
                ],
            )

    # ------------------------------------------------------------------
    # 3. HSTS Analysis
    # ------------------------------------------------------------------

    async def _hsts_analysis(self, base_url: str) -> None:
        resp = await self.http.get(base_url)
        hsts_header = resp.headers.get("strict-transport-security", "")

        if not hsts_header:
            self.add_finding(
                title="HTTP Strict Transport Security (HSTS) header missing",
                severity="Medium",
                cvss_score=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp="A02:2021 -- Cryptographic Failures",
                url=base_url,
                description=(
                    "The Strict-Transport-Security header is not set. Without HSTS, "
                    "browsers may allow insecure HTTP connections, making users "
                    "vulnerable to SSL stripping attacks."
                ),
                evidence_response="Strict-Transport-Security: (not present)",
                impact=(
                    "Users may be downgraded to insecure HTTP connections via "
                    "SSL stripping, exposing credentials and session tokens."
                ),
                remediation=(
                    "Add the Strict-Transport-Security header with a max-age of at "
                    "least one year (31536000 seconds), includeSubDomains, and preload: "
                    "'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://hstspreload.org/",
                ],
            )
            return

        hsts_lower = hsts_header.lower()

        # Parse max-age
        max_age_match = re.search(r"max-age=(\d+)", hsts_lower)
        max_age = int(max_age_match.group(1)) if max_age_match else 0

        if max_age < 31536000:
            self.add_finding(
                title=f"HSTS max-age is too low ({max_age} seconds)",
                severity="Low",
                cvss_score=3.5,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp="A02:2021 -- Cryptographic Failures",
                url=base_url,
                description=(
                    f"The HSTS max-age is set to {max_age} seconds, which is below "
                    "the recommended minimum of 31536000 seconds (one year). A short "
                    "max-age reduces the effectiveness of HSTS protection."
                ),
                evidence_response=f"Strict-Transport-Security: {hsts_header}",
                impact="Short HSTS duration leaves a wider window for SSL stripping attacks.",
                remediation="Increase max-age to at least 31536000 (one year).",
                references=[
                    "https://hstspreload.org/",
                ],
            )

        if "includesubdomains" not in hsts_lower:
            self.add_finding(
                title="HSTS missing includeSubDomains directive",
                severity="Low",
                cvss_score=2.5,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp="A02:2021 -- Cryptographic Failures",
                url=base_url,
                description=(
                    "The HSTS header does not include the 'includeSubDomains' "
                    "directive. Subdomains can still be accessed over insecure HTTP."
                ),
                evidence_response=f"Strict-Transport-Security: {hsts_header}",
                impact="Subdomains remain vulnerable to SSL stripping attacks.",
                remediation="Add 'includeSubDomains' to the HSTS header.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                ],
            )

        self.context["hsts_checked"] = True

        if "preload" not in hsts_lower:
            self.add_finding(
                title="HSTS missing preload directive",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp="A02:2021 -- Cryptographic Failures",
                url=base_url,
                description=(
                    "The HSTS header does not include the 'preload' directive. "
                    "Without preloading, the browser must visit the site at least once "
                    "before HSTS takes effect."
                ),
                evidence_response=f"Strict-Transport-Security: {hsts_header}",
                impact="First-visit users are not protected by HSTS until the header is received.",
                remediation=(
                    "Add 'preload' to the HSTS header and submit the domain to "
                    "https://hstspreload.org/ for inclusion in browser preload lists."
                ),
                references=[
                    "https://hstspreload.org/",
                ],
            )

    # ------------------------------------------------------------------
    # 4. Mixed Content
    # ------------------------------------------------------------------

    async def _mixed_content(self, base_url: str) -> None:
        if not base_url.startswith("https://"):
            return

        resp = await self.http.get(base_url)
        html = resp.text

        # Find http:// URLs in src and href attributes
        http_refs = re.findall(
            r'(?:src|href)\s*=\s*["\'](\s*http://[^"\']+)["\']',
            html,
            re.IGNORECASE,
        )

        # Deduplicate and filter out known safe patterns
        unique_refs = sorted(set(ref.strip() for ref in http_refs))

        if unique_refs:
            evidence = "\n".join(unique_refs[:20])
            if len(unique_refs) > 20:
                evidence += f"\n... and {len(unique_refs) - 20} more"

            self.add_finding(
                title=f"Mixed content: {len(unique_refs)} insecure HTTP references found",
                severity="Medium",
                cvss_score=4.5,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp="A02:2021 -- Cryptographic Failures",
                url=base_url,
                description=(
                    f"The HTTPS page at {base_url} references {len(unique_refs)} "
                    "resource(s) over insecure HTTP. Mixed content can be intercepted "
                    "or modified by network attackers."
                ),
                evidence_response=evidence,
                impact=(
                    "Insecure resources loaded over HTTP can be tampered with by "
                    "network attackers, potentially injecting malicious content "
                    "into the page."
                ),
                remediation=(
                    "Update all resource references to use HTTPS or protocol-relative "
                    "URLs. Use Content-Security-Policy: upgrade-insecure-requests as "
                    "a fallback."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                ],
            )

    # ------------------------------------------------------------------
    # 5. Certificate Transparency
    # ------------------------------------------------------------------

    async def _certificate_transparency(self, domain: str) -> None:
        try:
            resp = await self.http.get(
                f"https://crt.sh/?q=%.{domain}&output=json", timeout=20
            )
            if resp.status_code != 200:
                self.log(f"crt.sh returned status {resp.status_code}")
                return

            entries = resp.json()
        except Exception as exc:
            self.log(f"Certificate transparency query failed: {exc}")
            return

        cert_count = len(entries)
        self.context["ct_certificates"] = cert_count

        # Collect unique issuers and check for wildcards
        issuers: set[str] = set()
        wildcard_certs: list[str] = []

        for entry in entries:
            issuer_name = entry.get("issuer_name", "")
            if issuer_name:
                issuers.add(issuer_name)
            name_value = entry.get("name_value", "")
            if "*" in name_value:
                wildcard_certs.append(name_value)

        # Deduplicate wildcard entries
        unique_wildcards = sorted(set(wildcard_certs))

        self.context["ct_issuers"] = sorted(issuers)

        if unique_wildcards:
            self.add_finding(
                title=f"Wildcard certificates detected ({len(unique_wildcards)} unique)",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-295",
                cwe_name="Improper Certificate Validation",
                owasp="A02:2021 -- Cryptographic Failures",
                url=f"https://{domain}",
                description=(
                    f"Certificate Transparency logs show {len(unique_wildcards)} "
                    f"wildcard certificate(s) issued for {domain}. Wildcard "
                    "certificates cover all subdomains and, if compromised, affect "
                    "the entire domain."
                ),
                evidence_response="\n".join(unique_wildcards[:20]),
                impact=(
                    "A compromised wildcard certificate allows impersonation of "
                    "any subdomain under the domain."
                ),
                remediation=(
                    "Consider using specific per-subdomain certificates instead of "
                    "wildcards where practical. Monitor Certificate Transparency logs "
                    "for unauthorized issuances."
                ),
                references=[
                    "https://certificate.transparency.dev/",
                    "https://crt.sh/",
                ],
            )

    # ------------------------------------------------------------------
    # 6. Cipher Suite Analysis
    # ------------------------------------------------------------------

    async def _cipher_suite_analysis(self, domain: str) -> None:
        safe_domain = shlex.quote(domain)
        weak_ciphers_found: list[str] = []

        # Try nmap first for comprehensive analysis
        rc, stdout, stderr = await run_command(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain],
            timeout=60,
        )

        if rc == 0 and "ssl-enum-ciphers" in stdout:
            # Parse nmap output for weak ciphers and missing forward secrecy
            weak_patterns = ["NULL", "EXPORT", "RC4", "DES", "3DES", "anon"]
            for line in stdout.splitlines():
                line_stripped = line.strip()
                for pat in weak_patterns:
                    if pat in line_stripped and "TLS_" in line_stripped or "SSL_" in line_stripped:
                        weak_ciphers_found.append(line_stripped)
                        break

            # Check for missing forward secrecy
            if "forward secrecy" not in stdout.lower() and "ECDHE" not in stdout and "DHE" not in stdout:
                self.add_finding(
                    title="Server may not support forward secrecy",
                    severity="Medium",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-326",
                    cwe_name="Inadequate Encryption Strength",
                    owasp="A02:2021 -- Cryptographic Failures",
                    url=f"https://{domain}",
                    description=(
                        f"The server {domain} does not appear to support cipher suites "
                        "with forward secrecy (ECDHE/DHE key exchange). Without forward "
                        "secrecy, compromising the server's private key allows decryption "
                        "of all past recorded traffic."
                    ),
                    evidence_response=stdout[:2000],
                    impact="Past encrypted sessions can be decrypted if the server key is compromised.",
                    remediation="Enable cipher suites with ECDHE or DHE key exchange for forward secrecy.",
                    references=[
                        "https://ssl-config.mozilla.org/",
                    ],
                )
        else:
            # Fallback: test individual weak ciphers via openssl
            weak_cipher_list = [
                ("NULL-SHA", "NULL cipher (no encryption)"),
                ("EXPORT-RC4-MD5", "EXPORT-grade RC4 cipher"),
                ("RC4-SHA", "RC4 stream cipher"),
                ("DES-CBC-SHA", "Single DES cipher"),
                ("DES-CBC3-SHA", "Triple DES (3DES) cipher"),
                ("EXP-DES-CBC-SHA", "EXPORT-grade DES cipher"),
            ]

            for cipher, description in weak_cipher_list:
                rc, stdout, stderr = await run_command(
                    [
                        "bash", "-c",
                        f"echo | openssl s_client -connect {safe_domain}:443 "
                        f"-cipher {shlex.quote(cipher)} 2>&1",
                    ],
                    timeout=10,
                )
                combined = stdout + stderr
                if (
                    "CONNECTED" in combined
                    and "handshake failure" not in combined.lower()
                    and "no ciphers available" not in combined.lower()
                    and "ssl routines" not in combined.lower()
                ):
                    weak_ciphers_found.append(f"{cipher} ({description})")

        if weak_ciphers_found:
            evidence = "\n".join(weak_ciphers_found[:30])
            if len(weak_ciphers_found) > 30:
                evidence += f"\n... and {len(weak_ciphers_found) - 30} more"

            self.add_finding(
                title=f"Weak cipher suites accepted ({len(weak_ciphers_found)} found)",
                severity="High",
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-326",
                cwe_name="Inadequate Encryption Strength",
                owasp="A02:2021 -- Cryptographic Failures",
                url=f"https://{domain}",
                description=(
                    f"The server {domain} accepts {len(weak_ciphers_found)} weak cipher "
                    "suite(s) including NULL, EXPORT, RC4, DES, or 3DES ciphers. These "
                    "ciphers have known cryptographic weaknesses and can be exploited to "
                    "decrypt or tamper with traffic."
                ),
                evidence_response=evidence,
                impact=(
                    "Weak cipher suites allow attackers to decrypt traffic through "
                    "known attacks (SWEET32, BEAST, RC4 biases, brute force)."
                ),
                remediation=(
                    "Disable all NULL, EXPORT, RC4, DES, and 3DES cipher suites. "
                    "Use Mozilla's SSL Configuration Generator for recommended settings: "
                    "https://ssl-config.mozilla.org/"
                ),
                references=[
                    "https://ssl-config.mozilla.org/",
                    "https://www.rfc-editor.org/rfc/rfc7465",
                    "https://sweet32.info/",
                ],
            )
