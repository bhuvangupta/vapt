"""SSRF and Open Redirect scanner — active injection tests."""

from __future__ import annotations

from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding


# Internal/metadata URLs to probe for SSRF
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::1]",
    "http://0.0.0.0",
]

# Common parameter names that may accept URLs
URL_PARAMS = [
    "url", "link", "redirect", "next", "target",
    "uri", "path", "file", "src", "href", "fetch",
]

# Redirect-specific parameter names
REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "returnUrl",
    "continue", "dest", "destination", "goto", "forward",
]

# AWS/cloud metadata markers in response body
METADATA_MARKERS = [
    "ami-id", "instance-id", "instance-type", "local-hostname",
    "public-hostname", "security-credentials", "iam",
    "meta-data", "user-data", "placement",
]


@register_scanner
class SSRFScanner(BaseScanner):
    name = "ssrf"
    category = "injection"
    weight = 0.0
    active = True

    async def scan(self) -> list[Finding]:
        url = self.target.url

        tests = [
            self._test_url_param_ssrf(url),
            self._test_open_redirect(url),
            self._test_metadata_via_headers(url),
        ]

        for coro in tests:
            try:
                await coro
            except Exception as exc:
                self.log(f"SSRF test failed: {exc}")

        return self.findings

    # ------------------------------------------------------------------
    # 1. URL Parameter SSRF
    # ------------------------------------------------------------------

    async def _test_url_param_ssrf(self, url: str) -> None:
        """Inject internal URLs into common URL parameters and check responses."""
        # Get baseline response length
        try:
            baseline_resp = await self.http.get(url)
            baseline_len = len(baseline_resp.text)
        except Exception:
            baseline_len = 0

        for param in URL_PARAMS:
            for payload in SSRF_PAYLOADS:
                test_url = self._inject_param(url, param, payload)

                try:
                    resp = await self.http.get(test_url)
                except Exception:
                    continue

                body = resp.text.lower()

                # Check for cloud metadata markers (Critical)
                metadata_found = [m for m in METADATA_MARKERS if m in body]
                if metadata_found:
                    self.add_finding(
                        title=f"SSRF: Cloud metadata accessible via '{param}' parameter",
                        severity="Critical",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        cwe_id="CWE-918",
                        cwe_name="Server-Side Request Forgery (SSRF)",
                        owasp="A10:2021 -- Server-Side Request Forgery (SSRF)",
                        url=url,
                        parameter=param,
                        description=(
                            f"The '{param}' parameter is vulnerable to SSRF. Injecting "
                            f"'{payload}' returned cloud metadata markers: "
                            f"{', '.join(metadata_found[:5])}. An attacker can access "
                            "internal services and cloud instance metadata."
                        ),
                        evidence_request=f"GET {test_url}",
                        evidence_response=resp.text[:1000],
                        impact=(
                            "Full cloud metadata access including IAM credentials, "
                            "enabling lateral movement and privilege escalation in "
                            "the cloud environment."
                        ),
                        remediation=(
                            "Validate and sanitize all URL inputs server-side. Use an "
                            "allowlist of permitted domains. Block requests to internal "
                            "IP ranges (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, "
                            "172.16.0.0/12, 192.168.0.0/16). Use IMDSv2 on AWS."
                        ),
                        references=[
                            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                        ],
                    )
                    return  # One critical finding is sufficient

                # Check for significant response size difference (High)
                resp_len = len(resp.text)
                if baseline_len > 0 and resp_len > 0:
                    size_diff = abs(resp_len - baseline_len)
                    # Significant difference: response is 3x larger or 50%+ different
                    if size_diff > baseline_len * 0.5 and resp_len > baseline_len * 2:
                        self.add_finding(
                            title=f"Potential SSRF via '{param}' parameter",
                            severity="Medium",
                            cvss_score=5.3,
                            confidence="tentative",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                            cwe_id="CWE-918",
                            cwe_name="Server-Side Request Forgery (SSRF)",
                            owasp="A10:2021 -- Server-Side Request Forgery (SSRF)",
                            url=url,
                            parameter=param,
                            description=(
                                f"The '{param}' parameter may be vulnerable to SSRF. "
                                f"Injecting '{payload}' produced a response of "
                                f"{resp_len} bytes vs baseline {baseline_len} bytes, "
                                "suggesting the server fetched the injected URL."
                            ),
                            evidence_request=f"GET {test_url}",
                            evidence_response=f"Response length: {resp_len} (baseline: {baseline_len})",
                            impact=(
                                "Server-side request forgery can expose internal services, "
                                "bypass firewalls, and access cloud metadata."
                            ),
                            remediation=(
                                "Validate and sanitize all URL inputs. Use an allowlist "
                                "of permitted domains and block internal IP ranges."
                            ),
                            references=[
                                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                            ],
                        )
                        return  # One finding per test type

    # ------------------------------------------------------------------
    # 2. Open Redirect
    # ------------------------------------------------------------------

    async def _test_open_redirect(self, url: str) -> None:
        """Inject external URLs into redirect parameters and check for 3xx redirects."""
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
        ]

        for param in REDIRECT_PARAMS:
            for payload in redirect_payloads:
                test_url = self._inject_param(url, param, payload)

                try:
                    # Do not follow redirects for this test
                    resp = await self.http.request(
                        "GET", test_url,
                        follow_redirects=False,
                    )
                except Exception:
                    continue

                if 300 <= resp.status_code < 400:
                    location = resp.headers.get("location", "")
                    if "evil.com" in location.lower():
                        self.add_finding(
                            title=f"Open redirect via '{param}' parameter",
                            severity="Medium",
                            cvss_score=6.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            cwe_id="CWE-601",
                            cwe_name="URL Redirection to Untrusted Site ('Open Redirect')",
                            owasp="A01:2021 -- Broken Access Control",
                            url=url,
                            parameter=param,
                            description=(
                                f"The '{param}' parameter is vulnerable to open redirect. "
                                f"Injecting '{payload}' caused a {resp.status_code} redirect "
                                f"to '{location}'. Attackers can use this to redirect users "
                                "to malicious sites for phishing."
                            ),
                            evidence_request=f"GET {test_url}",
                            evidence_response=(
                                f"HTTP {resp.status_code}\n"
                                f"Location: {location}"
                            ),
                            impact=(
                                "Open redirects enable phishing attacks by abusing trust "
                                "in the legitimate domain. They can also be chained with "
                                "OAuth flows to steal tokens."
                            ),
                            remediation=(
                                "Validate redirect targets against an allowlist of "
                                "permitted domains. Use relative paths for internal "
                                "redirects. Never redirect to user-supplied URLs directly."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                            ],
                        )
                        return  # One finding is sufficient

    # ------------------------------------------------------------------
    # 3. Metadata via Headers
    # ------------------------------------------------------------------

    async def _test_metadata_via_headers(self, url: str) -> None:
        """Send crafted headers to probe for SSRF via server-side header processing."""
        header_tests = [
            {
                "X-Forwarded-For": "169.254.169.254",
                "X-Original-URL": "http://169.254.169.254/latest/meta-data/",
            },
            {
                "X-Forwarded-Host": "169.254.169.254",
                "X-Rewrite-URL": "http://169.254.169.254/latest/meta-data/",
            },
        ]

        for test_headers in header_tests:
            try:
                resp = await self.http.get(url, headers=test_headers)
            except Exception:
                continue

            body = resp.text.lower()
            metadata_found = [m for m in METADATA_MARKERS if m in body]

            if metadata_found:
                header_names = ", ".join(test_headers.keys())
                self.add_finding(
                    title=f"SSRF via header injection ({header_names})",
                    severity="Critical",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    cwe_id="CWE-918",
                    cwe_name="Server-Side Request Forgery (SSRF)",
                    owasp="A10:2021 -- Server-Side Request Forgery (SSRF)",
                    url=url,
                    description=(
                        f"Sending headers ({header_names}) with internal metadata URLs "
                        f"returned cloud metadata markers: {', '.join(metadata_found[:5])}. "
                        "The server may be processing these headers to make internal requests."
                    ),
                    evidence_request="\n".join(f"{k}: {v}" for k, v in test_headers.items()),
                    evidence_response=resp.text[:1000],
                    impact=(
                        "Cloud metadata access via header injection can expose IAM "
                        "credentials and enable full cloud account compromise."
                    ),
                    remediation=(
                        "Do not use client-supplied headers (X-Forwarded-For, "
                        "X-Original-URL, etc.) to construct internal requests. "
                        "Sanitize and validate all header values. Use IMDSv2 on AWS."
                    ),
                    references=[
                        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                    ],
                )
                return  # One critical finding is sufficient

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        """Append or replace a query parameter in the URL."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
