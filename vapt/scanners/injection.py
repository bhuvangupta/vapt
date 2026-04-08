"""Injection scanner — SQLi, XSS, SSTI, command injection, header injection."""

from __future__ import annotations

import asyncio
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding
from vapt.utils import run_command

# ---------------------------------------------------------------------------
# SQL error indicators by database engine
# ---------------------------------------------------------------------------
SQL_ERROR_PATTERNS = [
    "sql syntax", "mysql", "ora-", "postgresql", "unclosed quotation",
    "sqlite_error", "sqlstate", "microsoft ole db", "odbc sql server",
    "pg::error", "unterminated string", "syntax error at or near",
]

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------
SQLI_PAYLOADS = [
    "'",
    "1 OR 1=1",
    "1' OR '1'='1",
    "1; SELECT 1--",
    "1' AND SLEEP(5)--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "'-alert(1)-'",
]

SSTI_PAYLOADS = [
    ("{{7*191}}", "1337"),
    ("${7*191}", "1337"),
    ("<%= 7*191 %>", "1337"),
    ("#{7*191}", "1337"),
]

CMDI_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
]

FORCED_BROWSING_PATHS = [
    "/admin", "/dashboard", "/api/users", "/api/admin",
    "/settings", "/management", "/internal",
]

PAYLOAD_DIR = Path(__file__).parent.parent.parent / "payloads"


def _load_payloads(filename: str, fallback: list) -> list:
    """Load payloads from file, fall back to hardcoded list."""
    path = PAYLOAD_DIR / filename
    if path.is_file():
        lines = path.read_text().strip().splitlines()
        return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    return fallback


@register_scanner
class InjectionScanner(BaseScanner):
    name = "injection"
    category = "injection"
    weight = 0.20
    active = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._params: list[tuple[str, str, str]] = []  # (url, param_name, method)
        self._sqli_payloads = _load_payloads("sqli.txt", SQLI_PAYLOADS)
        self._xss_payloads = _load_payloads("xss.txt", XSS_PAYLOADS)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def scan(self) -> list[Finding]:
        await self._discover_params()

        await asyncio.gather(
            self._test_sqli(),
            self._test_xss(),
            self._test_ssti(),
            self._test_cmdi(),
            self._test_header_injection(),
        )
        return self.findings

    # ------------------------------------------------------------------
    # 1. Parameter Discovery
    # ------------------------------------------------------------------

    async def _discover_params(self) -> None:
        """Fetch target HTML to extract form actions, input names, and href query params."""
        try:
            resp = await self.http.get(self.target.url)
            body = resp.text
        except Exception:
            return

        base_url = self.target.base_url

        # Extract form actions and input names
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?(GET|POST)["\']?',
            re.IGNORECASE,
        )
        input_pattern = re.compile(
            r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE,
        )

        forms = form_pattern.findall(body)
        for action, method in forms:
            form_url = urljoin(base_url, action) if action else self.target.url
            # Find inputs within the form context (simplified: all inputs on page)
            for input_match in input_pattern.findall(body):
                self._params.append((form_url, input_match, method.upper()))

        # Extract href query params
        href_pattern = re.compile(r'href=["\']([^"\']*\?[^"\']*)["\']', re.IGNORECASE)
        for href in href_pattern.findall(body):
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            query_params = parse_qs(parsed.query)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param_name in query_params:
                self._params.append((clean_url, param_name, "GET"))

        # Check context for endpoints discovered by webapp scanner
        ctx_endpoints = self.context.get("discovered_endpoints", [])
        for ep in ctx_endpoints:
            ep_url = ep if ep.startswith("http") else urljoin(base_url, ep)
            parsed = urlparse(ep_url)
            query_params = parse_qs(parsed.query)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param_name in query_params:
                self._params.append((clean_url, param_name, "GET"))

        # Deduplicate
        self._params = list(set(self._params))

        # If no params found, create a synthetic one for the base URL
        if not self._params:
            self._params.append((self.target.url, "q", "GET"))

    # ------------------------------------------------------------------
    # Helper: send request with payload injected into parameter
    # ------------------------------------------------------------------

    async def _inject(self, url: str, param: str, method: str,
                      payload: str) -> tuple[str | None, float, int, str]:
        """Inject payload into param. Returns (response_body, elapsed, status, request_desc)."""
        try:
            start = time.monotonic()
            if method == "GET":
                test_url = f"{url}?{urlencode({param: payload})}"
                resp = await self.http.get(test_url)
                request_desc = f"GET {test_url}"
            else:
                resp = await self.http.post(url, data={param: payload})
                request_desc = f"POST {url} with {param}={payload}"
            elapsed = time.monotonic() - start
            return resp.text, elapsed, resp.status_code, request_desc
        except Exception:
            return None, 0.0, 0, ""

    async def _get_baseline(self, url: str, param: str, method: str) -> tuple[str, float]:
        """Get baseline response for comparison."""
        body, elapsed, _, _ = await self._inject(url, param, method, "testvalue123")
        return body or "", elapsed

    # ------------------------------------------------------------------
    # 2. SQL Injection
    # ------------------------------------------------------------------

    async def _test_sqli(self) -> None:
        try:
            await self._test_sqli_inner()
        except Exception:
            pass

    async def _test_sqli_inner(self) -> None:
        # Try sqlmap first if available
        if self.tools.available("sqlmap") and self._params:
            url, param, _ = self._params[0]
            test_url = f"{url}?{param}=1"
            with tempfile.TemporaryDirectory(prefix="vapt-sqlmap-") as tmpdir:
                rc, stdout, stderr = await run_command(
                    [
                        "sqlmap", "-u", test_url,
                        "--batch", "--level", "3", "--risk", "2",
                        "--forms", "--threads", "4",
                        f"--output-dir={tmpdir}",
                    ],
                    timeout=120,
                )
                output = stdout + stderr
            if rc == 0 and any(
                indicator in output.lower()
                for indicator in ["is vulnerable", "sqlmap identified", "parameter", "injectable"]
            ):
                self.add_finding(
                    title=f"SQL Injection (sqlmap confirmed)",
                    severity="Critical",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe_id="CWE-89",
                    cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
                    owasp="A03:2021 -- Injection",
                    url=test_url,
                    parameter=param,
                    description=f"sqlmap confirmed SQL injection in parameter '{param}'.",
                    steps_to_reproduce=[
                        f"Run: sqlmap -u '{test_url}' --batch --level 3 --risk 2",
                    ],
                    evidence_request=f"sqlmap -u '{test_url}' --batch",
                    evidence_response=output[:2000],
                    impact="Full database compromise. An attacker can read, modify, or delete all data and potentially achieve remote code execution.",
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                )
                return  # sqlmap found it, no need for manual fallback

        # Fallback: manual testing
        for url, param, method in self._params:
            baseline_body, baseline_time = await self._get_baseline(url, param, method)

            for payload in self._sqli_payloads:
                body, elapsed, status, req_desc = await self._inject(url, param, method, payload)
                if body is None:
                    continue

                # Check for error-based SQL injection
                body_lower = body.lower()
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in body_lower and pattern not in baseline_body.lower():
                        self.add_finding(
                            title=f"Error-based SQL Injection: {param}",
                            severity="Critical",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            cwe_id="CWE-89",
                            cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
                            owasp="A03:2021 -- Injection",
                            url=url,
                            parameter=param,
                            description=(
                                f"SQL error detected when injecting payload '{payload}' into "
                                f"parameter '{param}'. Database error pattern '{pattern}' found in response."
                            ),
                            steps_to_reproduce=[
                                f"Send: {req_desc}",
                                f"Observe SQL error pattern '{pattern}' in response body.",
                            ],
                            evidence_request=req_desc,
                            evidence_response=body[:2000],
                            impact="Full database compromise. An attacker can read, modify, or delete all data and potentially achieve remote code execution.",
                            remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                        )
                        return  # One finding per param type is enough

                # Check for boolean-based blind SQLi (significantly different response)
                if payload in ("1 OR 1=1", "1' OR '1'='1"):
                    len_diff = abs(len(body) - len(baseline_body))
                    if len_diff > 200 and status == 200:
                        self.add_finding(
                            title=f"Potential Boolean-based Blind SQL Injection: {param}",
                            severity="Critical",
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            cwe_id="CWE-89",
                            cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
                            owasp="A03:2021 -- Injection",
                            url=url,
                            parameter=param,
                            confidence="tentative",
                            description=(
                                f"Significant response difference ({len_diff} bytes) detected when "
                                f"injecting boolean payload '{payload}' into parameter '{param}'. "
                                "This may indicate blind SQL injection."
                            ),
                            steps_to_reproduce=[
                                f"Send baseline request: {url}?{param}=testvalue123",
                                f"Send: {req_desc}",
                                f"Compare response lengths: baseline={len(baseline_body)}, payload={len(body)}",
                            ],
                            evidence_request=req_desc,
                            evidence_response=body[:2000],
                            impact="Full database compromise via blind SQL injection. Data can be exfiltrated one bit at a time.",
                            remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                            ],
                        )
                        return

                # Check for time-based blind SQLi
                if "SLEEP" in payload.upper() and elapsed > baseline_time + 2.5:
                    self.add_finding(
                        title=f"Potential Time-based Blind SQL Injection: {param}",
                        severity="High",
                        cvss_score=8.6,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        cwe_id="CWE-89",
                        cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
                        owasp="A03:2021 -- Injection",
                        url=url,
                        parameter=param,
                        confidence="tentative",
                        description=(
                            f"Response delayed by {elapsed - baseline_time:.1f}s when injecting "
                            f"time-based payload '{payload}' into parameter '{param}'."
                        ),
                        steps_to_reproduce=[
                            f"Send baseline request and measure response time ({baseline_time:.1f}s).",
                            f"Send: {req_desc}",
                            f"Observe delayed response ({elapsed:.1f}s).",
                        ],
                        evidence_request=req_desc,
                        impact="Database compromise via time-based blind SQL injection. Data exfiltration is slower but fully exploitable.",
                        remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                    )
                    return

    # ------------------------------------------------------------------
    # 3. Reflected XSS
    # ------------------------------------------------------------------

    async def _test_xss(self) -> None:
        try:
            await self._test_xss_inner()
        except Exception:
            pass

    async def _test_xss_inner(self) -> None:
        for url, param, method in self._params:
            for payload in self._xss_payloads:
                body, _, status, req_desc = await self._inject(url, param, method, payload)
                if body is None:
                    continue

                # Check if payload appears unencoded in response
                if payload in body:
                    # Check for CSP header
                    has_csp = False
                    try:
                        resp = await self.http.get(url)
                        csp_header = resp.headers.get("content-security-policy", "")
                        has_csp = bool(csp_header)
                    except Exception:
                        pass

                    if has_csp:
                        severity, cvss = "Medium", 5.4
                        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
                        note = " (CSP present, reducing exploitability)"
                    else:
                        severity, cvss = "High", 7.1
                        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
                        note = " (no CSP protection)"

                    self.add_finding(
                        title=f"Reflected XSS{note}: {param}",
                        severity=severity,
                        cvss_score=cvss,
                        cvss_vector=cvss_vector,
                        cwe_id="CWE-79",
                        cwe_name="Improper Neutralization of Input During Web Page Generation",
                        owasp="A03:2021 -- Injection",
                        url=url,
                        parameter=param,
                        confidence="tentative",
                        description=(
                            f"The payload '{payload}' was reflected unencoded in the response when "
                            f"injected into parameter '{param}'. This suggests the parameter may be "
                            "vulnerable to cross-site scripting. Manual verification in a browser is "
                            "required to confirm execution."
                        ),
                        steps_to_reproduce=[
                            f"Send: {req_desc}",
                            "Observe the payload reflected unencoded in the response body.",
                            "Open the URL in a browser to confirm script execution.",
                        ],
                        evidence_request=req_desc,
                        evidence_response=body[:2000],
                        impact="An attacker can steal session cookies, redirect users to malicious sites, or perform actions on behalf of the victim.",
                        remediation="Context-aware output encoding + Content Security Policy.",
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    )
                    return  # One XSS finding is sufficient

    # ------------------------------------------------------------------
    # 4. Server-Side Template Injection (SSTI)
    # ------------------------------------------------------------------

    async def _test_ssti(self) -> None:
        try:
            await self._test_ssti_inner()
        except Exception:
            pass

    async def _test_ssti_inner(self) -> None:
        for url, param, method in self._params:
            for payload, expected in SSTI_PAYLOADS:
                body, _, status, req_desc = await self._inject(url, param, method, payload)
                if body is None:
                    continue

                # Check if the computed result appears in the response
                # but also ensure it is not just a literal echo of the payload
                if expected in body and payload not in body:
                    self.add_finding(
                        title=f"Server-Side Template Injection (SSTI): {param}",
                        severity="Critical",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-1336",
                        cwe_name="Improper Neutralization of Special Elements Used in a Template Engine",
                        owasp="A03:2021 -- Injection",
                        url=url,
                        parameter=param,
                        description=(
                            f"Injecting template expression '{payload}' into parameter '{param}' "
                            f"caused the server to evaluate it and return '{expected}' in the response. "
                            "This confirms server-side template injection."
                        ),
                        steps_to_reproduce=[
                            f"Send: {req_desc}",
                            f"Observe '{expected}' in the response (the evaluated result of {payload}).",
                        ],
                        evidence_request=req_desc,
                        evidence_response=body[:2000],
                        impact="Full remote code execution on the server. An attacker can read files, execute system commands, and pivot to internal networks.",
                        remediation="Never pass user input directly into template engines. Use sandboxed template environments and input validation.",
                        references=[
                            "https://portswigger.net/web-security/server-side-template-injection",
                            "https://owasp.org/www-project-web-security-testing-guide/",
                        ],
                    )
                    return  # One SSTI finding is sufficient

    # ------------------------------------------------------------------
    # 5. Command Injection
    # ------------------------------------------------------------------

    async def _test_cmdi(self) -> None:
        try:
            await self._test_cmdi_inner()
        except Exception:
            pass

    async def _test_cmdi_inner(self) -> None:
        for url, param, method in self._params:
            baseline_body, baseline_time = await self._get_baseline(url, param, method)

            for payload in CMDI_PAYLOADS:
                body, elapsed, status, req_desc = await self._inject(url, param, method, payload)
                if body is None:
                    continue

                # Time-based detection: if response takes >4s longer than baseline
                if elapsed > baseline_time + 4:
                    self.add_finding(
                        title=f"Potential Command Injection: {param}",
                        severity="High",
                        cvss_score=8.6,
                        confidence="tentative",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-78",
                        cwe_name="Improper Neutralization of Special Elements used in an OS Command",
                        owasp="A03:2021 -- Injection",
                        url=url,
                        parameter=param,
                        description=(
                            f"Response delayed by {elapsed - baseline_time:.1f}s when injecting "
                            f"time-based command injection payload '{payload}' into parameter '{param}'. "
                            "The server appears to be executing OS commands."
                        ),
                        steps_to_reproduce=[
                            f"Send baseline request and measure response time ({baseline_time:.1f}s).",
                            f"Send: {req_desc}",
                            f"Observe delayed response ({elapsed:.1f}s), confirming command execution.",
                        ],
                        evidence_request=req_desc,
                        impact="Full remote code execution. An attacker can execute arbitrary OS commands, read/write files, and compromise the server.",
                        remediation="Never pass user input to OS command functions. Use language-specific APIs instead of shell commands. Apply strict input validation with allowlists.",
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                        ],
                    )
                    return  # One cmdi finding is sufficient

    # ------------------------------------------------------------------
    # 6. Header Injection
    # ------------------------------------------------------------------

    async def _test_header_injection(self) -> None:
        try:
            await self._test_header_injection_inner()
        except Exception:
            pass

    async def _test_header_injection_inner(self) -> None:
        base_url = self.target.url

        # --- Host header injection ---
        try:
            resp = await self.http.get(base_url, headers={"Host": "evil.com"})
            body = resp.text
            location = resp.headers.get("location", "")

            if "evil.com" in body or "evil.com" in location:
                self.add_finding(
                    title="Host Header Injection",
                    severity="High",
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N",
                    cwe_id="CWE-644",
                    cwe_name="Improper Neutralization of HTTP Headers for Scripting Syntax",
                    owasp="A03:2021 -- Injection",
                    url=base_url,
                    parameter="Host header",
                    description=(
                        "The application reflects the Host header value in its response. "
                        "Injecting 'Host: evil.com' caused 'evil.com' to appear in the "
                        f"{'Location header' if 'evil.com' in location else 'response body'}."
                    ),
                    steps_to_reproduce=[
                        f"Send: curl -H 'Host: evil.com' {base_url}",
                        "Observe 'evil.com' in the response.",
                    ],
                    evidence_request=f"GET {base_url} with Host: evil.com",
                    evidence_response=(location if "evil.com" in location else body[:2000]),
                    impact="Host header injection can enable password reset poisoning, web cache poisoning, and SSRF attacks.",
                    remediation="Validate the Host header against a whitelist of allowed domains. Use server-side configuration for absolute URLs instead of relying on the Host header.",
                    references=[
                        "https://portswigger.net/web-security/host-header",
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                )
        except Exception:
            pass

        # --- CRLF injection ---
        try:
            crlf_url = f"{base_url}/%0d%0aX-Injected:%20true"
            resp = await self.http.get(crlf_url)
            injected_header = resp.headers.get("x-injected", "")

            if injected_header == "true":
                self.add_finding(
                    title="CRLF Injection (HTTP Response Splitting)",
                    severity="Medium",
                    cvss_score=5.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cwe_id="CWE-113",
                    cwe_name="Improper Neutralization of CRLF Sequences in HTTP Headers",
                    owasp="A03:2021 -- Injection",
                    url=crlf_url,
                    parameter="URL path",
                    description=(
                        "The application is vulnerable to CRLF injection. Injecting "
                        "%0d%0a sequences in the URL path allows arbitrary HTTP headers "
                        "to be injected into the response."
                    ),
                    steps_to_reproduce=[
                        f"Send: GET {crlf_url}",
                        "Observe 'X-Injected: true' in response headers.",
                    ],
                    evidence_request=f"GET {crlf_url}",
                    evidence_response=f"X-Injected: {injected_header}",
                    impact="CRLF injection enables HTTP response splitting, session fixation, XSS via injected headers, and cache poisoning.",
                    remediation="Strip or encode CRLF characters (\\r\\n) from all user-controlled input used in HTTP headers or redirects.",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                        "https://portswigger.net/web-security/request-smuggling",
                    ],
                )
        except Exception:
            pass
