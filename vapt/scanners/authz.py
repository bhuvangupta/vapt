"""Authorization scanner — forced browsing, IDOR, method tampering, path traversal."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlencode, urljoin

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding
from vapt.utils import run_command

# Paths that should not be accessible without authentication
SENSITIVE_PATHS = [
    ("/admin", "Admin panel"),
    ("/dashboard", "Dashboard"),
    ("/api/users", "User API"),
    ("/api/admin", "Admin API"),
    ("/settings", "Settings page"),
    ("/management", "Management panel"),
    ("/internal", "Internal endpoint"),
]

# Common IDOR test patterns
IDOR_ENDPOINTS = [
    "/api/users/{id}",
    "/api/orders/{id}",
    "/api/accounts/{id}",
    "/api/profiles/{id}",
    "/users/{id}",
    "/orders/{id}",
]

# HTTP methods to try for method tampering
TAMPER_METHODS = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

# Override headers for method tampering
METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
]

# Path traversal payloads
TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "dot-dot-slash"),
    ("....//....//etc/passwd", "double-dot bypass"),
    ("..%2f..%2f..%2fetc/passwd", "URL-encoded slash"),
    ("..%252f..%252fetc/passwd", "double URL-encoded slash"),
]


@register_scanner
class AuthzScanner(BaseScanner):
    name = "authz"
    category = "authorization"
    weight = 0.12
    active = True

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def scan(self) -> list[Finding]:
        await asyncio.gather(
            self._test_forced_browsing(),
            self._test_idor(),
            self._test_method_tampering(),
            self._test_path_traversal(),
        )
        return self.findings

    # ------------------------------------------------------------------
    # 1. Forced Browsing
    # ------------------------------------------------------------------

    async def _test_forced_browsing(self) -> None:
        try:
            await self._test_forced_browsing_inner()
        except Exception:
            pass

    async def _test_forced_browsing_inner(self) -> None:
        base = self.target.base_url

        # Fetch a known-404 baseline to detect soft-404s (SPAs returning 200)
        baseline_body = await self.fetch_soft404_baseline()

        async def check_path(path: str, desc: str) -> None:
            url = f"{base}{path}"
            try:
                resp = await self.http.get(url)
            except Exception:
                return

            if resp.status_code == 200:
                # Filter out soft-404s (SPAs that return 200 for all routes)
                if self.is_soft_404(resp.text, baseline_body):
                    return

                # Must have substantive content beyond a generic shell
                if len(resp.text) < 200:
                    return

                # Determine severity based on path sensitivity
                is_admin = any(kw in path.lower() for kw in ["admin", "management", "internal"])
                is_api = path.startswith("/api/")

                if is_admin:
                    severity, cvss = "Critical", 9.8
                    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                elif is_api:
                    severity, cvss = "High", 7.5
                    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                else:
                    severity, cvss = "High", 7.5
                    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

                self.add_finding(
                    title=f"Forced Browsing: {desc} Accessible ({path})",
                    severity=severity,
                    cvss_score=cvss,
                    cvss_vector=cvss_vector,
                    cwe_id="CWE-425",
                    cwe_name="Direct Request ('Forced Browsing')",
                    owasp="A01:2021 -- Broken Access Control",
                    url=url,
                    description=(
                        f"The {desc.lower()} at {path} returned HTTP 200 with distinct content "
                        f"({len(resp.text)} bytes) when accessed without authentication, and "
                        "the response does not match the site's default 404 page. "
                        "This indicates the endpoint exists and may lack access controls."
                    ),
                    steps_to_reproduce=[
                        "Ensure no authentication cookies or tokens are set.",
                        f"Navigate to {url}",
                        "Observe that the page is accessible without login.",
                    ],
                    evidence_request=f"GET {url} (no auth)",
                    evidence_response=resp.text[:2000],
                        impact="Unauthenticated access to sensitive functionality. Attackers can view or modify data, access admin features, or enumerate users.",
                        remediation="Implement server-side access controls on all sensitive endpoints. Enforce authentication before granting access to protected resources.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/",
                            "https://cwe.mitre.org/data/definitions/425.html",
                        ],
                    )

            elif resp.status_code == 403:
                self.add_finding(
                    title=f"Protected Endpoint Discovered: {path}",
                    severity="Info",
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    cwe_id="CWE-425",
                    cwe_name="Direct Request ('Forced Browsing')",
                    owasp="A01:2021 -- Broken Access Control",
                    url=url,
                    description=(
                        f"The endpoint {path} returned HTTP 403 (Forbidden). "
                        "The resource exists but access is restricted."
                    ),
                    impact="The endpoint exists and is protected. No vulnerability, but confirms the path for further testing.",
                    remediation="No action needed — access control is in place.",
                )

        tasks = [check_path(path, desc) for path, desc in SENSITIVE_PATHS]
        await asyncio.gather(*tasks)

    # ------------------------------------------------------------------
    # 2. IDOR Pattern Testing
    # ------------------------------------------------------------------

    async def _test_idor(self) -> None:
        try:
            await self._test_idor_inner()
        except Exception:
            pass

    async def _test_idor_inner(self) -> None:
        base = self.target.base_url

        # Collect endpoints to test: from context or defaults
        endpoints_to_test: list[str] = []

        ctx_endpoints = self.context.get("discovered_endpoints", [])
        for ep in ctx_endpoints:
            # Look for endpoints with numeric IDs
            if re.search(r'/\d+', ep):
                endpoints_to_test.append(ep)

        # Add default IDOR patterns
        for pattern in IDOR_ENDPOINTS:
            endpoints_to_test.append(pattern.replace("{id}", "1"))
            endpoints_to_test.append(pattern.replace("{id}", "2"))

        # Deduplicate
        endpoints_to_test = list(set(endpoints_to_test))

        # Build auth headers if target has authentication
        auth_headers: dict[str, str] = {}
        auth_cookies: dict[str, str] = {}
        if self.target.has_auth():
            auth = self.target.auth or {}
            header_name = auth.get("token_header", "Authorization")
            if auth.get("token"):
                auth_headers[header_name] = f"Bearer {auth['token']}"
            if auth.get("api_key"):
                auth_headers[header_name] = auth["api_key"]
            if auth.get("cookies"):
                auth_cookies = auth["cookies"]

        # Test pairs of IDs (1 vs 2) for IDOR
        tested_bases: set[str] = set()

        for endpoint in endpoints_to_test:
            ep_url = endpoint if endpoint.startswith("http") else f"{base}{endpoint}"

            # Extract the base pattern (replace last numeric ID)
            base_pattern = re.sub(r'/(\d+)(?=/|$)', '/{ID}', ep_url)
            if base_pattern in tested_bases:
                continue
            tested_bases.add(base_pattern)

            # Try ID 1 and ID 2
            url_id1 = re.sub(r'/\{ID\}', '/1', base_pattern)
            url_id2 = re.sub(r'/\{ID\}', '/2', base_pattern)

            try:
                kwargs = {}
                if auth_headers:
                    kwargs["headers"] = auth_headers
                if auth_cookies:
                    kwargs["cookies"] = auth_cookies

                resp1 = await self.http.get(url_id1, **kwargs)
                resp2 = await self.http.get(url_id2, **kwargs)
            except Exception:
                continue

            # Both IDs return 200 with different content — potential IDOR
            if (
                resp1.status_code == 200
                and resp2.status_code == 200
                and resp1.text != resp2.text
                and len(resp1.text) > 50
                and len(resp2.text) > 50
            ):
                self.add_finding(
                    title=f"Potential IDOR: {base_pattern}",
                    severity="Medium",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-639",
                    cwe_name="Authorization Bypass Through User-Controlled Key",
                    owasp="A01:2021 -- Broken Access Control",
                    url=url_id1,
                    parameter="Resource ID",
                    confidence="tentative",
                    description=(
                        f"Accessing {url_id1} and {url_id2} both returned HTTP 200 with different "
                        f"content ({len(resp1.text)} vs {len(resp2.text)} bytes). "
                        "This suggests that resource IDs are directly accessible without proper "
                        "authorization checks, allowing access to other users' data. "
                        "This is a heuristic detection — the differing responses may represent "
                        "distinct public resources. Manual verification required."
                    ),
                    steps_to_reproduce=[
                        f"Authenticate as user A.",
                        f"Send: GET {url_id1} — observe the response.",
                        f"Change the ID: GET {url_id2} — observe different data returned.",
                        "Confirm that data belongs to a different user.",
                    ],
                    evidence_request=f"GET {url_id1} and GET {url_id2}",
                    evidence_response=f"ID 1 response ({len(resp1.text)} bytes): {resp1.text[:500]}\n---\nID 2 response ({len(resp2.text)} bytes): {resp2.text[:500]}",
                    impact="Unauthorized access to other users' data. Attackers can enumerate and access any resource by changing the ID parameter.",
                    remediation="Implement proper authorization checks. Verify that the authenticated user owns the requested resource. Use indirect object references (UUIDs) instead of sequential IDs.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                    ],
                )

    # ------------------------------------------------------------------
    # 3. HTTP Method Tampering
    # ------------------------------------------------------------------

    async def _test_method_tampering(self) -> None:
        try:
            await self._test_method_tampering_inner()
        except Exception:
            pass

    async def _test_method_tampering_inner(self) -> None:
        base = self.target.base_url

        # Collect endpoints that return 403 on GET
        protected_endpoints: list[str] = []

        for path, desc in SENSITIVE_PATHS:
            url = f"{base}{path}"
            try:
                resp = await self.http.get(url)
                if resp.status_code == 403:
                    protected_endpoints.append(url)
            except Exception:
                continue

        # Also check context for protected endpoints
        for ep in self.context.get("protected_endpoints", []):
            ep_url = ep if ep.startswith("http") else f"{base}{ep}"
            protected_endpoints.append(ep_url)

        protected_endpoints = list(set(protected_endpoints))

        for url in protected_endpoints:
            # Try different HTTP methods
            for method in TAMPER_METHODS:
                try:
                    resp = await self.http.request(method, url)
                except Exception:
                    continue

                if resp.status_code == 200 and len(resp.text) > 100:
                    self.add_finding(
                        title=f"HTTP Method Tampering Bypass: {method} {url}",
                        severity="High",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-650",
                        cwe_name="Trusting HTTP Permission Methods on the Server Side",
                        owasp="A01:2021 -- Broken Access Control",
                        url=url,
                        parameter=f"HTTP Method: {method}",
                        description=(
                            f"The endpoint {url} returns HTTP 403 for GET requests but returns "
                            f"HTTP 200 with content when accessed via {method}. This indicates "
                            "that access controls only check specific HTTP methods."
                        ),
                        steps_to_reproduce=[
                            f"Send: GET {url} — observe HTTP 403.",
                            f"Send: {method} {url} — observe HTTP 200 with content.",
                        ],
                        evidence_request=f"{method} {url}",
                        evidence_response=resp.text[:2000],
                        impact="Bypassing access controls via HTTP method tampering allows unauthorized access to protected resources.",
                        remediation="Apply access controls regardless of HTTP method. Use framework-level authorization that covers all methods. Deny by default.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/",
                            "https://cwe.mitre.org/data/definitions/650.html",
                        ],
                    )
                    break  # One bypass per endpoint is enough

            # Try method override headers
            for override_header in METHOD_OVERRIDE_HEADERS:
                for override_method in ("GET", "PUT", "PATCH", "DELETE"):
                    try:
                        resp = await self.http.post(
                            url, headers={override_header: override_method}
                        )
                    except Exception:
                        continue

                    if resp.status_code == 200 and len(resp.text) > 100:
                        self.add_finding(
                            title=f"Method Override Bypass: {override_header}: {override_method}",
                            severity="High",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-650",
                            cwe_name="Trusting HTTP Permission Methods on the Server Side",
                            owasp="A01:2021 -- Broken Access Control",
                            url=url,
                            parameter=f"{override_header}: {override_method}",
                            description=(
                                f"The endpoint {url} returns HTTP 403 normally but returns HTTP 200 "
                                f"when a POST request includes the header '{override_header}: {override_method}'. "
                                "The server honors method override headers, bypassing access controls."
                            ),
                            steps_to_reproduce=[
                                f"Send: GET {url} — observe HTTP 403.",
                                f"Send: POST {url} with header '{override_header}: {override_method}' — observe HTTP 200.",
                            ],
                            evidence_request=f"POST {url} with {override_header}: {override_method}",
                            evidence_response=resp.text[:2000],
                            impact="Method override headers bypass access controls, granting unauthorized access to protected endpoints.",
                            remediation="Disable support for HTTP method override headers in production. Apply authorization checks regardless of the effective HTTP method.",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/",
                            ],
                        )
                        return  # Found a bypass, stop testing overrides

    # ------------------------------------------------------------------
    # 4. Path Traversal
    # ------------------------------------------------------------------

    async def _test_path_traversal(self) -> None:
        try:
            await self._test_path_traversal_inner()
        except Exception:
            pass

    async def _test_path_traversal_inner(self) -> None:
        base = self.target.base_url

        # Collect endpoints with file parameters from context
        file_endpoints: list[tuple[str, str]] = []  # (url, param_name)

        ctx_endpoints = self.context.get("discovered_endpoints", [])
        for ep in ctx_endpoints:
            ep_lower = ep.lower()
            # Look for file-related parameter names
            for file_param in ("file", "path", "page", "doc", "document", "template",
                               "include", "load", "read", "download", "filename"):
                if file_param in ep_lower:
                    ep_url = ep if ep.startswith("http") else f"{base}{ep}"
                    file_endpoints.append((ep_url, file_param))

        # Also try common patterns
        common_file_endpoints = [
            (f"{base}/download", "file"),
            (f"{base}/read", "file"),
            (f"{base}/view", "page"),
            (f"{base}/include", "file"),
            (f"{base}/static", "file"),
            (f"{base}/api/file", "path"),
        ]
        file_endpoints.extend(common_file_endpoints)

        # Deduplicate
        file_endpoints = list(set(file_endpoints))

        for ep_url, param_name in file_endpoints:
            # Get baseline to check the endpoint exists
            try:
                baseline = await self.http.get(f"{ep_url}?{param_name}=test.txt")
                if baseline.status_code == 404:
                    continue  # Endpoint doesn't exist
            except Exception:
                continue

            for payload, technique in TRAVERSAL_PAYLOADS:
                try:
                    test_url = f"{ep_url}?{urlencode({param_name: payload})}"
                    resp = await self.http.get(test_url)
                except Exception:
                    continue

                # Check for /etc/passwd content
                if resp.status_code == 200 and "root:" in resp.text:
                    self.add_finding(
                        title=f"Path Traversal via {param_name} ({technique})",
                        severity="High",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-22",
                        cwe_name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                        owasp="A01:2021 -- Broken Access Control",
                        url=test_url,
                        parameter=param_name,
                        description=(
                            f"The parameter '{param_name}' at {ep_url} is vulnerable to path traversal. "
                            f"Using the payload '{payload}' ({technique}), the contents of /etc/passwd "
                            "were successfully retrieved."
                        ),
                        steps_to_reproduce=[
                            f"Send: GET {test_url}",
                            "Observe /etc/passwd contents (lines starting with 'root:') in the response.",
                        ],
                        evidence_request=f"GET {test_url}",
                        evidence_response=resp.text[:2000],
                        impact="Arbitrary file read on the server. Attackers can access sensitive configuration files, source code, credentials, and system files.",
                        remediation="Validate and sanitize file paths. Use an allowlist of permitted files. Never pass user input directly to file system operations. Use chroot or jail the file access to a specific directory.",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cwe.mitre.org/data/definitions/22.html",
                        ],
                    )
                    return  # One traversal finding is enough
