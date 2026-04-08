"""Security headers scanner — passive analysis of HTTP response headers."""

from __future__ import annotations

import re

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding


@register_scanner
class HeadersScanner(BaseScanner):
    name = "headers"
    category = "headers"
    weight = 0.08
    active = False

    async def scan(self) -> list[Finding]:
        url = self.target.url

        try:
            response = await self.http.get(url)
        except Exception as exc:
            self.log(f"Failed to fetch {url}: {exc}")
            return self.findings

        headers = response.headers

        self._check_security_headers(url, headers)
        await self._check_cors(url)
        self._check_information_disclosure(url, headers)
        await self._check_http_methods(url)
        self._check_cookie_security(url, headers)

        return self.findings

    # ------------------------------------------------------------------
    # 1. Security Headers Check
    # ------------------------------------------------------------------

    def _check_security_headers(self, url: str, headers) -> None:
        self._check_csp(url, headers)
        self._check_x_frame_options(url, headers)
        self._check_hsts(url, headers)
        self._check_x_content_type_options(url, headers)
        self._check_referrer_policy(url, headers)
        self._check_permissions_policy(url, headers)

    def _check_csp(self, url: str, headers) -> None:
        csp = headers.get("content-security-policy", "")
        if not csp:
            self.add_finding(
                title="Missing Content-Security-Policy Header",
                severity="Medium",
                cvss_score=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-693",
                cwe_name="Protection Mechanism Failure",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                confidence="firm",
                description="The Content-Security-Policy header is missing. This header helps prevent XSS, clickjacking, and other code injection attacks.",
                impact="Without CSP, the application is more susceptible to cross-site scripting and data injection attacks.",
                remediation="Implement a strict Content-Security-Policy header that whitelists only trusted sources.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            )
            return

        # CSP exists — check for weak directives
        if "unsafe-inline" in csp and "script-src" in csp:
            self.add_finding(
                title="CSP Contains unsafe-inline in script-src",
                severity="Medium",
                cvss_score=5.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                cwe_id="CWE-693",
                cwe_name="Protection Mechanism Failure",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description="The CSP header contains 'unsafe-inline' in the script-src directive, which significantly weakens XSS protection.",
                evidence_response=f"Content-Security-Policy: {csp}",
                impact="Inline scripts are allowed, reducing the effectiveness of CSP against XSS attacks.",
                remediation="Remove 'unsafe-inline' from script-src and use nonce-based or hash-based CSP instead.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            )

        if "unsafe-eval" in csp:
            self.add_finding(
                title="CSP Contains unsafe-eval",
                severity="Medium",
                cvss_score=5.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                cwe_id="CWE-693",
                cwe_name="Protection Mechanism Failure",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description="The CSP header contains 'unsafe-eval', allowing the use of eval() and similar methods.",
                evidence_response=f"Content-Security-Policy: {csp}",
                impact="Allows dynamic code evaluation, which can be exploited for XSS attacks.",
                remediation="Remove 'unsafe-eval' from the CSP and refactor code to avoid eval().",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            )

        # Check for wildcard in source directives (not in report-uri etc.)
        directives = csp.split(";")
        for directive in directives:
            directive = directive.strip()
            if directive and " *" in directive or directive.endswith(" *"):
                parts = directive.split()
                if len(parts) >= 2 and "*" in parts[1:]:
                    self.add_finding(
                        title="CSP Contains Wildcard Source",
                        severity="Medium",
                        cvss_score=4.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-693",
                        cwe_name="Protection Mechanism Failure",
                        owasp="A05:2021 -- Security Misconfiguration",
                        url=url,
                        description=f"The CSP directive '{parts[0]}' contains a wildcard (*), allowing resources from any origin.",
                        evidence_response=f"Content-Security-Policy: {csp}",
                        impact="Any origin can serve resources for this directive, defeating the purpose of CSP.",
                        remediation="Replace wildcard sources with specific trusted domains.",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    )
                    break  # Report once

    def _check_x_frame_options(self, url: str, headers) -> None:
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp

        if not xfo and not has_frame_ancestors:
            self.add_finding(
                title="Missing X-Frame-Options Header",
                severity="Medium",
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cwe_id="CWE-1021",
                cwe_name="Improper Restriction of Rendered UI Layers or Frames",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                confidence="firm",
                description="Neither X-Frame-Options nor CSP frame-ancestors directive is set. The page may be vulnerable to clickjacking.",
                impact="Attackers can embed the page in an iframe and trick users into performing unintended actions.",
                remediation="Add the X-Frame-Options header with a value of DENY or SAMEORIGIN, or use CSP frame-ancestors directive.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
            )

    def _check_hsts(self, url: str, headers) -> None:
        # Skip HSTS check if ssl_tls scanner already handled it
        if not self.context.get("hsts_checked"):
            self._check_hsts_inner(url, headers)

    def _check_hsts_inner(self, url: str, headers) -> None:
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            self.add_finding(
                title="Missing Strict-Transport-Security Header",
                severity="Medium",
                cvss_score=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp="A02:2021 -- Cryptographic Failures",
                url=url,
                confidence="firm",
                description="The Strict-Transport-Security (HSTS) header is missing. Connections may be downgraded to HTTP.",
                impact="Users may be redirected to an unencrypted connection, allowing man-in-the-middle attacks.",
                remediation="Add the Strict-Transport-Security header with max-age of at least 31536000 (1 year) and includeSubDomains.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            )
            return

        # Check max-age value
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                self.add_finding(
                    title="HSTS max-age Is Too Short",
                    severity="Low",
                    cvss_score=3.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    owasp="A02:2021 -- Cryptographic Failures",
                    url=url,
                    description=f"HSTS max-age is set to {max_age} seconds, which is less than the recommended 31536000 (1 year).",
                    evidence_response=f"Strict-Transport-Security: {hsts}",
                    impact="Short HSTS duration increases the window for downgrade attacks after the policy expires.",
                    remediation="Set HSTS max-age to at least 31536000 (1 year).",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                )

        if "includesubdomains" not in hsts.lower():
            self.add_finding(
                title="HSTS Missing includeSubDomains Directive",
                severity="Low",
                cvss_score=2.5,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp="A02:2021 -- Cryptographic Failures",
                url=url,
                description="HSTS header does not include the includeSubDomains directive.",
                evidence_response=f"Strict-Transport-Security: {hsts}",
                impact="Subdomains are not covered by the HSTS policy and may be vulnerable to downgrade attacks.",
                remediation="Add the includeSubDomains directive to the Strict-Transport-Security header.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            )

    def _check_x_content_type_options(self, url: str, headers) -> None:
        xcto = headers.get("x-content-type-options", "")
        if not xcto or xcto.lower().strip() != "nosniff":
            self.add_finding(
                title="Missing or Incorrect X-Content-Type-Options Header",
                severity="Low",
                cvss_score=3.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cwe_id="CWE-16",
                cwe_name="Configuration",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                confidence="firm",
                description="The X-Content-Type-Options header is missing or not set to 'nosniff'. Browsers may MIME-sniff responses.",
                impact="MIME-type sniffing can lead to security issues such as XSS when the browser interprets files differently than intended.",
                remediation="Set the X-Content-Type-Options header to 'nosniff'.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
            )

    def _check_referrer_policy(self, url: str, headers) -> None:
        rp = headers.get("referrer-policy", "")
        if not rp or rp.lower().strip() == "unsafe-url":
            title = "Referrer-Policy Set to unsafe-url" if rp else "Missing Referrer-Policy Header"
            self.add_finding(
                title=title,
                severity="Low",
                cvss_score=2.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe_id="CWE-16",
                cwe_name="Configuration",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                confidence="firm",
                description="The Referrer-Policy header is missing or set to 'unsafe-url', potentially leaking sensitive URL information.",
                impact="Full URLs including query parameters may be sent to third parties via the Referer header.",
                remediation="Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
            )

    def _check_permissions_policy(self, url: str, headers) -> None:
        pp = headers.get("permissions-policy", "")
        if not pp:
            self.add_finding(
                title="Missing Permissions-Policy Header",
                severity="Low",
                cvss_score=2.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cwe_id="CWE-16",
                cwe_name="Configuration",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                confidence="firm",
                description="The Permissions-Policy header is missing. Browser features like camera, microphone, and geolocation are not restricted.",
                impact="Third-party scripts or embedded content may access powerful browser APIs without restriction.",
                remediation="Implement a Permissions-Policy header to restrict access to sensitive browser features.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
            )

    # ------------------------------------------------------------------
    # 2. CORS Analysis
    # ------------------------------------------------------------------

    async def _check_cors(self, url: str) -> None:
        try:
            response = await self.http.get(url, headers={"Origin": "https://evil.com"})
        except Exception:
            return

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower()

        if not acao:
            return

        if acao == "*" and acac == "true":
            self.add_finding(
                title="CORS Wildcard with Credentials Allowed",
                severity="High",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-942",
                cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description="CORS is configured with a wildcard Access-Control-Allow-Origin and credentials are allowed. Any origin can make authenticated requests.",
                evidence_response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                impact="Any website can make authenticated cross-origin requests, potentially stealing sensitive data.",
                remediation="Never use wildcard CORS with credentials. Implement a strict origin whitelist.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            )
        elif acao == "https://evil.com":
            self.add_finding(
                title="CORS Origin Reflected Without Validation",
                severity="High",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-942",
                cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description="The server reflects the Origin header value in Access-Control-Allow-Origin without validation. An attacker-controlled origin was accepted.",
                evidence_request="Origin: https://evil.com",
                evidence_response=f"Access-Control-Allow-Origin: {acao}",
                impact="Any attacker-controlled origin can read cross-origin responses, potentially exfiltrating sensitive data.",
                remediation="Validate the Origin header against an explicit whitelist of trusted origins.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            )
        elif acao == "null":
            self.add_finding(
                title="CORS Allows null Origin",
                severity="Medium",
                cvss_score=6.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                cwe_id="CWE-942",
                cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description="CORS is configured to allow the 'null' origin. Sandboxed iframes and data: URIs send a null origin.",
                evidence_response=f"Access-Control-Allow-Origin: {acao}",
                impact="Attackers can craft requests with a null origin using sandboxed iframes to bypass CORS restrictions.",
                remediation="Do not include 'null' in the list of allowed origins.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            )

    # ------------------------------------------------------------------
    # 3. Information Disclosure Headers
    # ------------------------------------------------------------------

    def _check_information_disclosure(self, url: str, headers) -> None:
        server = headers.get("server", "")
        if server and re.search(r"[\d]+\.[\d]+", server):
            self.add_finding(
                title="Server Header Exposes Version Information",
                severity="Low",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description=f"The Server header discloses version information: '{server}'.",
                evidence_response=f"Server: {server}",
                impact="Version information helps attackers identify known vulnerabilities for that specific software version.",
                remediation="Remove or genericize the Server header to avoid exposing version details.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )

        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            self.add_finding(
                title="X-Powered-By Header Exposes Technology Stack",
                severity="Low",
                cvss_score=3.5,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description=f"The X-Powered-By header reveals the technology stack: '{x_powered}'.",
                evidence_response=f"X-Powered-By: {x_powered}",
                impact="Technology stack information assists attackers in targeting known framework vulnerabilities.",
                remediation="Remove the X-Powered-By header from server responses.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )

        x_aspnet = headers.get("x-aspnet-version", "")
        if x_aspnet:
            self.add_finding(
                title="X-AspNet-Version Header Exposes Framework Version",
                severity="Low",
                cvss_score=3.5,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description=f"The X-AspNet-Version header reveals the ASP.NET framework version: '{x_aspnet}'.",
                evidence_response=f"X-AspNet-Version: {x_aspnet}",
                impact="Framework version disclosure helps attackers find and exploit known vulnerabilities.",
                remediation="Remove the X-AspNet-Version header by disabling it in web.config.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )

    # ------------------------------------------------------------------
    # 4. HTTP Methods
    # ------------------------------------------------------------------

    async def _check_http_methods(self, url: str) -> None:
        try:
            response = await self.http.options(url)
        except Exception:
            return

        allow = response.headers.get("allow", "")
        if not allow:
            return

        methods = [m.strip().upper() for m in allow.split(",")]

        if "TRACE" in methods:
            self.add_finding(
                title="HTTP TRACE Method Enabled",
                severity="Medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                cwe_id="CWE-693",
                cwe_name="Protection Mechanism Failure",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description="The HTTP TRACE method is enabled on the server. This can be used for Cross-Site Tracing (XST) attacks.",
                evidence_response=f"Allow: {allow}",
                impact="TRACE can reflect cookies and authentication headers, enabling credential theft via XST attacks.",
                remediation="Disable the TRACE method on the web server.",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
            )

        dangerous_on_static = {"PUT", "DELETE"}
        enabled_dangerous = dangerous_on_static.intersection(methods)
        if enabled_dangerous:
            self.add_finding(
                title=f"Dangerous HTTP Methods Enabled ({', '.join(sorted(enabled_dangerous))})",
                severity="Medium",
                cvss_score=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
                cwe_id="CWE-693",
                cwe_name="Protection Mechanism Failure",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description=f"The server allows potentially dangerous HTTP methods: {', '.join(sorted(enabled_dangerous))}.",
                evidence_response=f"Allow: {allow}",
                impact="PUT and DELETE methods on static content can allow unauthorized file upload or deletion.",
                remediation="Disable PUT and DELETE methods unless explicitly required by the application.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )

    # ------------------------------------------------------------------
    # 5. Cookie Security
    # ------------------------------------------------------------------

    def _check_cookie_security(self, url: str, headers) -> None:
        # httpx headers support getlist via get_list or iterating multi-values
        set_cookies = headers.multi_items() if hasattr(headers, "multi_items") else []
        cookie_values = [v for k, v in set_cookies if k.lower() == "set-cookie"]

        if not cookie_values:
            return

        is_https = url.startswith("https://")

        for cookie_str in cookie_values:
            # Extract cookie name
            name = cookie_str.split("=", 1)[0].strip()
            lower = cookie_str.lower()

            if "httponly" not in lower:
                self.add_finding(
                    title=f"Cookie '{name}' Missing HttpOnly Flag",
                    severity="Medium",
                    cvss_score=4.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cwe_id="CWE-1004",
                    cwe_name="Sensitive Cookie Without 'HttpOnly' Flag",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=url,
                    description=f"The cookie '{name}' does not have the HttpOnly flag set. It can be accessed via JavaScript.",
                    evidence_response=f"Set-Cookie: {cookie_str}",
                    impact="Cookies accessible to JavaScript can be stolen via XSS attacks.",
                    remediation="Add the HttpOnly flag to all session and sensitive cookies.",
                    references=["https://owasp.org/www-community/HttpOnly"],
                )

            if is_https and "secure" not in lower:
                self.add_finding(
                    title=f"Cookie '{name}' Missing Secure Flag",
                    severity="Medium",
                    cvss_score=4.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cwe_id="CWE-614",
                    cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=url,
                    description=f"The cookie '{name}' is served over HTTPS but lacks the Secure flag.",
                    evidence_response=f"Set-Cookie: {cookie_str}",
                    impact="The cookie may be transmitted over unencrypted HTTP connections, exposing it to interception.",
                    remediation="Add the Secure flag to all cookies served over HTTPS.",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                )

            if "samesite" not in lower:
                self.add_finding(
                    title=f"Cookie '{name}' Missing SameSite Attribute",
                    severity="Low",
                    cvss_score=3.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-1275",
                    cwe_name="Sensitive Cookie with Improper SameSite Attribute",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=url,
                    description=f"The cookie '{name}' does not have a SameSite attribute, making it susceptible to CSRF attacks.",
                    evidence_response=f"Set-Cookie: {cookie_str}",
                    impact="Without SameSite, cookies are sent with cross-site requests, enabling CSRF attacks.",
                    remediation="Set the SameSite attribute to 'Strict' or 'Lax' on all cookies.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                )
