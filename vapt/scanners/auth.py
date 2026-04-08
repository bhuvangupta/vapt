"""Authentication scanner — brute force, enumeration, session, JWT, password reset."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding
from vapt.utils import run_command

# Paths commonly hosting login forms
LOGIN_PATHS = ["/login", "/signin", "/auth", "/admin", "/wp-login.php"]

# Password reset paths
RESET_PATHS = [
    "/forgot-password", "/password-reset", "/reset-password",
    "/forgot", "/account/recover", "/wp-login.php?action=lostpassword",
]


@register_scanner
class AuthScanner(BaseScanner):
    name = "auth"
    category = "authentication"
    weight = 0.15
    active = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._login_url: str | None = None
        self._login_fields: dict[str, str] = {}  # field_name -> type hint
        self._username_field: str | None = None
        self._password_field: str | None = None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def scan(self) -> list[Finding]:
        await self._detect_login()

        await asyncio.gather(
            self._test_brute_force(),
            self._test_username_enum(),
            self._test_session_tokens(),
            self._test_jwt(),
            self._test_password_reset(),
        )
        return self.findings

    # ------------------------------------------------------------------
    # 1. Login Detection
    # ------------------------------------------------------------------

    async def _detect_login(self) -> None:
        try:
            await self._detect_login_inner()
        except Exception:
            pass

    async def _detect_login_inner(self) -> None:
        base = self.target.base_url

        for path in LOGIN_PATHS:
            url = f"{base}{path}"
            try:
                resp = await self.http.get(url)
            except Exception:
                continue

            if resp.status_code not in (200, 301, 302):
                continue

            body = resp.text

            # Look for forms containing password inputs
            if re.search(r'<input[^>]*type=["\']password["\']', body, re.IGNORECASE):
                self._login_url = url

                # Extract all input fields in the form
                input_pattern = re.compile(
                    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']([^"\']+)["\']',
                    re.IGNORECASE,
                )
                # Also handle type before name
                input_pattern_alt = re.compile(
                    r'<input[^>]*type=["\']([^"\']+)["\'][^>]*name=["\']([^"\']+)["\']',
                    re.IGNORECASE,
                )

                for name, input_type in input_pattern.findall(body):
                    self._login_fields[name] = input_type
                    if input_type.lower() == "password":
                        self._password_field = name
                    elif input_type.lower() in ("text", "email"):
                        self._username_field = name

                for input_type, name in input_pattern_alt.findall(body):
                    if name not in self._login_fields:
                        self._login_fields[name] = input_type
                        if input_type.lower() == "password":
                            self._password_field = name
                        elif input_type.lower() in ("text", "email"):
                            self._username_field = name

                # Defaults if not detected
                if not self._username_field:
                    self._username_field = "username"
                if not self._password_field:
                    self._password_field = "password"

                break

    # ------------------------------------------------------------------
    # 2. Brute Force Resistance
    # ------------------------------------------------------------------

    async def _test_brute_force(self) -> None:
        try:
            await self._test_brute_force_inner()
        except Exception:
            pass

    async def _test_brute_force_inner(self) -> None:
        if not self._login_url:
            return

        username_field = self._username_field or "username"
        password_field = self._password_field or "password"

        statuses: list[int] = []
        bodies: list[str] = []
        has_rate_limit = False
        has_lockout = False
        has_captcha = False

        for i in range(10):
            data = {
                username_field: "admin",
                password_field: f"wrongpassword{i}",
            }
            try:
                resp = await self.http.post(self._login_url, data=data)
                statuses.append(resp.status_code)
                bodies.append(resp.text)

                if resp.status_code == 429:
                    has_rate_limit = True
                    break

                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ["locked", "lockout", "too many attempts", "account disabled"]):
                    has_lockout = True
                    break

                if any(kw in body_lower for kw in ["captcha", "recaptcha", "hcaptcha", "challenge"]):
                    has_captcha = True
                    break

            except Exception:
                continue

        if not has_rate_limit and not has_lockout and not has_captcha and len(statuses) >= 10:
            # Check if error messages changed (adaptive response)
            unique_bodies = set(b[:500] for b in bodies)
            if len(unique_bodies) <= 2:
                self.add_finding(
                    title="No Brute Force Protection on Login",
                    severity="High",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-307",
                    cwe_name="Improper Restriction of Excessive Authentication Attempts",
                    owasp="A07:2021 -- Identification and Authentication Failures",
                    url=self._login_url,
                    parameter=username_field,
                    description=(
                        "The login form accepts unlimited authentication attempts without rate limiting, "
                        "account lockout, or CAPTCHA challenge. 10 rapid failed login attempts were "
                        "accepted without any protective response."
                    ),
                    steps_to_reproduce=[
                        f"Navigate to {self._login_url}",
                        "Submit 10 consecutive login attempts with wrong passwords.",
                        "Observe that no rate limiting, lockout, or CAPTCHA is triggered.",
                    ],
                    evidence_request=f"POST {self._login_url} (10 rapid attempts)",
                    evidence_response=f"Statuses: {statuses}",
                    impact="Attackers can perform credential stuffing or brute force attacks to gain unauthorized access to user accounts.",
                    remediation="Implement rate limiting (e.g., max 5 attempts per minute), progressive delays, account lockout after N failures, and CAPTCHA after repeated failures.",
                    references=[
                        "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    ],
                )

    # ------------------------------------------------------------------
    # 3. Username Enumeration
    # ------------------------------------------------------------------

    async def _test_username_enum(self) -> None:
        try:
            await self._test_username_enum_inner()
        except Exception:
            pass

    async def _test_username_enum_inner(self) -> None:
        if not self._login_url:
            return

        username_field = self._username_field or "username"
        password_field = self._password_field or "password"

        # Test with valid-looking username
        valid_data = {username_field: "admin", password_field: "wrongpassword123"}
        # Test with clearly invalid username
        invalid_data = {username_field: "xq9z_nonexistent_user_8k2m", password_field: "wrongpassword123"}

        try:
            start_valid = time.monotonic()
            resp_valid = await self.http.post(self._login_url, data=valid_data)
            time_valid = time.monotonic() - start_valid

            start_invalid = time.monotonic()
            resp_invalid = await self.http.post(self._login_url, data=invalid_data)
            time_invalid = time.monotonic() - start_invalid
        except Exception:
            return

        differences: list[str] = []

        # Compare response body length
        len_diff = abs(len(resp_valid.text) - len(resp_invalid.text))
        if len_diff > 50:
            differences.append(f"Response length differs by {len_diff} bytes")

        # Compare status codes
        if resp_valid.status_code != resp_invalid.status_code:
            differences.append(
                f"Status codes differ: {resp_valid.status_code} vs {resp_invalid.status_code}"
            )

        # Compare response time
        time_diff = abs(time_valid - time_invalid)
        if time_diff > 0.5:
            differences.append(f"Response time differs by {time_diff:.2f}s")

        # Check for specific enumeration messages
        enum_patterns = [
            "user not found", "no such user", "invalid username",
            "account does not exist", "username is incorrect",
            "email not found", "unknown user",
        ]
        valid_lower = resp_valid.text.lower()
        invalid_lower = resp_invalid.text.lower()

        for pattern in enum_patterns:
            in_valid = pattern in valid_lower
            in_invalid = pattern in invalid_lower
            if in_valid != in_invalid:
                differences.append(f"Enumeration message detected: '{pattern}'")
                break

        if differences:
            self.add_finding(
                title="Username Enumeration via Login Response Differences",
                severity="Low",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-203",
                cwe_name="Observable Discrepancy",
                owasp="A07:2021 -- Identification and Authentication Failures",
                url=self._login_url,
                parameter=username_field,
                description=(
                    "The login form reveals whether a username exists by returning "
                    "different responses for valid vs. invalid usernames.\n"
                    "Observed differences:\n" + "\n".join(f"  - {d}" for d in differences)
                ),
                steps_to_reproduce=[
                    f"POST to {self._login_url} with username='admin' and a wrong password.",
                    f"POST to {self._login_url} with username='xq9z_nonexistent_user_8k2m' and a wrong password.",
                    "Compare the responses for differences.",
                ],
                evidence_request=f"POST {self._login_url} (valid vs invalid username)",
                evidence_response=f"Valid user response length: {len(resp_valid.text)}, Invalid user response length: {len(resp_invalid.text)}",
                impact="Attackers can enumerate valid usernames to target in brute force or credential stuffing attacks.",
                remediation="Return identical responses for valid and invalid usernames. Use generic messages like 'Invalid credentials'. Ensure consistent response times.",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                ],
            )

    # ------------------------------------------------------------------
    # 4. Session Token Analysis
    # ------------------------------------------------------------------

    async def _test_session_tokens(self) -> None:
        try:
            await self._test_session_tokens_inner()
        except Exception:
            pass

    async def _test_session_tokens_inner(self) -> None:
        try:
            resp = await self.http.get(self.target.url)
        except Exception:
            return

        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        # httpx uses headers.get_list or we can iterate
        if not cookies:
            # Try alternate approach
            cookies = [
                v for k, v in resp.headers.multi_items()
                if k.lower() == "set-cookie"
            ]

        if not cookies:
            return

        for cookie_str in cookies:
            # Parse cookie name and value
            parts = cookie_str.split(";")
            if not parts:
                continue

            name_value = parts[0].strip()
            if "=" not in name_value:
                continue

            cookie_name, cookie_value = name_value.split("=", 1)
            cookie_name = cookie_name.strip()
            cookie_value = cookie_value.strip()

            # Skip non-session cookies (short values, tracking pixels, etc.)
            if len(cookie_value) < 8:
                continue

            cookie_lower = cookie_str.lower()
            flag_issues: list[str] = []

            # Check token length
            if len(cookie_value) < 16:
                self.add_finding(
                    title=f"Short Session Token: {cookie_name}",
                    severity="Medium",
                    cvss_score=5.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-330",
                    cwe_name="Use of Insufficiently Random Values",
                    owasp="A07:2021 -- Identification and Authentication Failures",
                    url=self.target.url,
                    parameter=cookie_name,
                    description=(
                        f"Session cookie '{cookie_name}' has a value of only "
                        f"{len(cookie_value)} characters, which may be brute-forceable."
                    ),
                    steps_to_reproduce=[
                        f"Send a GET request to {self.target.url}",
                        f"Examine the Set-Cookie header for '{cookie_name}'.",
                        f"Observe the token length: {len(cookie_value)} characters.",
                    ],
                    evidence_response=f"Set-Cookie: {cookie_name}={cookie_value[:20]}...",
                    impact="Short session tokens can be brute-forced, allowing session hijacking.",
                    remediation="Use session tokens of at least 128 bits (32 hex characters) generated by a cryptographically secure random number generator.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                    ],
                )

            # Check randomness (is it hex or base64?)
            is_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', cookie_value))
            is_b64 = bool(re.fullmatch(r'[A-Za-z0-9+/=]+', cookie_value))
            if not is_hex and not is_b64:
                flag_issues.append("Token does not appear to be hex or base64 encoded (possibly predictable)")

            # Check cookie flags
            if "httponly" not in cookie_lower:
                flag_issues.append("Missing HttpOnly flag (cookie accessible via JavaScript)")
            if "secure" not in cookie_lower:
                flag_issues.append("Missing Secure flag (cookie sent over unencrypted connections)")
            if "samesite" not in cookie_lower:
                flag_issues.append("Missing SameSite attribute (vulnerable to CSRF)")

            if flag_issues:
                self.add_finding(
                    title=f"Insecure Session Cookie Flags: {cookie_name}",
                    severity="Medium",
                    cvss_score=4.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cwe_id="CWE-614",
                    cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                    owasp="A07:2021 -- Identification and Authentication Failures",
                    url=self.target.url,
                    parameter=cookie_name,
                    description=(
                        f"Session cookie '{cookie_name}' is missing security flags:\n"
                        + "\n".join(f"  - {issue}" for issue in flag_issues)
                    ),
                    steps_to_reproduce=[
                        f"Send a GET request to {self.target.url}",
                        f"Examine the Set-Cookie header for '{cookie_name}'.",
                        "Note the missing security flags.",
                    ],
                    evidence_response=f"Set-Cookie: {cookie_str[:200]}",
                    impact="Missing cookie flags can lead to session hijacking via XSS (no HttpOnly), network interception (no Secure), or CSRF attacks (no SameSite).",
                    remediation="Set HttpOnly, Secure, and SameSite=Strict (or Lax) flags on all session cookies.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    ],
                )

    # ------------------------------------------------------------------
    # 5. JWT Analysis
    # ------------------------------------------------------------------

    async def _test_jwt(self) -> None:
        try:
            await self._test_jwt_inner()
        except Exception:
            pass

    async def _test_jwt_inner(self) -> None:
        try:
            resp = await self.http.get(self.target.url)
        except Exception:
            return

        jwt_tokens: list[tuple[str, str]] = []  # (location, token)

        # Check cookies
        cookie_headers = [
            v for k, v in resp.headers.multi_items()
            if k.lower() == "set-cookie"
        ]
        for cookie_str in cookie_headers:
            name_value = cookie_str.split(";")[0].strip()
            if "=" in name_value:
                _, value = name_value.split("=", 1)
                if self._is_jwt(value.strip()):
                    jwt_tokens.append(("cookie", value.strip()))

        # Check Authorization-like response headers
        for header_name in ("authorization", "x-auth-token", "x-access-token"):
            value = resp.headers.get(header_name, "")
            token = value.replace("Bearer ", "").strip()
            if self._is_jwt(token):
                jwt_tokens.append((header_name, token))

        # Check response body for JWT patterns
        body = resp.text
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        for match in jwt_pattern.findall(body):
            jwt_tokens.append(("response body", match))

        # Also check if target has auth and we can get a JWT from login
        if not jwt_tokens and self.target.has_auth() and self._login_url:
            auth = self.target.auth or {}
            login_data = {
                self._username_field or "username": auth.get("username", ""),
                self._password_field or "password": auth.get("password", ""),
            }
            try:
                login_resp = await self.http.post(self._login_url, data=login_data)
                # Check response body
                for match in jwt_pattern.findall(login_resp.text):
                    jwt_tokens.append(("login response", match))
                # Check response headers
                for header_name in ("authorization", "x-auth-token", "x-access-token"):
                    value = login_resp.headers.get(header_name, "")
                    token = value.replace("Bearer ", "").strip()
                    if self._is_jwt(token):
                        jwt_tokens.append((header_name, token))
            except Exception:
                pass

        # Analyze each JWT found
        for location, token in jwt_tokens:
            self._analyze_jwt(location, token)

    def _is_jwt(self, value: str) -> bool:
        """Check if a string looks like a JWT (three base64url-encoded segments starting with eyJ)."""
        parts = value.split(".")
        if len(parts) != 3:
            return False
        return parts[0].startswith("eyJ") and parts[1].startswith("eyJ")

    def _b64_decode(self, segment: str) -> dict | None:
        """Decode a JWT base64url segment to dict."""
        try:
            # Add padding
            padded = segment + "=" * (4 - len(segment) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return None

    def _analyze_jwt(self, location: str, token: str) -> None:
        """Analyze a JWT for common security issues."""
        parts = token.split(".")
        header = self._b64_decode(parts[0])
        payload = self._b64_decode(parts[1])

        if not header or not payload:
            return

        alg = header.get("alg", "unknown")

        # Check for alg:none vulnerability
        if alg.lower() in ("none", ""):
            self.add_finding(
                title="JWT Algorithm None Accepted",
                severity="Critical",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-347",
                cwe_name="Improper Verification of Cryptographic Signature",
                owasp="A07:2021 -- Identification and Authentication Failures",
                url=self.target.url,
                parameter=f"JWT in {location}",
                description=(
                    f"A JWT token found in {location} uses algorithm '{alg}'. "
                    "The 'none' algorithm means the token signature is not verified, "
                    "allowing attackers to forge arbitrary tokens."
                ),
                steps_to_reproduce=[
                    f"Extract the JWT from {location}.",
                    "Decode the header: " + json.dumps(header),
                    "Observe alg is set to 'none'.",
                    "Modify the payload and re-encode without signature.",
                ],
                evidence_response=f"JWT header: {json.dumps(header)}",
                impact="Complete authentication bypass. Any user can forge tokens to impersonate any other user, including administrators.",
                remediation="Enforce a strong signing algorithm (RS256 or ES256). Reject tokens with alg:none. Validate signatures server-side.",
                references=[
                    "https://portswigger.net/web-security/jwt",
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                ],
            )

        # Check for missing exp claim
        if "exp" not in payload:
            self.add_finding(
                title="JWT Missing Expiration Claim",
                severity="Medium",
                cvss_score=5.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                cwe_id="CWE-613",
                cwe_name="Insufficient Session Expiration",
                owasp="A07:2021 -- Identification and Authentication Failures",
                url=self.target.url,
                parameter=f"JWT in {location}",
                description=(
                    f"A JWT token found in {location} does not contain an 'exp' (expiration) claim. "
                    "This means the token never expires and remains valid indefinitely."
                ),
                steps_to_reproduce=[
                    f"Extract the JWT from {location}.",
                    "Decode the payload: " + json.dumps(payload),
                    "Observe there is no 'exp' field.",
                ],
                evidence_response=f"JWT payload keys: {list(payload.keys())}",
                impact="Stolen tokens remain valid forever, giving attackers persistent access.",
                remediation="Always include an 'exp' claim with a reasonable expiration time. Implement token refresh mechanisms.",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                ],
            )

        # Check for sensitive data in payload
        sensitive_keys = ["password", "passwd", "pwd", "ssn", "credit", "card_number", "secret"]
        found_sensitive = [
            k for k in payload.keys()
            if any(s in k.lower() for s in sensitive_keys)
        ]

        if found_sensitive:
            self.add_finding(
                title="Sensitive Data in JWT Payload",
                severity="Medium",
                cvss_score=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-315",
                cwe_name="Cleartext Storage of Sensitive Information in a Cookie",
                owasp="A02:2021 -- Cryptographic Failures",
                url=self.target.url,
                parameter=f"JWT in {location}",
                description=(
                    f"The JWT token found in {location} contains potentially sensitive fields: "
                    f"{', '.join(found_sensitive)}. JWT payloads are base64-encoded (not encrypted) "
                    "and can be trivially decoded by anyone."
                ),
                steps_to_reproduce=[
                    f"Extract the JWT from {location}.",
                    "Base64-decode the payload segment.",
                    f"Observe sensitive fields: {', '.join(found_sensitive)}.",
                ],
                evidence_response=f"JWT payload keys: {list(payload.keys())}",
                impact="Sensitive data exposed in JWT tokens can be read by anyone who intercepts the token.",
                remediation="Never store sensitive data in JWT payloads. Use JWE (encrypted JWT) if payload confidentiality is needed. Store sensitive data server-side referenced by opaque identifiers.",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                ],
            )

    # ------------------------------------------------------------------
    # 6. Password Reset
    # ------------------------------------------------------------------

    async def _test_password_reset(self) -> None:
        try:
            await self._test_password_reset_inner()
        except Exception:
            pass

    async def _test_password_reset_inner(self) -> None:
        base = self.target.base_url
        reset_url: str | None = None

        # Soft-404 baseline
        baseline_body = await self.fetch_soft404_baseline()

        # Find password reset page
        for path in RESET_PATHS:
            url = f"{base}{path}"
            try:
                resp = await self.http.get(url)
                if resp.status_code == 200:
                    # Filter soft-404 pages
                    if self.is_soft_404(resp.text, baseline_body):
                        continue
                    body_lower = resp.text.lower()
                    if any(kw in body_lower for kw in ["email", "reset", "forgot", "recover"]):
                        reset_url = url
                        break
            except Exception:
                continue

        if not reset_url:
            return

        # Find email field
        try:
            resp = await self.http.get(reset_url)
            body = resp.text
        except Exception:
            return

        email_field = "email"
        input_match = re.search(
            r'<input[^>]*name=["\']([^"\']*(?:email|mail|user)[^"\']*)["\']',
            body, re.IGNORECASE,
        )
        if input_match:
            email_field = input_match.group(1)

        # Test enumeration via response differences
        try:
            resp_valid = await self.http.post(
                reset_url, data={email_field: "admin@" + self.target.domain}
            )
            resp_invalid = await self.http.post(
                reset_url, data={email_field: "xq9z_nonexistent_8k2m@example.com"}
            )

            len_diff = abs(len(resp_valid.text) - len(resp_invalid.text))
            status_diff = resp_valid.status_code != resp_invalid.status_code
            body_diff = resp_valid.text.strip() != resp_invalid.text.strip()

            if (len_diff > 50 or status_diff) and body_diff:
                self.add_finding(
                    title="User Enumeration via Password Reset",
                    severity="Low",
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-203",
                    cwe_name="Observable Discrepancy",
                    owasp="A07:2021 -- Identification and Authentication Failures",
                    url=reset_url,
                    parameter=email_field,
                    description=(
                        "The password reset form returns different responses for valid vs. invalid "
                        f"email addresses (length diff: {len_diff} bytes, "
                        f"status diff: {status_diff})."
                    ),
                    steps_to_reproduce=[
                        f"POST to {reset_url} with a valid-looking email.",
                        f"POST to {reset_url} with a clearly invalid email.",
                        "Compare the responses.",
                    ],
                    evidence_request=f"POST {reset_url}",
                    evidence_response=f"Valid email response: {len(resp_valid.text)} bytes (HTTP {resp_valid.status_code}), Invalid: {len(resp_invalid.text)} bytes (HTTP {resp_invalid.status_code})",
                    impact="Attackers can enumerate valid email addresses/usernames via the password reset form.",
                    remediation="Always return the same response regardless of whether the email exists. Use a generic message like 'If the email exists, a reset link has been sent.'",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
                    ],
                )
        except Exception:
            pass

        # Test rate limiting on password reset
        try:
            statuses: list[int] = []
            for _ in range(10):
                resp = await self.http.post(
                    reset_url, data={email_field: "test@" + self.target.domain}
                )
                statuses.append(resp.status_code)
                if resp.status_code == 429:
                    break

            if 429 not in statuses and len(statuses) >= 10:
                self.add_finding(
                    title="No Rate Limiting on Password Reset",
                    severity="Medium",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
                    cwe_id="CWE-307",
                    cwe_name="Improper Restriction of Excessive Authentication Attempts",
                    owasp="A07:2021 -- Identification and Authentication Failures",
                    url=reset_url,
                    parameter=email_field,
                    description=(
                        "The password reset endpoint accepts unlimited requests without rate limiting. "
                        "10 rapid requests were accepted without throttling."
                    ),
                    steps_to_reproduce=[
                        f"Send 10 rapid POST requests to {reset_url}.",
                        "Observe that no rate limiting (HTTP 429) is enforced.",
                    ],
                    evidence_request=f"POST {reset_url} (10 rapid requests)",
                    evidence_response=f"Statuses: {statuses}",
                    impact="Attackers can abuse the password reset function to spam users with reset emails, enumerate accounts, or attempt reset token brute force.",
                    remediation="Implement rate limiting on the password reset endpoint (e.g., max 3 requests per email per hour).",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
                    ],
                )
        except Exception:
            pass
