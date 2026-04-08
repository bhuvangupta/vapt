"""Logic scanner — active business logic tests: race conditions, numeric boundaries, workflow bypass, idempotency."""

from __future__ import annotations

import asyncio
import json

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding

# Numeric boundary test values grouped by intent
BOUNDARY_NEGATIVE = [-1, -100]
BOUNDARY_ZERO = [0]
BOUNDARY_EXTREME = [99999999, 2147483647]
BOUNDARY_DECIMAL = [0.001, 0.0001]

# Parameters that commonly accept numeric values
NUMERIC_PARAMS = ["quantity", "amount", "price", "count", "qty", "num", "total", "value"]

# Common multi-step process indicators
STEP_PARAMS = ["step", "page", "stage", "phase", "wizard_step", "current_step"]


@register_scanner
class LogicScanner(BaseScanner):
    name = "logic"
    category = "logic"
    weight = 0.05
    active = True

    async def scan(self) -> list[Finding]:
        await asyncio.gather(
            self._race_condition(),
            self._numeric_boundary(),
            self._workflow_bypass(),
            self._idempotency_check(),
        )
        return self.findings

    # ------------------------------------------------------------------
    # 1. Race Condition
    # ------------------------------------------------------------------

    async def _race_condition(self) -> None:
        """Send concurrent identical POST requests to detect race conditions."""
        try:
            # Gather POST endpoints from context (discovered by API scanner or forms)
            post_endpoints = self._get_post_endpoints()
            if not post_endpoints:
                return

            auth_headers = self._build_auth_headers()
            concurrent_count = 10

            for ep in post_endpoints:
                url = ep["url"]
                payload = ep.get("payload", {})

                async def send_request() -> tuple[int, str]:
                    try:
                        resp = await self.http.post(
                            url, json=payload, headers=auth_headers,
                        )
                        return resp.status_code, resp.text[:500]
                    except Exception:
                        return 0, ""

                results = await asyncio.gather(*(send_request() for _ in range(concurrent_count)))

                success_count = sum(1 for status, _ in results if status in (200, 201))
                error_count = sum(1 for status, _ in results if status >= 400)
                response_bodies = [body for _, body in results if body]

                # If most/all requests succeeded and this is a one-time operation, flag it
                if success_count >= concurrent_count * 0.8:
                    self.add_finding(
                        title=f"Potential Race Condition: {ep.get('path', url)}",
                        severity="Medium",
                        cvss_score=5.3,
                        confidence="tentative",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        cwe_id="CWE-362",
                        cwe_name="Concurrent Execution using Shared Resource with Improper Synchronization",
                        owasp="A04:2021 -- Insecure Design",
                        url=url,
                        description=(
                            f"Sent {concurrent_count} concurrent identical POST requests to {ep.get('path', url)}. "
                            f"{success_count} returned success (200/201), suggesting the endpoint does not "
                            "enforce atomicity or locking for state-changing operations."
                        ),
                        steps_to_reproduce=[
                            f"Authenticate and prepare a POST request to {url}",
                            f"Send {concurrent_count} identical requests concurrently",
                            f"Observe that {success_count}/{concurrent_count} requests succeeded",
                        ],
                        evidence_request=json.dumps(payload, indent=2)[:1000] if payload else f"POST {url}",
                        evidence_response=(
                            f"Successes: {success_count}/{concurrent_count}, "
                            f"Errors: {error_count}/{concurrent_count}\n"
                            f"Sample response: {response_bodies[0][:500] if response_bodies else 'N/A'}"
                        ),
                        impact=(
                            "Race conditions allow attackers to duplicate one-time operations such as "
                            "coupon redemption, fund transfers, or vote submissions. This can lead to "
                            "financial loss and data integrity issues."
                        ),
                        remediation=(
                            "Implement proper locking mechanisms (database-level locks, optimistic concurrency "
                            "control, or idempotency keys). Use transactions to ensure atomicity of "
                            "state-changing operations."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Race_Condition",
                            "https://portswigger.net/web-security/race-conditions",
                        ],
                    )
        except Exception:
            self.log("Race condition test failed")

    # ------------------------------------------------------------------
    # 2. Numeric Boundary
    # ------------------------------------------------------------------

    async def _numeric_boundary(self) -> None:
        """Test numeric parameters with boundary values (negative, zero, extreme, decimal)."""
        try:
            api_endpoints = self.context.get("api_endpoints", [])
            forms = self.context.get("forms", [])
            if not api_endpoints and not forms:
                return

            auth_headers = self._build_auth_headers()
            base = self.target.base_url

            # Build test URLs from API endpoints
            test_targets: list[str] = []
            for ep in api_endpoints:
                if ep["status"] == 200 and any(kw in ep["path"] for kw in ("/cart", "/order", "/purchase", "/checkout", "/payment", "/transfer")):
                    test_targets.append(ep["url"])

            # Fallback: test common e-commerce/financial endpoints
            if not test_targets:
                test_targets = [
                    f"{base}/api/cart",
                    f"{base}/api/orders",
                    f"{base}/api/checkout",
                ]

            for url in test_targets:
                for param in NUMERIC_PARAMS:
                    # Test negative values
                    for neg_val in BOUNDARY_NEGATIVE:
                        try:
                            resp = await self.http.post(
                                url, json={param: neg_val}, headers=auth_headers,
                            )
                            if resp.status_code in (200, 201):
                                body = resp.text.lower()
                                # Check for signs that negative value was processed (credit, refund, etc.)
                                if any(kw in body for kw in ("credit", "refund", "success", "created", "processed")):
                                    self.add_finding(
                                        title=f"Negative Value Accepted: {param}={neg_val}",
                                        severity="High",
                                        cvss_score=8.1,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
                                        cwe_id="CWE-20",
                                        cwe_name="Improper Input Validation",
                                        owasp="A04:2021 -- Insecure Design",
                                        url=url,
                                        parameter=param,
                                        description=(
                                            f"The API accepted a negative value ({neg_val}) for parameter '{param}' "
                                            "and processed it successfully. This may allow attackers to generate "
                                            "credits, refunds, or reverse transactions."
                                        ),
                                        steps_to_reproduce=[
                                            f"Send POST {url} with body: {json.dumps({param: neg_val})}",
                                            "Observe the request is processed successfully",
                                        ],
                                        evidence_request=json.dumps({param: neg_val}),
                                        evidence_response=resp.text[:2000],
                                        impact=(
                                            "Negative value processing can lead to unauthorized credits, "
                                            "balance manipulation, and financial fraud."
                                        ),
                                        remediation=(
                                            "Validate all numeric inputs server-side. Enforce minimum value "
                                            "constraints (e.g., quantity >= 1). Reject negative values for "
                                            "fields that must be positive."
                                        ),
                                        references=[
                                            "https://owasp.org/www-project-web-security-testing-guide/",
                                        ],
                                    )
                                    break  # One finding per param is enough
                        except Exception:
                            continue

                    # Test extreme values for server errors
                    for extreme_val in BOUNDARY_EXTREME:
                        try:
                            resp = await self.http.post(
                                url, json={param: extreme_val}, headers=auth_headers,
                            )
                            if resp.status_code >= 500:
                                self.add_finding(
                                    title=f"Server Error on Extreme Value: {param}={extreme_val}",
                                    severity="Medium",
                                    cvss_score=5.5,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L",
                                    cwe_id="CWE-20",
                                    cwe_name="Improper Input Validation",
                                    owasp="A04:2021 -- Insecure Design",
                                    url=url,
                                    parameter=param,
                                    description=(
                                        f"The API returned a server error (HTTP {resp.status_code}) when "
                                        f"parameter '{param}' was set to extreme value {extreme_val}. "
                                        "This indicates missing input validation and potential integer overflow."
                                    ),
                                    steps_to_reproduce=[
                                        f"Send POST {url} with body: {json.dumps({param: extreme_val})}",
                                        f"Observe HTTP {resp.status_code} server error",
                                    ],
                                    evidence_request=json.dumps({param: extreme_val}),
                                    evidence_response=resp.text[:2000],
                                    impact=(
                                        "Extreme values can cause integer overflow, application crashes, "
                                        "or unexpected behavior that may be exploitable."
                                    ),
                                    remediation=(
                                        "Validate numeric input ranges server-side. Set maximum allowed "
                                        "values and return proper 400 errors for out-of-range input."
                                    ),
                                    references=[
                                        "https://owasp.org/www-project-web-security-testing-guide/",
                                    ],
                                )
                                break  # One finding per param is enough
                        except Exception:
                            continue
        except Exception:
            self.log("Numeric boundary test failed")

    # ------------------------------------------------------------------
    # 3. Workflow Bypass
    # ------------------------------------------------------------------

    async def _workflow_bypass(self) -> None:
        """Attempt to skip steps in multi-step workflows."""
        try:
            forms = self.context.get("forms", [])
            api_endpoints = self.context.get("api_endpoints", [])
            auth_headers = self._build_auth_headers()
            base = self.target.base_url

            # Detect multi-step endpoints from context
            step_endpoints: list[dict] = []

            for ep in api_endpoints:
                path = ep.get("path", "")
                if any(sp in path.lower() for sp in STEP_PARAMS):
                    step_endpoints.append(ep)

            # Also check forms for step parameters
            for form in forms:
                action = form.get("action", "")
                fields = form.get("fields", {})
                if any(sp in str(fields).lower() for sp in STEP_PARAMS):
                    step_endpoints.append({
                        "url": action if action.startswith("http") else f"{base}{action}",
                        "path": action,
                        "fields": fields,
                    })

            # Fallback: try common multi-step patterns
            if not step_endpoints:
                common_multistep = [
                    "/checkout", "/register", "/signup", "/onboarding",
                    "/wizard", "/application", "/enrollment",
                ]
                for path in common_multistep:
                    step_endpoints.append({
                        "url": f"{base}{path}",
                        "path": path,
                    })

            for ep in step_endpoints:
                url = ep["url"]

                # Try skipping to the final step directly
                for final_step in [3, 4, 5, "final", "complete", "submit"]:
                    for param in STEP_PARAMS:
                        try:
                            payload = {param: final_step}
                            resp = await self.http.post(
                                url, json=payload, headers=auth_headers,
                            )

                            if resp.status_code in (200, 201):
                                body = resp.text.lower()
                                # Check for signs of successful completion
                                if any(kw in body for kw in (
                                    "success", "complete", "confirmed", "thank you",
                                    "order placed", "registration complete",
                                )):
                                    self.add_finding(
                                        title=f"Workflow Bypass: {ep.get('path', url)}",
                                        severity="Medium",
                                        cvss_score=5.3,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
                                        cwe_id="CWE-841",
                                        cwe_name="Improper Enforcement of Behavioral Workflow",
                                        owasp="A04:2021 -- Insecure Design",
                                        url=url,
                                        parameter=param,
                                        confidence="tentative",
                                        description=(
                                            f"A multi-step workflow at {ep.get('path', url)} was bypassed by "
                                            f"directly submitting {param}={final_step} without completing "
                                            "prior steps. The server did not enforce sequential step completion. "
                                            "This is a heuristic detection based on success keywords in the "
                                            "response. Manual verification is required to confirm the workflow "
                                            "was actually bypassed."
                                        ),
                                        steps_to_reproduce=[
                                            f"Send POST {url} with body: {json.dumps(payload)}",
                                            "Skip steps 1 and 2 entirely",
                                            "Observe the final step is processed successfully",
                                        ],
                                        evidence_request=json.dumps(payload),
                                        evidence_response=resp.text[:2000],
                                        impact=(
                                            "Workflow bypass allows attackers to skip validation steps, "
                                            "payment verification, identity checks, or approval processes "
                                            "in multi-step business flows."
                                        ),
                                        remediation=(
                                            "Enforce step sequence on the server side using session-based "
                                            "state tracking. Validate that each step is completed before "
                                            "allowing the next. Use cryptographic tokens to prevent step tampering."
                                        ),
                                        references=[
                                            "https://owasp.org/www-project-web-security-testing-guide/",
                                        ],
                                    )
                                    return  # One workflow bypass finding is sufficient
                        except Exception:
                            continue
        except Exception:
            self.log("Workflow bypass test failed")

    # ------------------------------------------------------------------
    # 4. Idempotency Check
    # ------------------------------------------------------------------

    async def _idempotency_check(self) -> None:
        """Submit the same POST request twice rapidly to detect duplicate processing."""
        try:
            post_endpoints = self._get_post_endpoints()
            if not post_endpoints:
                return

            auth_headers = self._build_auth_headers()

            for ep in post_endpoints:
                url = ep["url"]
                payload = ep.get("payload", {})
                is_payment = any(kw in ep.get("path", "").lower() for kw in (
                    "payment", "pay", "charge", "transfer", "transaction",
                ))

                try:
                    # Send two identical requests rapidly
                    resp_1, resp_2 = await asyncio.gather(
                        self.http.post(url, json=payload, headers=auth_headers),
                        self.http.post(url, json=payload, headers=auth_headers),
                    )
                except Exception:
                    continue

                both_success = (
                    resp_1.status_code in (200, 201) and
                    resp_2.status_code in (200, 201)
                )

                if not both_success:
                    continue

                # Check if both created new resources (duplicate)
                try:
                    data_1 = resp_1.json()
                    data_2 = resp_2.json()
                except Exception:
                    data_1 = resp_1.text
                    data_2 = resp_2.text

                # If both responses are identical, the server may be idempotent (good)
                # If they differ (different IDs), duplicates were created (bad)
                responses_differ = data_1 != data_2
                different_ids = False

                if isinstance(data_1, dict) and isinstance(data_2, dict):
                    id_1 = data_1.get("id") or data_1.get("order_id") or data_1.get("transaction_id")
                    id_2 = data_2.get("id") or data_2.get("order_id") or data_2.get("transaction_id")
                    if id_1 and id_2 and id_1 != id_2:
                        different_ids = True

                if different_ids or (responses_differ and both_success):
                    severity = "Critical" if is_payment else "Medium"
                    cvss = 9.1 if is_payment else 5.0
                    cwe_id = "CWE-837"
                    cwe_name = "Improper Enforcement of a Single, Unique Action"

                    self.add_finding(
                        title=f"{'Duplicate Payment Processed' if is_payment else 'Duplicate Resource Created'}: {ep.get('path', url)}",
                        severity=severity,
                        cvss_score=cvss,
                        cvss_vector=(
                            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
                            if is_payment
                            else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N"
                        ),
                        cwe_id=cwe_id,
                        cwe_name=cwe_name,
                        owasp="A04:2021 -- Insecure Design",
                        url=url,
                        description=(
                            f"Two identical POST requests to {ep.get('path', url)} both succeeded, "
                            + (
                                "processing the same payment twice. "
                                "This can lead to double charges and financial loss."
                                if is_payment
                                else "creating duplicate resources. "
                                "The server does not enforce idempotency."
                            )
                        ),
                        steps_to_reproduce=[
                            f"Send POST {url} with payload: {json.dumps(payload)[:500]}",
                            "Immediately send the identical request again",
                            "Observe that both requests create separate resources",
                        ],
                        evidence_request=json.dumps(payload, indent=2)[:1000] if payload else f"POST {url}",
                        evidence_response=(
                            f"Response 1: {json.dumps(data_1, indent=2)[:800] if isinstance(data_1, dict) else str(data_1)[:800]}\n"
                            f"Response 2: {json.dumps(data_2, indent=2)[:800] if isinstance(data_2, dict) else str(data_2)[:800]}"
                        ),
                        impact=(
                            "Duplicate payment processing causes financial loss and customer disputes."
                            if is_payment
                            else "Duplicate resource creation leads to data integrity issues and inconsistent state."
                        ),
                        remediation=(
                            "Implement idempotency keys for all state-changing operations. "
                            "Require a unique Idempotency-Key header on POST requests and "
                            "return the cached response for duplicate keys. Use database unique "
                            "constraints to prevent duplicate records."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/",
                            "https://stripe.com/docs/api/idempotent_requests",
                        ],
                    )
        except Exception:
            self.log("Idempotency check failed")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_post_endpoints(self) -> list[dict]:
        """Collect POST-capable endpoints from context."""
        endpoints: list[dict] = []

        # From API discovery
        for ep in self.context.get("api_endpoints", []):
            if ep.get("status") == 200:
                path = ep.get("path", "")
                # Select endpoints that are likely state-changing
                if any(kw in path.lower() for kw in (
                    "redeem", "coupon", "voucher", "order", "purchase",
                    "payment", "transfer", "submit", "create", "add",
                    "cart", "checkout", "register", "apply",
                )):
                    endpoints.append(ep)

        # From forms context
        for form in self.context.get("forms", []):
            if form.get("method", "").upper() == "POST":
                action = form.get("action", "")
                base = self.target.base_url
                url = action if action.startswith("http") else f"{base}{action}"
                endpoints.append({
                    "url": url,
                    "path": action,
                    "payload": form.get("fields", {}),
                })

        return endpoints

    def _build_auth_headers(self) -> dict:
        """Build authentication headers from target auth config."""
        headers: dict[str, str] = {}
        if not self.target.has_auth():
            return headers

        auth = self.target.auth
        if auth.get("api_key"):
            header_name = auth.get("token_header", "Authorization")
            headers[header_name] = auth["api_key"]
        elif auth.get("token"):
            header_name = auth.get("token_header", "Authorization")
            headers[header_name] = f"Bearer {auth['token']}"
        if auth.get("cookies"):
            headers["Cookie"] = auth["cookies"]

        return headers
