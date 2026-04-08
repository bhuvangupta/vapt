"""API scanner — active API discovery, authentication, BOLA, mass assignment, and rate limiting tests."""

from __future__ import annotations

import asyncio
import json

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding

# Paths to probe for API discovery
API_DISCOVERY_PATHS = [
    "/swagger.json", "/swagger-ui/", "/openapi.json",
    "/api-docs", "/v1/api-docs", "/v2/api-docs", "/docs/api",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/health", "/api/status", "/api/metrics",
    "/graphql", "/graphiql",
]

# Paths that expose API documentation (Swagger/OpenAPI)
DOCUMENTATION_PATHS = {
    "/swagger.json", "/swagger-ui/", "/openapi.json",
    "/api-docs", "/v1/api-docs", "/v2/api-docs", "/docs/api",
}

# BOLA resource patterns to test
BOLA_RESOURCES = [
    "/api/users/", "/api/orders/", "/api/documents/",
]

# Mass assignment payloads — extra fields to inject
MASS_ASSIGNMENT_FIELDS = {
    "role": "admin",
    "is_admin": True,
    "balance": 999999,
    "verified": True,
}


@register_scanner
class ApiScanner(BaseScanner):
    name = "api"
    category = "api"
    weight = 0.12
    active = True

    async def scan(self) -> list[Finding]:
        await self._api_discovery()
        await asyncio.gather(
            self._unauthenticated_api_access(),
            self._bola_pattern(),
            self._mass_assignment(),
            self._rate_limiting(),
            self._graphql_detection(),
        )
        return self.findings

    # ------------------------------------------------------------------
    # 1. API Discovery
    # ------------------------------------------------------------------

    async def _api_discovery(self) -> None:
        """Probe common API paths and store discovered endpoints in context."""
        try:
            base = self.target.base_url
            discovered: list[dict] = []
            semaphore = asyncio.Semaphore(10)

            async def check_path(path: str) -> None:
                url = f"{base}{path}"
                async with semaphore:
                    try:
                        resp = await self.http.get(url)
                    except Exception:
                        return
                    if resp.status_code in (200, 301, 302):
                        discovered.append({
                            "path": path,
                            "url": url,
                            "status": resp.status_code,
                        })

            await asyncio.gather(*(check_path(p) for p in API_DISCOVERY_PATHS))

            # Store for other tests and scanners
            self.context.setdefault("api_endpoints", [])
            self.context["api_endpoints"].extend(discovered)

            # Report publicly accessible API documentation
            doc_endpoints = [
                ep for ep in discovered
                if ep["path"] in DOCUMENTATION_PATHS and ep["status"] == 200
            ]
            if doc_endpoints:
                paths_str = ", ".join(ep["path"] for ep in doc_endpoints)
                self.add_finding(
                    title="API Documentation Publicly Accessible",
                    severity="Medium",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=doc_endpoints[0]["url"],
                    description=(
                        f"Swagger/OpenAPI documentation is publicly accessible at: {paths_str}. "
                        "This reveals all API endpoints, parameters, and data models to potential attackers."
                    ),
                    steps_to_reproduce=[
                        f"Navigate to {ep['url']}" for ep in doc_endpoints
                    ],
                    impact=(
                        "Exposed API documentation provides attackers with a complete map of the API surface, "
                        "including endpoint paths, accepted parameters, authentication schemes, and data models."
                    ),
                    remediation=(
                        "Restrict API documentation to authenticated internal users only. "
                        "Disable Swagger UI in production or protect it behind authentication."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                    ],
                )

            if discovered:
                self.add_finding(
                    title=f"API Endpoints Discovered: {len(discovered)} paths",
                    severity="Info",
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=self.target.url,
                    description=(
                        "The following API endpoints were discovered:\n"
                        + "\n".join(f"  {ep['path']} (HTTP {ep['status']})" for ep in discovered)
                    ),
                    impact="Discovered API endpoints reveal application structure and functionality.",
                    remediation="Ensure all API endpoints enforce proper authentication and authorization.",
                )
        except Exception:
            self.log("API discovery failed")

    # ------------------------------------------------------------------
    # 2. Unauthenticated API Access
    # ------------------------------------------------------------------

    async def _unauthenticated_api_access(self) -> None:
        """Test discovered API endpoints for unauthenticated access."""
        try:
            endpoints = self.context.get("api_endpoints", [])
            if not endpoints:
                return

            base = self.target.base_url
            semaphore = asyncio.Semaphore(10)

            async def check_endpoint(ep: dict) -> None:
                url = ep["url"]
                async with semaphore:
                    try:
                        # Send request without any auth headers
                        resp = await self.http.get(url, headers={
                            "Authorization": "",
                            "Cookie": "",
                        })
                    except Exception:
                        return

                    if resp.status_code != 200:
                        return

                    body = resp.text.strip()
                    # Check if response contains meaningful data (not just an empty body or login page)
                    if len(body) < 10:
                        return
                    # Skip if it looks like a login/redirect page
                    if any(kw in body.lower() for kw in ("login", "sign in", "unauthorized", "<!doctype")):
                        return

                    self.add_finding(
                        title=f"Unauthenticated API Access: {ep['path']}",
                        severity="High",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-306",
                        cwe_name="Missing Authentication for Critical Function",
                        owasp="API2:2023 -- Broken Authentication",
                        url=url,
                        description=(
                            f"The API endpoint {ep['path']} returned data without any authentication. "
                            "An attacker can access this endpoint directly to extract information."
                        ),
                        steps_to_reproduce=[
                            f"Send a GET request to {url} without authentication headers",
                            "Observe that the response contains data",
                        ],
                        evidence_response=body[:2000],
                        impact="Unauthenticated API access allows attackers to read or manipulate data without credentials.",
                        remediation=(
                            "Enforce authentication on all API endpoints. Use API keys, OAuth tokens, "
                            "or session-based authentication for every request."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                        ],
                    )

            await asyncio.gather(*(check_endpoint(ep) for ep in endpoints))
        except Exception:
            self.log("Unauthenticated API access test failed")

    # ------------------------------------------------------------------
    # 3. BOLA Pattern (Broken Object Level Authorization)
    # ------------------------------------------------------------------

    async def _bola_pattern(self) -> None:
        """Test for BOLA by accessing resources with sequential IDs."""
        try:
            if not self.target.has_auth():
                return

            endpoints = self.context.get("api_endpoints", [])
            if not endpoints:
                return

            base = self.target.base_url
            auth_headers = self._build_auth_headers()

            for resource in BOLA_RESOURCES:
                url_1 = f"{base}{resource}1"
                url_2 = f"{base}{resource}2"

                try:
                    resp_1 = await self.http.get(url_1, headers=auth_headers)
                    resp_2 = await self.http.get(url_2, headers=auth_headers)
                except Exception:
                    continue

                if resp_1.status_code != 200 or resp_2.status_code != 200:
                    continue

                # Both return 200 — check if second returns different user data
                try:
                    data_1 = resp_1.json()
                    data_2 = resp_2.json()
                except Exception:
                    continue

                if not data_1 or not data_2:
                    continue

                # If both return data and the data differs, potential BOLA
                if data_1 != data_2:
                    self.add_finding(
                        title=f"Potential BOLA: {resource}",
                        severity="Medium",
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-639",
                        cwe_name="Authorization Bypass Through User-Controlled Key",
                        owasp="API1:2023 -- Broken Object Level Authorization",
                        url=url_2,
                        confidence="tentative",
                        description=(
                            f"Accessing {resource}1 and {resource}2 with the same authentication token "
                            "returned different data. This is a heuristic detection that requires manual "
                            "verification. The differing responses may be expected behavior for distinct "
                            "public resources."
                        ),
                        steps_to_reproduce=[
                            f"Authenticate and send GET {url_1}",
                            f"Using the same token, send GET {url_2}",
                            "Compare the response data — different user data is returned",
                        ],
                        evidence_request=f"GET {url_2} with auth token from user 1",
                        evidence_response=json.dumps(data_2, indent=2)[:2000],
                        impact=(
                            "Broken Object Level Authorization allows any authenticated user to access, "
                            "modify, or delete resources belonging to other users by manipulating resource IDs."
                        ),
                        remediation=(
                            "Implement object-level authorization checks that verify the authenticated user "
                            "owns or has permission to access the requested resource. Use UUIDs instead of "
                            "sequential integer IDs to make enumeration harder."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        ],
                    )
        except Exception:
            self.log("BOLA pattern test failed")

    # ------------------------------------------------------------------
    # 4. Mass Assignment
    # ------------------------------------------------------------------

    async def _mass_assignment(self) -> None:
        """Test for mass assignment by injecting privileged fields in PUT/POST requests."""
        try:
            endpoints = self.context.get("api_endpoints", [])
            if not endpoints:
                return

            auth_headers = self._build_auth_headers()
            base = self.target.base_url

            # Test on API endpoints that likely accept JSON
            test_paths = [
                ep["url"] for ep in endpoints
                if any(kw in ep["path"] for kw in ("/api/users", "/api/profile", "/api/account", "/api/settings"))
            ]

            # Fallback: try generic API paths
            if not test_paths:
                test_paths = [
                    f"{base}/api/users/me",
                    f"{base}/api/profile",
                    f"{base}/api/account",
                ]

            for url in test_paths:
                try:
                    # First, GET current state
                    get_resp = await self.http.get(url, headers=auth_headers)
                    if get_resp.status_code != 200:
                        continue

                    try:
                        original_data = get_resp.json()
                    except Exception:
                        continue

                    if not isinstance(original_data, dict):
                        continue

                    # Inject mass assignment fields into the original data
                    payload = {**original_data, **MASS_ASSIGNMENT_FIELDS}

                    # Try PUT
                    put_resp = await self.http.put(
                        url, json=payload, headers=auth_headers,
                    )

                    resp_to_check = put_resp
                    if put_resp.status_code not in (200, 201):
                        # Try POST
                        post_resp = await self.http.post(
                            url, json=payload, headers=auth_headers,
                        )
                        if post_resp.status_code not in (200, 201):
                            continue
                        resp_to_check = post_resp

                    try:
                        result_data = resp_to_check.json()
                    except Exception:
                        continue

                    if not isinstance(result_data, dict):
                        continue

                    # Check if any injected fields were reflected back
                    accepted_fields = []
                    for field_name, field_value in MASS_ASSIGNMENT_FIELDS.items():
                        if field_name in result_data:
                            if result_data[field_name] == field_value:
                                accepted_fields.append(f"{field_name}={field_value}")

                    if accepted_fields:
                        self.add_finding(
                            title=f"Mass Assignment Vulnerability: {url}",
                            severity="Critical",
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            cwe_id="CWE-915",
                            cwe_name="Improperly Controlled Modification of Dynamically-Determined Object Attributes",
                            owasp="API6:2023 -- Unrestricted Access to Sensitive Business Flows",
                            url=url,
                            description=(
                                f"The API endpoint accepted privileged fields via mass assignment: "
                                f"{', '.join(accepted_fields)}. An attacker can escalate privileges "
                                "or manipulate critical attributes by including extra fields in API requests."
                            ),
                            steps_to_reproduce=[
                                f"Send GET {url} to retrieve current profile data",
                                f"Add fields {json.dumps(MASS_ASSIGNMENT_FIELDS)} to the request body",
                                f"Send PUT/POST {url} with the modified payload",
                                "Observe that privileged fields are accepted and reflected in the response",
                            ],
                            evidence_request=json.dumps(payload, indent=2)[:2000],
                            evidence_response=json.dumps(result_data, indent=2)[:2000],
                            impact=(
                                "Mass assignment allows attackers to modify fields they should not control, "
                                "including role escalation to admin, balance manipulation, and bypassing "
                                "verification checks."
                            ),
                            remediation=(
                                "Implement a strict allowlist of fields that users can modify. "
                                "Never bind request parameters directly to internal objects. "
                                "Use DTOs (Data Transfer Objects) to control which fields are accepted."
                            ),
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                            ],
                        )
                except Exception:
                    continue
        except Exception:
            self.log("Mass assignment test failed")

    # ------------------------------------------------------------------
    # 5. Rate Limiting
    # ------------------------------------------------------------------

    async def _rate_limiting(self) -> None:
        """Send rapid requests to check for rate limiting (HTTP 429)."""
        try:
            endpoints = self.context.get("api_endpoints", [])
            if not endpoints:
                return

            # Pick the first responsive API endpoint
            target_ep = None
            for ep in endpoints:
                if ep["status"] == 200:
                    target_ep = ep
                    break

            if not target_ep:
                return

            url = target_ep["url"]
            request_count = 50

            # Fire all requests concurrently (bypass rate limiter via raw client)
            async def fire_request() -> int:
                try:
                    resp = await self.http.get(url)
                    return resp.status_code
                except Exception:
                    return 0

            results = await asyncio.gather(*(fire_request() for _ in range(request_count)))

            total_valid = sum(1 for r in results if r > 0)
            rate_limited = sum(1 for r in results if r == 429)
            non_limited = total_valid - rate_limited

            if total_valid > 0 and rate_limited == 0:
                self.add_finding(
                    title=f"No Rate Limiting on API Endpoint: {target_ep['path']}",
                    severity="Medium",
                    cvss_score=5.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
                    cwe_id="CWE-770",
                    cwe_name="Allocation of Resources Without Limits or Throttling",
                    owasp="API4:2023 -- Unrestricted Resource Consumption",
                    url=url,
                    description=(
                        f"Sent {request_count} rapid requests to {target_ep['path']}. "
                        f"All {non_limited} successful responses returned non-429 status codes, "
                        "indicating no rate limiting is in place."
                    ),
                    steps_to_reproduce=[
                        f"Send {request_count} concurrent GET requests to {url}",
                        "Observe that no HTTP 429 (Too Many Requests) responses are returned",
                    ],
                    evidence_response=(
                        f"Total requests: {request_count}, "
                        f"Successful (non-429): {non_limited}, "
                        f"Rate limited (429): {rate_limited}"
                    ),
                    impact=(
                        "Without rate limiting, attackers can perform brute-force attacks, "
                        "credential stuffing, API scraping, and denial-of-service attacks "
                        "against API endpoints."
                    ),
                    remediation=(
                        "Implement rate limiting on all API endpoints. Use HTTP 429 responses "
                        "with Retry-After headers. Consider per-user, per-IP, and per-endpoint "
                        "rate limits. Use API gateways or WAF rules for enforcement."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    ],
                )
        except Exception:
            self.log("Rate limiting test failed")

    # ------------------------------------------------------------------
    # 6. GraphQL Detection & Introspection
    # ------------------------------------------------------------------

    async def _graphql_detection(self) -> None:
        """Detect GraphQL endpoints and test for introspection."""
        try:
            base = self.target.base_url
            graphql_url = f"{base}/graphql"

            try:
                resp = await self.http.get(graphql_url)
            except Exception:
                return

            if resp.status_code != 200:
                return

            # GraphQL endpoint exists — store in context
            self.context.setdefault("graphql_endpoints", [])
            self.context["graphql_endpoints"].append(graphql_url)

            # Test introspection query
            introspection_query = {"query": "{ __schema { types { name } } }"}
            try:
                intro_resp = await self.http.post(
                    graphql_url,
                    json=introspection_query,
                    headers={"Content-Type": "application/json"},
                )
            except Exception:
                return

            if intro_resp.status_code != 200:
                return

            try:
                intro_data = intro_resp.json()
            except Exception:
                return

            # Check if introspection returned schema data
            if "data" in intro_data and "__schema" in (intro_data.get("data") or {}):
                type_names = []
                schema = intro_data["data"]["__schema"]
                if "types" in schema:
                    type_names = [t.get("name", "") for t in schema["types"] if not t.get("name", "").startswith("__")]

                self.add_finding(
                    title="GraphQL Introspection Enabled",
                    severity="Medium",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=graphql_url,
                    description=(
                        "GraphQL introspection is enabled, allowing anyone to query the full API schema. "
                        "This reveals all types, fields, queries, mutations, and subscriptions.\n"
                        + (f"Discovered types: {', '.join(type_names[:20])}" if type_names else "")
                    ),
                    steps_to_reproduce=[
                        f"Send POST to {graphql_url} with body: {json.dumps(introspection_query)}",
                        "Observe the full schema is returned including all types and fields",
                    ],
                    evidence_request=json.dumps(introspection_query),
                    evidence_response=json.dumps(intro_data, indent=2)[:2000],
                    impact=(
                        "GraphQL introspection exposes the entire API schema, allowing attackers "
                        "to discover hidden queries, mutations, internal types, and sensitive fields."
                    ),
                    remediation=(
                        "Disable GraphQL introspection in production. If introspection is needed "
                        "for development, restrict it to internal networks or authenticated admin users."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    ],
                )

                # Store full schema for graphql scanner
                self.context["graphql_schema"] = intro_data.get("data", {}).get("__schema", {})
        except Exception:
            self.log("GraphQL detection failed")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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
