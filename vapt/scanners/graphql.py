"""GraphQL security scanner — discovery, introspection, depth/batching abuse, and injection."""

from __future__ import annotations

import asyncio
import json
import re

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding

# Common paths where GraphQL endpoints are hosted
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/v1/graphql", "/api/graphql",
    "/query", "/gql", "/graphql/console", "/altair", "/playground",
]

# Simple probe query
TYPENAME_QUERY = '{"query": "{ __typename }"}'

# Full introspection query
INTROSPECTION_QUERY = json.dumps({
    "query": (
        "{ __schema { queryType { name } mutationType { name } "
        "types { name kind fields { name type { name kind ofType { name } } } } } }"
    )
})

# Deeply nested query to test depth limits (8 levels)
DEPTH_QUERY = json.dumps({
    "query": (
        "{ __schema { types { fields { type { "
        "fields { type { fields { type { name } } } } } } } } }"
    )
})

# Alias-based batching query (10 aliases)
BATCH_QUERY = json.dumps({
    "query": "{ " + " ".join(f"a{i}: __typename" for i in range(10)) + " }"
})

# SQL error patterns
SQL_ERROR_PATTERNS = [
    r"SQL syntax",
    r"mysql_",
    r"ORA-\d+",
    r"PG::Error",
    r"SQLite3::",
    r"SQLSTATE",
    r"Microsoft OLE DB",
    r"ODBC SQL Server",
    r"Unclosed quotation mark",
    r"syntax error at or near",
]

JSON_HEADERS = {"Content-Type": "application/json"}


@register_scanner
class GraphQLScanner(BaseScanner):
    name = "graphql"
    category = "api"
    weight = 0.0
    active = True

    async def scan(self) -> list[Finding]:
        await self._endpoint_discovery()
        endpoint = self.context.get("graphql_endpoint")
        if endpoint:
            await asyncio.gather(
                self._introspection(endpoint),
                self._query_depth(endpoint),
                self._alias_batching(endpoint),
            )
            # SQLi test depends on introspection results
            await self._sqli_via_arguments(endpoint)
        return self.findings

    # ------------------------------------------------------------------
    # 1. Endpoint Discovery
    # ------------------------------------------------------------------

    async def _endpoint_discovery(self) -> None:
        base = self.target.base_url
        semaphore = asyncio.Semaphore(10)

        async def check_path(path: str) -> str | None:
            url = f"{base}{path}"
            async with semaphore:
                try:
                    response = await self.http.post(
                        url,
                        content=TYPENAME_QUERY,
                        headers=JSON_HEADERS,
                    )
                except Exception:
                    return None

                if response.status_code == 200:
                    try:
                        data = response.json()
                    except Exception:
                        return None
                    if "data" in data:
                        return url
            return None

        tasks = [check_path(p) for p in GRAPHQL_PATHS]
        results = await asyncio.gather(*tasks)

        found_endpoints = [url for url in results if url is not None]

        if found_endpoints:
            # Use the first discovered endpoint as the primary one
            endpoint = found_endpoints[0]
            self.context["graphql_endpoint"] = endpoint
            self.context["graphql_endpoints"] = found_endpoints

            for url in found_endpoints:
                path = url.replace(base, "")
                self.add_finding(
                    title=f"GraphQL Endpoint Discovered: {path}",
                    severity="Info",
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=url,
                    description=(
                        f"A GraphQL endpoint was discovered at {path}. "
                        "The server responded to a __typename query with valid data."
                    ),
                    steps_to_reproduce=[
                        f'POST {url} with body: {TYPENAME_QUERY}',
                        "Observe a 200 response containing a data field.",
                    ],
                    impact="GraphQL endpoints expose a query interface that may reveal schema details and sensitive data.",
                    remediation=(
                        "Restrict GraphQL endpoint access. Disable introspection in production. "
                        "Implement query depth limiting and rate limiting."
                    ),
                    references=[
                        "https://graphql.org/learn/",
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                )

    # ------------------------------------------------------------------
    # 2. Introspection
    # ------------------------------------------------------------------

    async def _introspection(self, endpoint: str) -> None:
        try:
            response = await self.http.post(
                endpoint,
                content=INTROSPECTION_QUERY,
                headers=JSON_HEADERS,
            )
        except Exception:
            return

        if response.status_code != 200:
            return

        try:
            data = response.json()
        except Exception:
            return

        schema = data.get("data", {}).get("__schema")
        if not schema:
            return

        # Parse type names and mutation names
        type_names: list[str] = []
        mutation_names: list[str] = []
        types_with_string_args: list[dict] = []

        for t in schema.get("types", []):
            name = t.get("name", "")
            kind = t.get("kind", "")
            type_names.append(name)

            # Collect fields for potential SQLi testing
            fields = t.get("fields") or []
            if fields and not name.startswith("__"):
                types_with_string_args.append(t)

        mutation_type_name = None
        mt = schema.get("mutationType")
        if mt:
            mutation_type_name = mt.get("name")
            for t in schema.get("types", []):
                if t.get("name") == mutation_type_name:
                    for f in t.get("fields", []):
                        mutation_names.append(f.get("name", ""))

        # Store parsed data in context
        self.context["graphql_types"] = type_names
        self.context["graphql_mutations"] = mutation_names
        self.context["graphql_schema_types"] = types_with_string_args

        user_types = [n for n in type_names if not n.startswith("__")]

        self.add_finding(
            title="GraphQL Introspection Enabled",
            severity="Medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
            owasp="A05:2021 -- Security Misconfiguration",
            url=endpoint,
            description=(
                "GraphQL introspection is enabled, exposing the full API schema. "
                f"Discovered {len(user_types)} user-defined types"
                + (f" and {len(mutation_names)} mutations" if mutation_names else "")
                + ".\n\nTypes: " + ", ".join(user_types[:20])
                + ("..." if len(user_types) > 20 else "")
                + (
                    "\nMutations: " + ", ".join(mutation_names[:20])
                    + ("..." if len(mutation_names) > 20 else "")
                    if mutation_names
                    else ""
                )
            ),
            steps_to_reproduce=[
                f"POST {endpoint} with introspection query.",
                "Observe that the full schema is returned.",
            ],
            evidence_response=json.dumps(data, indent=2)[:2000],
            impact=(
                "An attacker can enumerate all types, fields, queries, and mutations, "
                "enabling targeted attacks against the API."
            ),
            remediation="Disable introspection in production environments. Use allowlists for permitted queries.",
            references=[
                "https://graphql.org/learn/introspection/",
                "https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/",
            ],
        )

    # ------------------------------------------------------------------
    # 3. Query Depth Limit
    # ------------------------------------------------------------------

    async def _query_depth(self, endpoint: str) -> None:
        try:
            response = await self.http.post(
                endpoint,
                content=DEPTH_QUERY,
                headers=JSON_HEADERS,
            )
        except Exception:
            return

        if response.status_code != 200:
            return

        try:
            data = response.json()
        except Exception:
            return

        # If the deeply nested query succeeded without errors, no depth limit
        if "data" in data and "errors" not in data:
            self.add_finding(
                title="No GraphQL Query Depth Limit",
                severity="Medium",
                cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                cwe_id="CWE-400",
                cwe_name="Uncontrolled Resource Consumption",
                owasp="A05:2021 -- Security Misconfiguration",
                url=endpoint,
                description=(
                    "The GraphQL endpoint does not enforce a query depth limit. "
                    "A deeply nested query (8 levels) was executed without error, "
                    "indicating the server is vulnerable to denial-of-service via "
                    "resource-exhaustion attacks."
                ),
                steps_to_reproduce=[
                    f"POST {endpoint} with a deeply nested query (8 levels).",
                    "Observe that the query executes without error.",
                ],
                evidence_request=DEPTH_QUERY,
                evidence_response=json.dumps(data, indent=2)[:1000],
                impact=(
                    "An attacker can craft exponentially expensive queries to exhaust "
                    "server resources, causing denial of service."
                ),
                remediation=(
                    "Implement query depth limiting (recommended max depth: 5-7). "
                    "Use query cost analysis to reject expensive queries. "
                    "Consider tools like graphql-depth-limit or graphql-query-complexity."
                ),
                references=[
                    "https://www.howtographql.com/advanced/4-security/",
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            )

    # ------------------------------------------------------------------
    # 4. Alias-Based Batching
    # ------------------------------------------------------------------

    async def _alias_batching(self, endpoint: str) -> None:
        try:
            response = await self.http.post(
                endpoint,
                content=BATCH_QUERY,
                headers=JSON_HEADERS,
            )
        except Exception:
            return

        if response.status_code != 200:
            return

        try:
            data = response.json()
        except Exception:
            return

        result_data = data.get("data", {})
        # Check if all 10 aliases resolved
        resolved = sum(1 for i in range(10) if f"a{i}" in result_data)

        if resolved == 10:
            self.add_finding(
                title="GraphQL Alias-Based Batching Allowed",
                severity="Low",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                cwe_id="CWE-799",
                cwe_name="Improper Control of Interaction Frequency",
                owasp="A05:2021 -- Security Misconfiguration",
                url=endpoint,
                description=(
                    "The GraphQL endpoint allows alias-based batching. "
                    "A query with 10 aliases of the same field all resolved successfully. "
                    "This can be used to bypass rate limiting by packing multiple operations "
                    "into a single HTTP request."
                ),
                steps_to_reproduce=[
                    f"POST {endpoint} with a query containing 10 aliases of __typename.",
                    "Observe that all 10 aliases resolve in a single response.",
                ],
                evidence_request=BATCH_QUERY,
                evidence_response=json.dumps(data, indent=2)[:1000],
                impact=(
                    "Rate limiting based on HTTP requests can be bypassed by batching "
                    "multiple operations via GraphQL aliases. This enables brute-force "
                    "attacks, enumeration, and abuse of expensive resolvers."
                ),
                remediation=(
                    "Implement alias/operation counting in rate limiting logic. "
                    "Limit the number of aliases per query. "
                    "Use query cost analysis to account for batched operations."
                ),
                references=[
                    "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            )

    # ------------------------------------------------------------------
    # 5. SQL Injection via Arguments
    # ------------------------------------------------------------------

    async def _sqli_via_arguments(self, endpoint: str) -> None:
        # Attempt a SQL injection probe against a common field pattern
        sqli_query = json.dumps({
            "query": '{ user(id: "1\' OR \'1\'=\'1") { id } }'
        })

        try:
            response = await self.http.post(
                endpoint,
                content=sqli_query,
                headers=JSON_HEADERS,
            )
        except Exception:
            return

        if response.status_code not in (200, 400, 500):
            return

        body = response.text

        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                self.add_finding(
                    title="SQL Injection via GraphQL Arguments",
                    severity="Critical",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe_id="CWE-89",
                    cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
                    owasp="A03:2021 -- Injection",
                    url=endpoint,
                    parameter="user(id:)",
                    description=(
                        "A SQL injection vulnerability was detected in the GraphQL API. "
                        "Injecting a SQL payload into a GraphQL query argument triggered "
                        "a SQL error in the response, indicating that user input is "
                        "concatenated directly into SQL queries without parameterization."
                    ),
                    steps_to_reproduce=[
                        f"POST {endpoint} with Content-Type: application/json",
                        f"Body: {sqli_query}",
                        "Observe SQL error in the response.",
                    ],
                    evidence_request=sqli_query,
                    evidence_response=body[:2000],
                    impact=(
                        "An attacker can read, modify, or delete arbitrary database contents. "
                        "In severe cases, this can lead to full server compromise via "
                        "OS command execution through the database."
                    ),
                    remediation=(
                        "Use parameterized queries or prepared statements in all GraphQL resolvers. "
                        "Never concatenate user input into SQL queries. "
                        "Implement input validation on all GraphQL arguments."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                )
                break  # One match is enough
