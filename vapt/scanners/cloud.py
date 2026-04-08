"""Cloud scanner — active cloud misconfiguration tests: provider detection, S3 buckets, subdomain takeover, exposed config, Firebase."""

from __future__ import annotations

import asyncio
import json
import re

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding
from vapt.utils import run_command

# Cloud provider header signatures
CLOUD_HEADERS = {
    "aws": ["x-amz-"],
    "gcp": ["x-goog-"],
    "azure": ["x-ms-", "x-azure-"],
}

CLOUD_SERVER_VALUES = {
    "aws": ["amazons3", "amazonelb"],
    "gcp": ["gws", "gse"],
    "azure": [],
    "cloudflare": ["cloudflare"],
}

# Cloud URLs to search for in page source
CLOUD_URL_PATTERNS = {
    "aws": [r"[\w.-]+\.s3\.amazonaws\.com", r"[\w.-]+\.cloudfront\.net"],
    "gcp": [r"storage\.googleapis\.com", r"[\w.-]+\.firebaseio\.com"],
    "azure": [r"[\w.-]+\.blob\.core\.windows\.net"],
    "firebase": [r"([\w.-]+)\.firebaseio\.com"],
}

# S3 bucket name suffixes to generate from domain
S3_BUCKET_SUFFIXES = [
    "", "-assets", "-backup", "-static", "-uploads", "-media", "-data",
]

# Subdomain takeover fingerprints: (CNAME pattern, error text indicating takeover is possible)
TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "herokudns.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "fastly.net": "Fastly error: unknown domain",
    "ghost.io": "The thing you were looking for is no longer here",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "azurewebsites.net": "404 Web Site not found",
    "cloudapp.net": "404 Web Site not found",
    "trafficmanager.net": "404 Web Site not found",
    "azureedge.net": "404 Web Site not found",
    "pantheonsite.io": "404 error unknown site",
    "zendesk.com": "Help Center Closed",
    "teamwork.com": "Oops - We didn't find your site",
    "helpjuice.com": "We could not find what you're looking for",
    "helpscoutdocs.com": "No settings were found for this company",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "tumblr.com": "There's nothing here",
    "wordpress.com": "Do you want to register",
    "feedpress.me": "The feed has not been found",
    "freshdesk.com": "There is no helpdesk here",
    "unbounce.com": "The requested URL was not found on this server",
}

# Exposed cloud configuration file paths
CLOUD_CONFIG_PATHS = [
    ("/.aws/credentials", "AWS credentials file"),
    ("/.aws/config", "AWS config file"),
    ("/firebase.json", "Firebase configuration"),
    ("/.firebaserc", "Firebase project config"),
    ("/google-services.json", "Google Services config (Android)"),
    ("/GoogleService-Info.plist", "Google Services config (iOS)"),
    ("/web.config", "IIS/ASP.NET configuration"),
]

# Keywords in web.config that indicate connection strings
CONNECTION_STRING_PATTERNS = [
    r"connectionString\s*=",
    r"Server\s*=.*Password\s*=",
    r"Data Source\s*=",
    r"Initial Catalog\s*=",
    r"AccountKey\s*=",
]


@register_scanner
class CloudScanner(BaseScanner):
    name = "cloud"
    category = "network"
    weight = 0.0  # Findings feed into existing "network" category
    active = True

    async def scan(self) -> list[Finding]:
        await self._cloud_provider_detection()
        await asyncio.gather(
            self._s3_bucket_testing(),
            self._subdomain_takeover(),
            self._exposed_cloud_config(),
            self._firebase_database(),
        )
        return self.findings

    # ------------------------------------------------------------------
    # 1. Cloud Provider Detection
    # ------------------------------------------------------------------

    async def _cloud_provider_detection(self) -> None:
        """Inspect response headers and page source to identify cloud providers."""
        try:
            providers: set[str] = set()

            # Fetch the homepage
            try:
                resp = await self.http.get(self.target.url)
            except Exception:
                return

            # Check response headers
            for header_name, header_value in resp.headers.items():
                header_lower = header_name.lower()
                value_lower = header_value.lower()

                for provider, prefixes in CLOUD_HEADERS.items():
                    if any(header_lower.startswith(p) for p in prefixes):
                        providers.add(provider)

                if header_lower == "server":
                    for provider, server_vals in CLOUD_SERVER_VALUES.items():
                        if any(sv in value_lower for sv in server_vals):
                            providers.add(provider)

            # Check page source for cloud URLs
            body = resp.text
            firebase_projects: list[str] = []

            for provider, patterns in CLOUD_URL_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, body)
                    if matches:
                        providers.add(provider)
                        # Capture Firebase project names
                        if "firebaseio" in pattern:
                            firebase_projects.extend(matches)

            # Store results in context
            self.context["cloud_providers"] = list(providers)
            if firebase_projects:
                self.context["firebase_projects"] = list(set(firebase_projects))

            if providers:
                self.add_finding(
                    title=f"Cloud Provider Detected: {', '.join(sorted(providers)).upper()}",
                    severity="Info",
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=self.target.url,
                    description=(
                        f"Cloud infrastructure detected: {', '.join(sorted(providers)).upper()}. "
                        "Identified via response headers and page source analysis."
                    ),
                    impact="Cloud provider identification assists in targeting cloud-specific misconfigurations.",
                    remediation=(
                        "Remove unnecessary cloud-specific headers. Ensure cloud resources are "
                        "properly secured regardless of provider identification."
                    ),
                )
        except Exception:
            self.log("Cloud provider detection failed")

    # ------------------------------------------------------------------
    # 2. S3 Bucket Testing
    # ------------------------------------------------------------------

    async def _s3_bucket_testing(self) -> None:
        """Generate and test S3 bucket names based on domain for public access."""
        try:
            domain = self.target.domain
            # Strip TLD variations to get the base name
            base_name = domain.split(".")[0]
            bucket_names = [f"{base_name}{suffix}" for suffix in S3_BUCKET_SUFFIXES]

            semaphore = asyncio.Semaphore(5)

            async def test_bucket(bucket: str) -> None:
                url = f"https://{bucket}.s3.amazonaws.com/"
                async with semaphore:
                    try:
                        resp = await self.http.get(url)
                    except Exception:
                        return

                    body = resp.text

                    if resp.status_code == 200 and "<ListBucketResult" in body:
                        # Public listing enabled — critical
                        # Extract a few object keys as evidence
                        keys = re.findall(r"<Key>([^<]+)</Key>", body)
                        sample_keys = keys[:10] if keys else []

                        self.add_finding(
                            title=f"S3 Bucket Publicly Listable: {bucket}",
                            severity="Critical",
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            cwe_id="CWE-284",
                            cwe_name="Improper Access Control",
                            owasp="A01:2021 -- Broken Access Control",
                            url=url,
                            description=(
                                f"The S3 bucket '{bucket}' allows public listing of its contents. "
                                f"Found {len(keys)} objects."
                                + (f"\nSample objects: {', '.join(sample_keys)}" if sample_keys else "")
                            ),
                            steps_to_reproduce=[
                                f"Navigate to {url}",
                                "Observe the XML response listing all bucket contents",
                            ],
                            evidence_response=body[:2000],
                            impact=(
                                "Publicly listable S3 buckets expose all stored files including "
                                "potentially sensitive data, backups, credentials, and source code."
                            ),
                            remediation=(
                                "Disable public access on the S3 bucket. Enable S3 Block Public Access "
                                "at the account level. Review bucket policies and ACLs to restrict access "
                                "to authorized principals only."
                            ),
                            references=[
                                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                            ],
                        )
                    elif resp.status_code == 403 and "AccessDenied" in body:
                        # Bucket exists but access denied — informational
                        self.add_finding(
                            title=f"S3 Bucket Exists (Access Denied): {bucket}",
                            severity="Info",
                            cvss_score=0.0,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            cwe_id="CWE-284",
                            cwe_name="Improper Access Control",
                            owasp="A05:2021 -- Security Misconfiguration",
                            url=url,
                            description=(
                                f"The S3 bucket '{bucket}' exists but returns AccessDenied. "
                                "Public listing is blocked, but the bucket name is confirmed."
                            ),
                            impact="Confirmed bucket names can be used for targeted attacks or social engineering.",
                            remediation="Ensure bucket policies are properly configured and regularly audited.",
                        )
                    elif "NoSuchBucket" in body:
                        # Bucket does not exist — info only
                        self.add_finding(
                            title=f"S3 Bucket Does Not Exist: {bucket}",
                            severity="Info",
                            cvss_score=0.0,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            cwe_id="CWE-284",
                            cwe_name="Improper Access Control",
                            owasp="A05:2021 -- Security Misconfiguration",
                            url=url,
                            description=(
                                f"The S3 bucket '{bucket}' does not exist (NoSuchBucket). "
                                "An attacker could potentially register this name for subdomain takeover."
                            ),
                            impact="Non-existent buckets with predictable names could be claimed by attackers.",
                            remediation="Proactively register expected bucket names to prevent namespace squatting.",
                        )

            await asyncio.gather(*(test_bucket(b) for b in bucket_names))
        except Exception:
            self.log("S3 bucket testing failed")

    # ------------------------------------------------------------------
    # 3. Subdomain Takeover
    # ------------------------------------------------------------------

    async def _subdomain_takeover(self) -> None:
        """Check subdomains from context for potential takeover via dangling CNAME records."""
        try:
            subdomains = self.context.get("subdomains", [])
            if not subdomains:
                return

            semaphore = asyncio.Semaphore(5)

            async def check_subdomain(subdomain: str) -> None:
                async with semaphore:
                    # Resolve CNAME using dig
                    returncode, stdout, stderr = await run_command(
                        ["dig", "+short", "CNAME", subdomain],
                        timeout=10,
                    )

                    if returncode != 0 or not stdout.strip():
                        return

                    cname = stdout.strip().rstrip(".")

                    # Check if CNAME points to a known vulnerable service
                    for service_pattern, error_text in TAKEOVER_FINGERPRINTS.items():
                        if service_pattern not in cname.lower():
                            continue

                        # CNAME points to a vulnerable service — check for error
                        try:
                            resp = await self.http.get(
                                f"https://{subdomain}",
                                headers={"Host": subdomain},
                            )
                        except Exception:
                            try:
                                resp = await self.http.get(
                                    f"http://{subdomain}",
                                    headers={"Host": subdomain},
                                )
                            except Exception:
                                continue

                        if error_text.lower() in resp.text.lower():
                            self.add_finding(
                                title=f"Subdomain Takeover Possible: {subdomain}",
                                severity="High",
                                cvss_score=7.5,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                cwe_id="CWE-284",
                                cwe_name="Improper Access Control",
                                owasp="A05:2021 -- Security Misconfiguration",
                                url=f"https://{subdomain}",
                                description=(
                                    f"The subdomain {subdomain} has a CNAME record pointing to "
                                    f"{cname} ({service_pattern}), but the target service returns "
                                    f"an error indicating the resource is unclaimed. An attacker "
                                    "can register the resource on the service to take over this subdomain."
                                ),
                                steps_to_reproduce=[
                                    f"Resolve CNAME for {subdomain}: points to {cname}",
                                    f"Visit https://{subdomain}",
                                    f"Observe error: '{error_text}'",
                                    f"Register the resource on {service_pattern} to claim the subdomain",
                                ],
                                evidence_request=f"dig +short CNAME {subdomain}\n{cname}",
                                evidence_response=resp.text[:2000],
                                impact=(
                                    "Subdomain takeover allows attackers to serve content on a trusted "
                                    "subdomain. This enables phishing, cookie theft, and bypassing "
                                    "same-origin policy protections."
                                ),
                                remediation=(
                                    f"Remove the dangling CNAME record for {subdomain} or reclaim "
                                    f"the resource on {service_pattern}. Regularly audit DNS records "
                                    "for subdomains pointing to decommissioned services."
                                ),
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                                    "https://github.com/EdOverflow/can-i-take-over-xyz",
                                ],
                            )
                        break

            await asyncio.gather(*(check_subdomain(s) for s in subdomains))
        except Exception:
            self.log("Subdomain takeover test failed")

    # ------------------------------------------------------------------
    # 4. Exposed Cloud Configuration Files
    # ------------------------------------------------------------------

    async def _exposed_cloud_config(self) -> None:
        """Check for exposed cloud configuration files containing credentials."""
        try:
            base = self.target.base_url
            semaphore = asyncio.Semaphore(10)

            async def check_config(path: str, description: str) -> None:
                url = f"{base}{path}"
                async with semaphore:
                    try:
                        resp = await self.http.get(url)
                    except Exception:
                        return

                    if resp.status_code != 200:
                        return

                    body = resp.text.strip()
                    if not body or len(body) < 5:
                        return

                    # Skip HTML error pages
                    if body.lower().startswith("<!doctype") or "<html" in body.lower()[:100]:
                        return

                    # Special handling for web.config — check for connection strings
                    has_secrets = False
                    if "web.config" in path:
                        for pattern in CONNECTION_STRING_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                has_secrets = True
                                break

                    # AWS credentials check
                    if ".aws" in path:
                        if any(kw in body for kw in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token")):
                            has_secrets = True

                    # Firebase/Google config check
                    if "firebase" in path.lower() or "google" in path.lower():
                        if any(kw in body.lower() for kw in ("api_key", "apikey", "auth_domain", "project_id", "client_id")):
                            has_secrets = True

                    # Any cloud config file accessible = critical
                    if has_secrets:
                        severity = "Critical"
                        cvss = 9.8
                    else:
                        severity = "Critical"
                        cvss = 9.8

                    self.add_finding(
                        title=f"Exposed Cloud Config: {path}",
                        severity=severity,
                        cvss_score=cvss,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-522",
                        cwe_name="Insufficiently Protected Credentials",
                        owasp="A05:2021 -- Security Misconfiguration",
                        url=url,
                        description=(
                            f"The {description} is publicly accessible at {path}. "
                            + (
                                "The file contains credentials or sensitive configuration data."
                                if has_secrets
                                else "Cloud configuration files may contain API keys, secrets, and access credentials."
                            )
                        ),
                        steps_to_reproduce=[
                            f"Navigate to {url}",
                            "Observe the cloud configuration file contents",
                        ],
                        evidence_response=body[:2000],
                        impact=(
                            "Exposed cloud credentials allow attackers to access cloud infrastructure, "
                            "read/write data in storage buckets, access databases, and potentially "
                            "escalate to full account compromise."
                        ),
                        remediation=(
                            f"Immediately remove {path} from the webroot. Rotate all credentials "
                            "found in the file. Block access to configuration files via web server "
                            "rules. Use environment variables or secret management services instead "
                            "of configuration files."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/",
                            "https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html",
                        ],
                    )

            await asyncio.gather(*(check_config(path, desc) for path, desc in CLOUD_CONFIG_PATHS))
        except Exception:
            self.log("Exposed cloud config test failed")

    # ------------------------------------------------------------------
    # 5. Firebase Database
    # ------------------------------------------------------------------

    async def _firebase_database(self) -> None:
        """Test Firebase Realtime Database for unauthenticated read/write access."""
        try:
            firebase_projects = self.context.get("firebase_projects", [])
            if not firebase_projects:
                # Also check page source if not already done
                try:
                    resp = await self.http.get(self.target.url)
                    matches = re.findall(r"([\w.-]+)\.firebaseio\.com", resp.text)
                    firebase_projects = list(set(matches))
                except Exception:
                    return

            if not firebase_projects:
                return

            for project in firebase_projects:
                db_url = f"https://{project}.firebaseio.com/.json"

                # Test read access
                try:
                    read_resp = await self.http.get(db_url)
                except Exception:
                    continue

                if read_resp.status_code == 200:
                    body = read_resp.text.strip()

                    # Check if it returned actual data (not "null")
                    if body and body != "null":
                        self.add_finding(
                            title=f"Firebase Database Publicly Readable: {project}",
                            severity="High",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-284",
                            cwe_name="Improper Access Control",
                            owasp="A01:2021 -- Broken Access Control",
                            url=db_url,
                            description=(
                                f"The Firebase Realtime Database for project '{project}' is publicly "
                                "readable without authentication. Anyone can access the full database "
                                "contents by appending .json to the database URL."
                            ),
                            steps_to_reproduce=[
                                f"Navigate to {db_url}",
                                "Observe that the database contents are returned without authentication",
                            ],
                            evidence_response=body[:2000],
                            impact=(
                                "Publicly readable Firebase databases expose all stored data including "
                                "user records, personal information, API keys, and application data."
                            ),
                            remediation=(
                                "Configure Firebase Security Rules to require authentication for all "
                                "reads. Set rules to deny public access:\n"
                                '  {"rules": {".read": "auth != null", ".write": "auth != null"}}'
                            ),
                            references=[
                                "https://firebase.google.com/docs/database/security",
                            ],
                        )

                        # Test write access
                        test_key = "__vapt_write_test__"
                        test_url = f"https://{project}.firebaseio.com/{test_key}.json"
                        test_data = {"test": True, "scanner": "vapt"}

                        try:
                            write_resp = await self.http.put(
                                test_url, json=test_data,
                            )

                            if write_resp.status_code == 200:
                                # Write succeeded — clean up
                                try:
                                    await self.http.delete(test_url)
                                except Exception:
                                    pass

                                self.add_finding(
                                    title=f"Firebase Database Publicly Writable: {project}",
                                    severity="Critical",
                                    cvss_score=9.8,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    cwe_id="CWE-284",
                                    cwe_name="Improper Access Control",
                                    owasp="A01:2021 -- Broken Access Control",
                                    url=db_url,
                                    description=(
                                        f"The Firebase Realtime Database for project '{project}' is publicly "
                                        "writable without authentication. Anyone can create, modify, or delete "
                                        "data in the database."
                                    ),
                                    steps_to_reproduce=[
                                        f"Send PUT to {test_url} with JSON body: {json.dumps(test_data)}",
                                        "Observe the data is written successfully (HTTP 200)",
                                    ],
                                    evidence_request=f"PUT {test_url}\n{json.dumps(test_data)}",
                                    evidence_response=write_resp.text[:2000],
                                    impact=(
                                        "Publicly writable Firebase databases allow attackers to modify "
                                        "application data, inject malicious content, corrupt records, "
                                        "and potentially take over the entire application."
                                    ),
                                    remediation=(
                                        "Immediately configure Firebase Security Rules to require "
                                        "authentication for all writes. Audit database for unauthorized "
                                        "modifications. Set rules:\n"
                                        '  {"rules": {".read": "auth != null", ".write": "auth != null"}}'
                                    ),
                                    references=[
                                        "https://firebase.google.com/docs/database/security",
                                    ],
                                )
                        except Exception:
                            pass
                elif read_resp.status_code == 401:
                    # Database exists but requires auth — good
                    self.add_finding(
                        title=f"Firebase Database Detected (Secured): {project}",
                        severity="Info",
                        cvss_score=0.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                        owasp="A05:2021 -- Security Misconfiguration",
                        url=db_url,
                        description=(
                            f"Firebase Realtime Database detected for project '{project}'. "
                            "Authentication is required for access (properly secured)."
                        ),
                        impact="Firebase project name is disclosed, but access controls are enforced.",
                        remediation="Continue to maintain strict Firebase Security Rules.",
                    )
        except Exception:
            self.log("Firebase database test failed")
