"""Web application scanner — passive directory discovery, file detection, and CMS fingerprinting."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding

# Paths that indicate admin panels when accessible
ADMIN_PATHS = {
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/wp-admin", "/wp-admin/", "/manager", "/cpanel",
    "/phpmyadmin", "/adminer", "/admin/login",
}

# Paths that indicate sensitive configuration files
SENSITIVE_CONFIG_PATHS = {
    "/config.yml", "/config.json", "/config.xml",
    "/database.yml", "/settings.py", "/application.properties",
    "/web.config", "/php.ini", "/conf/server.xml",
}

# Backup and config file paths for dedicated check
BACKUP_CONFIG_PATHS = [
    (".env", "Environment configuration file"),
    (".git/config", "Git configuration file"),
    (".git/HEAD", "Git HEAD reference"),
    (".svn/entries", "SVN entries file"),
    (".htaccess", "Apache configuration file"),
    (".htpasswd", "Apache password file"),
    ("web.config", "IIS/ASP.NET configuration file"),
    ("wp-config.php.bak", "WordPress configuration backup"),
    (".DS_Store", "macOS directory metadata file"),
]

# Error page keywords indicating information disclosure
ERROR_KEYWORDS = {
    "stack_trace": [
        "Traceback (most recent call last)",
        "at System.",
        "at java.",
        "Exception in thread",
        "stack trace",
        "Runtime Error",
        "Unhandled Exception",
    ],
    "framework_version": [
        "X-Powered-By",
        "ASP.NET Version",
        "PHP Version",
        "Django Version",
        "Rails Version",
        "Laravel",
        "Spring Boot",
    ],
    "file_path": [
        "\\Users\\",
        "/home/",
        "/var/www/",
        "/opt/",
        "/usr/local/",
        "C:\\inetpub",
        "C:\\Windows",
    ],
    "sql_error": [
        "SQL syntax",
        "mysql_",
        "ORA-",
        "PG::Error",
        "SQLite3::",
        "SQLSTATE",
        "Microsoft OLE DB",
        "ODBC SQL Server",
    ],
    "debug_info": [
        "DEBUG = True",
        "DJANGO_SETTINGS_MODULE",
        "WP_DEBUG",
        "display_errors",
        "error_reporting",
    ],
}


@register_scanner
class WebAppScanner(BaseScanner):
    name = "webapp"
    category = "scan"
    weight = 0.07
    active = False

    async def scan(self) -> list[Finding]:
        await asyncio.gather(
            self._directory_discovery(),
            self._backup_config_detection(),
            self._error_disclosure(),
            self._cms_detection(),
        )
        return self.findings

    # ------------------------------------------------------------------
    # 1. Directory Discovery
    # ------------------------------------------------------------------

    async def _directory_discovery(self) -> None:
        paths = self._load_paths()
        if not paths:
            self.log("No paths loaded from payloads/paths.txt, skipping directory discovery.")
            return

        base = self.target.base_url
        semaphore = asyncio.Semaphore(10)

        # Fetch soft-404 baseline (uses base class method)
        baseline_body = await self.fetch_soft404_baseline()

        async def check_path(path: str) -> None:
            url = f"{base}/{path.lstrip('/')}"
            async with semaphore:
                try:
                    response = await self.http.head(url)
                except Exception:
                    return

                status = response.status_code
                if status not in (200, 301, 302, 403):
                    return

                # For 200 responses, do a GET and check for soft-404
                if status == 200 and baseline_body:
                    try:
                        full_resp = await self.http.get(url)
                        if self.is_soft_404(full_resp.text, baseline_body):
                            return
                    except Exception:
                        pass

                normalized_path = "/" + path.lstrip("/")
                is_admin = normalized_path.rstrip("/") in {p.rstrip("/") for p in ADMIN_PATHS}
                is_config = normalized_path in SENSITIVE_CONFIG_PATHS

                if status == 200:
                    if is_admin:
                        self.add_finding(
                            title=f"Admin Panel Accessible: {normalized_path}",
                            severity="High",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-200",
                            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                            owasp="A01:2021 -- Broken Access Control",
                            url=url,
                            description=f"The admin panel at {normalized_path} is directly accessible without authentication.",
                            steps_to_reproduce=[f"Navigate to {url}"],
                            impact="Unauthorized access to admin functionality may allow full application compromise.",
                            remediation="Restrict admin panel access via IP whitelisting, VPN, or strong authentication.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        )
                    elif is_config:
                        self.add_finding(
                            title=f"Sensitive Config File Accessible: {normalized_path}",
                            severity="High",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-538",
                            cwe_name="Insertion of Sensitive Information into Externally-Accessible File or Directory",
                            owasp="A05:2021 -- Security Misconfiguration",
                            url=url,
                            description=f"A sensitive configuration file was found accessible at {normalized_path}.",
                            steps_to_reproduce=[f"Navigate to {url}"],
                            impact="Configuration files may contain database credentials, API keys, or internal architecture details.",
                            remediation="Block access to configuration files via web server rules. Move sensitive files outside the webroot.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        )
                    else:
                        self.add_finding(
                            title=f"Directory/File Discovered: {normalized_path}",
                            severity="Info",
                            cvss_score=0.0,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            cwe_id="CWE-200",
                            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                            owasp="A05:2021 -- Security Misconfiguration",
                            url=url,
                            description=f"The path {normalized_path} returned HTTP {status}.",
                            impact="Discovered paths reveal application structure and may contain sensitive information.",
                            remediation="Review discovered paths and restrict access where appropriate.",
                        )
                elif status == 403 and is_admin:
                    self.add_finding(
                        title=f"Admin Panel Exists but Restricted: {normalized_path}",
                        severity="Info",
                        cvss_score=0.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                        owasp="A01:2021 -- Broken Access Control",
                        url=url,
                        description=f"An admin panel was detected at {normalized_path} (HTTP 403). Access is currently restricted.",
                        impact="The existence of an admin panel is confirmed, which may assist in targeted attacks.",
                        remediation="Ensure robust authentication and consider hiding admin panel paths.",
                    )

        tasks = [check_path(p) for p in paths]
        await asyncio.gather(*tasks)

    def _load_paths(self) -> list[str]:
        """Load directory/file paths from payloads/paths.txt."""
        paths_file = Path(__file__).resolve().parent.parent.parent / "payloads" / "paths.txt"
        try:
            text = paths_file.read_text(encoding="utf-8")
            return [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        except FileNotFoundError:
            self.log(f"Payloads file not found: {paths_file}")
            return []

    # ------------------------------------------------------------------
    # 2. Backup & Config File Detection
    # ------------------------------------------------------------------

    async def _backup_config_detection(self) -> None:
        base = self.target.base_url
        semaphore = asyncio.Semaphore(10)

        # Fetch soft-404 baseline (uses base class method)
        baseline_body = await self.fetch_soft404_baseline()

        async def check_file(path: str, description: str) -> None:
            url = f"{base}/{path}"
            async with semaphore:
                try:
                    response = await self.http.get(url)
                except Exception:
                    return

                if response.status_code != 200:
                    return

                # Filter soft-404 pages
                if self.is_soft_404(response.text, baseline_body):
                    return

                is_git = path.startswith(".git/")

                self.add_finding(
                    title=f"{'Git Repository Exposed' if is_git else f'Sensitive File Accessible: {path}'}",
                    severity="High",
                    cvss_score=8.1 if is_git else 7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                    if is_git
                    else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-538",
                    cwe_name="Insertion of Sensitive Information into Externally-Accessible File or Directory",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=url,
                    description=(
                        f"The Git repository metadata is exposed at /{path}. "
                        "An attacker can reconstruct the full source code."
                        if is_git
                        else f"The file {path} ({description}) is publicly accessible."
                    ),
                    steps_to_reproduce=[f"Navigate to {url}"],
                    impact=(
                        "Full source code, credentials, and commit history may be extracted from the exposed Git repository."
                        if is_git
                        else f"The {description.lower()} may contain credentials, API keys, or sensitive configuration."
                    ),
                    remediation=(
                        "Block access to .git directories via web server configuration."
                        if is_git
                        else f"Remove {path} from the webroot or block access via web server configuration."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                )

        tasks = [check_file(path, desc) for path, desc in BACKUP_CONFIG_PATHS]
        await asyncio.gather(*tasks)

    # ------------------------------------------------------------------
    # 3. Information Disclosure via Errors
    # ------------------------------------------------------------------

    async def _error_disclosure(self) -> None:
        url = f"{self.target.base_url}/vapt-test-404-xxx"
        try:
            response = await self.http.get(url)
        except Exception:
            return

        body = response.text
        disclosed: list[str] = []

        for category, patterns in ERROR_KEYWORDS.items():
            for pattern in patterns:
                if pattern.lower() in body.lower():
                    disclosed.append(f"{category}: matched '{pattern}'")
                    break  # One match per category is enough

        if disclosed:
            self.add_finding(
                title="Detailed Error Information Disclosed",
                severity="Medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                cwe_id="CWE-209",
                cwe_name="Generation of Error Message Containing Sensitive Information",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description=(
                    "The application error page reveals sensitive technical information.\n"
                    "Detected disclosures:\n" + "\n".join(f"  - {d}" for d in disclosed)
                ),
                steps_to_reproduce=[
                    f"Send a GET request to {url}",
                    "Examine the response body for technical details.",
                ],
                evidence_response=body[:2000],
                impact="Technical details in error pages help attackers map the application stack and craft targeted exploits.",
                remediation="Configure custom error pages that do not reveal stack traces, file paths, or framework details. Disable debug mode in production.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )

    # ------------------------------------------------------------------
    # 4. CMS Detection
    # ------------------------------------------------------------------

    async def _cms_detection(self) -> None:
        base = self.target.base_url
        cms_detected: str | None = None
        cms_version: str | None = None

        # Soft-404 baseline
        baseline_body = await self.fetch_soft404_baseline()

        # Fetch homepage for content-based checks
        try:
            homepage_resp = await self.http.get(self.target.url)
            homepage_body = homepage_resp.text
        except Exception:
            homepage_body = ""

        # --- WordPress ---
        wp_indicators = 0
        # Strong indicator: wp-content in homepage source (not a soft-404 artifact)
        if "wp-content" in homepage_body:
            wp_indicators += 2  # Strong signal — actual WordPress content

        for wp_path in ("/wp-login.php", "/wp-admin/"):
            try:
                resp = await self.http.get(f"{base}{wp_path}")
                if resp.status_code in (200, 301, 302):
                    # Must NOT be a soft-404 to count
                    if resp.status_code == 200 and self.is_soft_404(resp.text, baseline_body):
                        continue
                    wp_indicators += 1
            except Exception:
                pass

        # Require at least 2 indicators to confirm WordPress
        if wp_indicators >= 2:
            cms_detected = "WordPress"
            # Try to extract version from meta tag or feed
            version_match = re.search(
                r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)',
                homepage_body,
                re.IGNORECASE,
            )
            if version_match:
                cms_version = version_match.group(1)

        # --- Drupal ---
        if not cms_detected:
            try:
                resp = await self.http.get(f"{base}/core/CHANGELOG.txt")
                if resp.status_code == 200 and not self.is_soft_404(resp.text, baseline_body) and "drupal" in resp.text.lower():
                    cms_detected = "Drupal"
                    version_match = re.search(r"Drupal\s+([\d.]+)", resp.text)
                    if version_match:
                        cms_version = version_match.group(1)
            except Exception:
                pass

        # --- Joomla ---
        if not cms_detected:
            try:
                resp = await self.http.get(f"{base}/administrator/")
                if resp.status_code in (200, 301, 302) and not self.is_soft_404(resp.text, baseline_body):
                    cms_detected = "Joomla"
                    # Try manifest for version
                    try:
                        manifest = await self.http.get(f"{base}/administrator/manifests/files/joomla.xml")
                        if manifest.status_code == 200:
                            ver_match = re.search(r"<version>([\d.]+)</version>", manifest.text)
                            if ver_match:
                                cms_version = ver_match.group(1)
                    except Exception:
                        pass
            except Exception:
                pass

        if cms_detected:
            # Store in context for other scanners
            self.context["cms"] = cms_detected
            if cms_version:
                self.context["cms_version"] = cms_version

            self.add_finding(
                title=f"CMS Detected: {cms_detected}",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=self.target.url,
                description=f"The application is running {cms_detected}"
                + (f" version {cms_version}." if cms_version else "."),
                impact=f"Knowing the CMS ({cms_detected}) allows attackers to target CMS-specific vulnerabilities and default configurations.",
                remediation=f"Keep {cms_detected} and all plugins up to date. Remove version identifiers from public-facing pages.",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            )

            if cms_version:
                self.add_finding(
                    title=f"{cms_detected} Version Exposed: {cms_version}",
                    severity="Low",
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                    owasp="A05:2021 -- Security Misconfiguration",
                    url=self.target.url,
                    description=f"The {cms_detected} version ({cms_version}) is publicly exposed, aiding targeted attacks.",
                    impact="Version information allows attackers to search for known vulnerabilities specific to this release.",
                    remediation=f"Remove version information from HTML meta tags, changelogs, and default files. Update {cms_detected} to the latest version.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                )
