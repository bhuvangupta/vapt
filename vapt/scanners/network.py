"""Network scanner — passive port scanning and service risk assessment."""

from __future__ import annotations

import asyncio
import re

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding
from vapt.utils import run_command

# Port -> (service name, description)
COMMON_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol v3"),
    143: ("IMAP", "Internet Message Access Protocol"),
    443: ("HTTPS", "HTTPS"),
    445: ("SMB", "Server Message Block"),
    993: ("IMAPS", "IMAP over SSL"),
    995: ("POP3S", "POP3 over SSL"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    5900: ("VNC", "Virtual Network Computing"),
    6379: ("Redis", "Redis In-Memory Store"),
    8080: ("HTTP-Alt", "HTTP Alternate"),
    8443: ("HTTPS-Alt", "HTTPS Alternate"),
    9090: ("Proxy", "Web Proxy"),
    27017: ("MongoDB", "MongoDB Database"),
}

# Ports that carry specific risk assessments
SERVICE_RISKS: dict[int, dict] = {
    21: {
        "title": "FTP Service Detected (Cleartext Protocol)",
        "severity": "Medium",
        "cvss_score": 5.3,
        "description": "FTP transmits credentials and data in cleartext, vulnerable to sniffing.",
        "remediation": "Replace FTP with SFTP or SCP. If FTP is required, enforce FTPS (FTP over TLS).",
    },
    23: {
        "title": "Telnet Service Detected (Cleartext Protocol)",
        "severity": "High",
        "cvss_score": 7.4,
        "description": "Telnet transmits all data including credentials in cleartext with no authentication encryption.",
        "remediation": "Disable Telnet and use SSH for remote administration.",
    },
    445: {
        "title": "SMB Service Exposed to Network",
        "severity": "Medium",
        "cvss_score": 5.0,
        "description": "SMB port is exposed, potentially vulnerable to EternalBlue and other SMB exploits.",
        "remediation": "Restrict SMB access via firewall rules. Ensure SMBv1 is disabled and all patches are applied.",
    },
    3306: {
        "title": "MySQL Database Port Publicly Accessible",
        "severity": "High",
        "cvss_score": 7.5,
        "description": "MySQL database port is exposed to the network, allowing remote connection attempts.",
        "remediation": "Restrict database access to application servers only using firewall rules. Bind to localhost if possible.",
    },
    5432: {
        "title": "PostgreSQL Database Port Publicly Accessible",
        "severity": "High",
        "cvss_score": 7.5,
        "description": "PostgreSQL database port is exposed to the network, allowing remote connection attempts.",
        "remediation": "Restrict database access to application servers only using firewall rules. Bind to localhost if possible.",
    },
    6379: {
        "title": "Redis Service Exposed (Often No Authentication)",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "Redis is exposed to the network and commonly runs without authentication, allowing full data access and command execution.",
        "remediation": "Bind Redis to localhost, enable authentication with a strong password, and restrict access via firewall.",
    },
    27017: {
        "title": "MongoDB Service Exposed (Often No Authentication)",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "MongoDB is exposed to the network. Default configurations often lack authentication, allowing full database access.",
        "remediation": "Enable authentication, bind to localhost, and restrict access via firewall rules.",
    },
    3389: {
        "title": "RDP Service Exposed (Brute Force Target)",
        "severity": "Medium",
        "cvss_score": 5.0,
        "description": "Remote Desktop Protocol is exposed, making it a common target for brute-force and credential stuffing attacks.",
        "remediation": "Restrict RDP access via VPN or firewall. Enable Network Level Authentication and account lockout policies.",
    },
    5900: {
        "title": "VNC Service Exposed (Weak Authentication Common)",
        "severity": "Medium",
        "cvss_score": 5.0,
        "description": "VNC is exposed to the network. VNC implementations frequently have weak authentication mechanisms.",
        "remediation": "Restrict VNC access via VPN or SSH tunneling. Use strong passwords and consider alternatives like RDP or SSH.",
    },
}


@register_scanner
class NetworkScanner(BaseScanner):
    name = "network"
    category = "network"
    weight = 0.08
    active = False

    async def scan(self) -> list[Finding]:
        domain = self.target.domain

        open_ports = await self._scan_ports(domain)

        # Store discovered ports in context for other scanners
        self.context["open_ports"] = open_ports

        self._assess_service_risks(domain, open_ports)

        return self.findings

    # ------------------------------------------------------------------
    # 1. Port Scanning
    # ------------------------------------------------------------------

    async def _scan_ports(self, domain: str) -> list[tuple[int, str]]:
        """Scan ports and return list of (port, service_name) tuples."""
        if self.tools.available("nmap"):
            result = await self._scan_with_nmap(domain)
            if result is not None:
                return result

        # Fallback: async socket scan
        return await self._scan_with_sockets(domain)

    async def _scan_with_nmap(self, domain: str) -> list[tuple[int, str]] | None:
        """Use nmap for port scanning. Returns None if nmap fails."""
        self.log(f"Running nmap scan on {domain}")
        returncode, stdout, stderr = await run_command(
            ["nmap", "-sT", "-T4", "--top-ports", "100", "-oG", "-", domain],
            timeout=120,
        )

        if returncode != 0:
            self.log(f"nmap failed (rc={returncode}): {stderr}")
            return None

        open_ports: list[tuple[int, str]] = []
        for line in stdout.splitlines():
            if "/open/" not in line:
                continue
            # Parse grepable format: port matches like 80/open/tcp//http//
            port_matches = re.findall(r"(\d+)/open/tcp//([^/]*)/", line)
            for port_str, service in port_matches:
                port = int(port_str)
                service_name = COMMON_PORTS.get(port, (service or "unknown", ""))[0]
                open_ports.append((port, service_name))

        if open_ports:
            self.add_finding(
                title=f"Port Scan Results: {len(open_ports)} Open Ports Discovered",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=self.target.url,
                confidence="firm",
                description=f"Port scan of {domain} discovered {len(open_ports)} open ports via nmap.",
                evidence_response="\n".join(
                    f"  {port}/tcp  open  {svc}" for port, svc in sorted(open_ports)
                ),
                impact="Open ports expand the attack surface. Each exposed service is a potential entry point.",
                remediation="Close unnecessary ports and restrict access to required services using firewall rules.",
                references=["https://nmap.org/book/man.html"],
            )

        return open_ports

    async def _scan_with_sockets(self, domain: str) -> list[tuple[int, str]]:
        """Fallback: scan common ports using asyncio sockets with concurrency control."""
        self.log(f"Running socket-based port scan on {domain}")
        semaphore = asyncio.Semaphore(10)
        open_ports: list[tuple[int, str]] = []
        lock = asyncio.Lock()

        async def check_port(port: int) -> None:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(domain, port),
                        timeout=3,
                    )
                    writer.close()
                    await writer.wait_closed()
                    service_name = COMMON_PORTS.get(port, ("unknown", ""))[0]
                    async with lock:
                        open_ports.append((port, service_name))
                except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                    pass

        tasks = [check_port(port) for port in COMMON_PORTS]
        await asyncio.gather(*tasks)

        if open_ports:
            self.add_finding(
                title=f"Port Scan Results: {len(open_ports)} Open Ports Discovered",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=self.target.url,
                confidence="firm",
                description=f"Socket-based port scan of {domain} discovered {len(open_ports)} open ports.",
                evidence_response="\n".join(
                    f"  {port}/tcp  open  {svc}" for port, svc in sorted(open_ports)
                ),
                impact="Open ports expand the attack surface. Each exposed service is a potential entry point.",
                remediation="Close unnecessary ports and restrict access to required services using firewall rules.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )

        return open_ports

    # ------------------------------------------------------------------
    # 2. Service Risk Assessment
    # ------------------------------------------------------------------

    def _assess_service_risks(self, domain: str, open_ports: list[tuple[int, str]]) -> None:
        """Evaluate risk for each open port based on known service profiles."""
        for port, service_name in open_ports:
            risk = SERVICE_RISKS.get(port)
            if risk is None:
                continue

            # Determine CWE based on risk type
            is_db_or_noauth = port in (3306, 5432, 6379, 27017)
            cwe_id = "CWE-284" if is_db_or_noauth else "CWE-200"
            cwe_name = (
                "Improper Access Control"
                if is_db_or_noauth
                else "Exposure of Sensitive Information to an Unauthorized Actor"
            )

            self.add_finding(
                title=risk["title"],
                severity=risk["severity"],
                cvss_score=risk["cvss_score"],
                cvss_vector=self._cvss_vector_for_severity(risk["severity"], risk["cvss_score"]),
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                owasp="A05:2021 -- Security Misconfiguration",
                url=f"{self.target.base_url}:{port}" if port not in (80, 443) else self.target.url,
                confidence="firm",
                description=risk["description"],
                evidence_response=f"Port {port}/tcp ({service_name}) is open on {domain}.",
                impact=f"The {service_name} service on port {port} is accessible from the network, increasing the attack surface.",
                remediation=risk["remediation"],
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                ],
            )

    @staticmethod
    def _cvss_vector_for_severity(severity: str, score: float) -> str:
        """Return an approximate CVSS vector matching the severity/score."""
        vectors = {
            "Critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "Medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "Low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "Info": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        }
        return vectors.get(severity, vectors["Medium"])
