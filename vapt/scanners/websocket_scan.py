"""WebSocket security scanner — discovery, CSWSH, transport security, and protocol detection."""

from __future__ import annotations

import asyncio

from vapt.scanners import register_scanner
from vapt.scanners.base import BaseScanner
from vapt.models.finding import Finding

# Paths commonly used for WebSocket endpoints
WS_PATHS = [
    "/ws", "/wss", "/websocket", "/socket", "/socket.io/",
    "/sockjs/", "/cable", "/hub", "/realtime", "/live",
]

# Headers required for a WebSocket upgrade handshake
WS_UPGRADE_HEADERS = {
    "Upgrade": "websocket",
    "Connection": "Upgrade",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
    "Sec-WebSocket-Version": "13",
}


@register_scanner
class WebSocketScanner(BaseScanner):
    name = "websocket"
    category = "api"
    weight = 0.0
    active = True

    async def scan(self) -> list[Finding]:
        await self._ws_discovery()
        ws_endpoints = self.context.get("ws_endpoints", [])
        if ws_endpoints:
            await asyncio.gather(
                self._origin_validation(ws_endpoints),
                self._transport_security(ws_endpoints),
            )
        await self._socketio_detection()
        return self.findings

    # ------------------------------------------------------------------
    # 1. WebSocket Discovery
    # ------------------------------------------------------------------

    async def _ws_discovery(self) -> None:
        base = self.target.base_url
        found: list[str] = []
        semaphore = asyncio.Semaphore(10)

        async def check_path(path: str) -> None:
            url = f"{base}{path}"
            async with semaphore:
                try:
                    response = await self.http.get(url, headers=WS_UPGRADE_HEADERS)
                except Exception:
                    return

                if response.status_code == 101:
                    found.append(url)
                    self.add_finding(
                        title=f"WebSocket Endpoint Discovered: {path}",
                        severity="Info",
                        cvss_score=0.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                        owasp="A05:2021 -- Security Misconfiguration",
                        url=url,
                        description=(
                            f"A WebSocket endpoint was found at {path}. "
                            "The server responded with 101 Switching Protocols."
                        ),
                        steps_to_reproduce=[
                            f"Send a GET request to {url} with WebSocket upgrade headers.",
                            "Observe the 101 Switching Protocols response.",
                        ],
                        impact="WebSocket endpoints may expose real-time data channels that bypass traditional HTTP security controls.",
                        remediation="Ensure WebSocket endpoints enforce authentication, authorization, and input validation.",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/",
                            "https://portswigger.net/web-security/websockets",
                        ],
                    )

        tasks = [check_path(p) for p in WS_PATHS]
        await asyncio.gather(*tasks)

        if found:
            self.context["ws_endpoints"] = found

    # ------------------------------------------------------------------
    # 2. Origin Validation (Cross-Site WebSocket Hijacking)
    # ------------------------------------------------------------------

    async def _origin_validation(self, endpoints: list[str]) -> None:
        evil_headers = {
            **WS_UPGRADE_HEADERS,
            "Origin": "https://evil.com",
        }

        for url in endpoints:
            try:
                response = await self.http.get(url, headers=evil_headers)
            except Exception:
                continue

            if response.status_code == 101:
                self.add_finding(
                    title="Cross-Site WebSocket Hijacking (CSWSH)",
                    severity="High",
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-346",
                    cwe_name="Origin Validation Error",
                    owasp="A01:2021 -- Broken Access Control",
                    url=url,
                    description=(
                        f"The WebSocket endpoint at {url} accepted a connection with "
                        "Origin: https://evil.com. This indicates the server does not "
                        "validate the Origin header, allowing Cross-Site WebSocket Hijacking."
                    ),
                    steps_to_reproduce=[
                        f"Send a WebSocket upgrade request to {url} with Origin: https://evil.com.",
                        "Observe that the server responds with 101 Switching Protocols.",
                    ],
                    evidence_request=f"GET {url} with Origin: https://evil.com",
                    evidence_response=f"HTTP/1.1 101 Switching Protocols",
                    impact=(
                        "An attacker can hijack authenticated WebSocket connections from a victim's browser, "
                        "potentially reading sensitive data or sending commands on behalf of the user."
                    ),
                    remediation=(
                        "Validate the Origin header on the server side. "
                        "Only allow connections from trusted origins. "
                        "Implement CSRF tokens for WebSocket handshakes."
                    ),
                    references=[
                        "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                )

    # ------------------------------------------------------------------
    # 3. Transport Security
    # ------------------------------------------------------------------

    async def _transport_security(self, endpoints: list[str]) -> None:
        for url in endpoints:
            if url.startswith("http://") or url.startswith("ws://"):
                self.add_finding(
                    title="WebSocket Using Unencrypted Transport (ws://)",
                    severity="Medium",
                    cvss_score=5.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    owasp="A02:2021 -- Cryptographic Failures",
                    url=url,
                    description=(
                        f"The WebSocket endpoint at {url} uses an unencrypted transport. "
                        "Data transmitted over ws:// can be intercepted by attackers on the network path."
                    ),
                    steps_to_reproduce=[
                        f"Observe that the WebSocket URL is {url} (unencrypted).",
                        "Use a network sniffer to capture WebSocket frames in transit.",
                    ],
                    impact="Sensitive data exchanged over the WebSocket connection can be intercepted via man-in-the-middle attacks.",
                    remediation="Use wss:// (WebSocket Secure) instead of ws://. Ensure TLS is properly configured.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/",
                        "https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API",
                    ],
                )

    # ------------------------------------------------------------------
    # 4. Socket.IO Detection
    # ------------------------------------------------------------------

    async def _socketio_detection(self) -> None:
        url = f"{self.target.base_url}/socket.io/?EIO=4&transport=polling"
        try:
            response = await self.http.get(url)
        except Exception:
            return

        if response.status_code == 200 and "sid" in response.text:
            self.context["socketio_detected"] = True
            self.add_finding(
                title="Socket.IO Protocol Detected",
                severity="Info",
                cvss_score=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cwe_id="CWE-200",
                cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="A05:2021 -- Security Misconfiguration",
                url=url,
                description=(
                    "The application uses the Socket.IO protocol. "
                    "A polling transport session was successfully established, "
                    "indicating a Socket.IO server is running."
                ),
                steps_to_reproduce=[
                    f"Send a GET request to {url}.",
                    "Observe that a Socket.IO session ID (sid) is returned.",
                ],
                evidence_response=response.text[:500],
                impact="Socket.IO exposes additional attack surface including event-based messaging and namespace access.",
                remediation="Ensure Socket.IO namespaces and events enforce authentication and authorization. Disable unused namespaces.",
                references=[
                    "https://socket.io/docs/v4/",
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            )
