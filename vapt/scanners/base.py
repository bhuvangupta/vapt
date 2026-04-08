"""Base scanner abstract class."""

from abc import ABC, abstractmethod
from vapt.models.finding import Finding
from vapt.models.target import TargetConfig
from vapt.tools import ToolRegistry
from vapt.utils import AsyncHttpClient


class BaseScanner(ABC):
    """Abstract base class for all VAPT scanners.

    Subclasses must set class-level attributes:
        name: str — scanner identifier (e.g., "recon")
        category: str — scoring category key
        weight: float — scoring weight (0.0 to 1.0)
        active: bool — True if scanner requires --active flag
    """

    name: str = ""
    category: str = ""
    weight: float = 0.0
    active: bool = False  # passive by default

    def __init__(self, target: TargetConfig, http: AsyncHttpClient,
                 tools: ToolRegistry, settings: dict, context: dict | None = None):
        self.target = target
        self.http = http
        self.tools = tools
        self.settings = settings
        self.context = context or {}
        self.findings: list[Finding] = []
        self._finding_counter = 0

    def requires_active(self) -> bool:
        return self.active

    @abstractmethod
    async def scan(self) -> list[Finding]:
        """Execute all tests and return findings."""
        ...

    # Title prefixes that indicate heuristic findings
    _HEURISTIC_PREFIXES = ("potential", "possible", "suspected", "likely")

    def add_finding(self, **kwargs) -> Finding:
        """Helper to create and register a finding.

        Enforces confidence consistency: if the title starts with a
        heuristic keyword (Potential, Possible, etc.) but confidence is
        not explicitly set, it is auto-set to ``tentative``.
        """
        self._finding_counter += 1

        # Central guardrail: infer tentative when title signals heuristic
        title = kwargs.get("title", "")
        confidence = kwargs.get("confidence", "confirmed")
        if confidence == "confirmed" and title.lower().startswith(self._HEURISTIC_PREFIXES):
            kwargs["confidence"] = "tentative"

        finding = Finding(
            id=f"FINDING-{self._finding_counter:03d}",
            scanner=self.name,
            category=self.category,
            **kwargs,
        )
        self.findings.append(finding)
        return finding

    def build_auth_headers(self) -> dict[str, str]:
        """Build authentication headers from target config.

        Supports bearer token, API key, and basic auth. Returns an empty
        dict if no auth is configured. Scanners should pass the result as
        ``headers=self.build_auth_headers()`` for authenticated requests.
        """
        if not self.target.has_auth():
            return {}

        headers: dict[str, str] = {}
        auth = self.target.auth or {}
        header_name = auth.get("token_header", "Authorization")

        if auth.get("api_key"):
            headers[header_name] = auth["api_key"]
        elif auth.get("token"):
            headers[header_name] = f"Bearer {auth['token']}"

        return headers

    # ── Soft-404 detection ──────────────────────────────────────────────

    SOFT_404_KEYWORDS = (
        "404", "not found", "page not found", "does not exist",
        "cannot be found", "could not find", "no longer available",
        "page you requested", "page is not available",
        "sorry but we could not find",
    )

    async def fetch_soft404_baseline(self) -> str:
        """Fetch a known-nonexistent path and return its body.

        If the server returns HTTP 200 for a garbage path (common with
        SPAs), the body is the soft-404 baseline.  Returns an empty
        string when the server returns a proper 404 status.
        """
        try:
            resp = await self.http.get(
                f"{self.target.base_url}/vapt-nonexistent-{id(self)}"
            )
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return ""

    def is_soft_404(self, body: str, baseline_body: str = "") -> bool:
        """Return True if *body* looks like a soft-404 page.

        Checks for common 404 keywords and, when a *baseline_body* is
        provided, whether the two bodies are within 10% length of each
        other (indicating the same SPA shell).
        """
        lower = body.lower()
        if any(kw in lower for kw in self.SOFT_404_KEYWORDS):
            return True
        if baseline_body:
            bl = len(baseline_body)
            if bl > 0 and abs(len(body) - bl) / bl < 0.10:
                return True
        return False

    def log(self, msg: str):
        """Log a message (picked up by runner for display)."""
        # Will be replaced by proper logging in runner
        pass
