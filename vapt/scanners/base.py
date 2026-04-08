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

    def log(self, msg: str):
        """Log a message (picked up by runner for display)."""
        # Will be replaced by proper logging in runner
        pass
