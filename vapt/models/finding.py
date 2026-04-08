from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass
class Finding:
    """A single security finding from a VAPT scan."""

    SEVERITY_ORDER: dict[str, int] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    id: str  # e.g. "FINDING-001"
    title: str
    severity: str  # Critical / High / Medium / Low / Info
    cvss_score: float
    cvss_vector: str  # CVSS:3.1/AV:N/AC:L/...
    cwe_id: str  # CWE-89
    cwe_name: str
    owasp: str  # e.g. "A03:2021 -- Injection"
    category: str  # injection/authentication/authorization/api/ssl/headers/network/scan/logic/recon
    url: str
    parameter: str = ""
    description: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    evidence_request: str = ""
    evidence_response: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    scanner: str = ""
    confidence: str = "confirmed"  # confirmed | firm | tentative
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        # Set the class-level constant on every instance so it is always accessible.
        object.__setattr__(self, "SEVERITY_ORDER", {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Info": 4,
        })

    def to_dict(self) -> dict:
        """Return all fields as a plain dictionary."""
        d = asdict(self)
        # asdict will include SEVERITY_ORDER; keep it for completeness.
        return d
