from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class CategoryScore:
    """Score for a single VAPT category (e.g. injection, ssl)."""

    name: str
    weight: float
    raw_score: float  # 0-100
    weighted_score: float
    finding_counts: dict[str, int] = field(default_factory=dict)  # severity -> count

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PostureScore:
    """Overall security posture score aggregated from category scores."""

    overall_score: float
    rating: str
    categories: list[CategoryScore] = field(default_factory=list)
    total_findings: int = 0

    def to_dict(self) -> dict:
        return asdict(self)
