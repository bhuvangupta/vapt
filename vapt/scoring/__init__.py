"""Scoring engine for VAPT findings."""

from vapt.scoring.cvss import calculate_cvss
from vapt.scoring.posture import calculate_posture_score

__all__ = ["calculate_cvss", "calculate_posture_score"]
