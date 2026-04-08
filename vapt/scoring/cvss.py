"""CVSS v3.1 Score Calculator for VAPT Reports."""

import math

# CVSS v3.1 metric values
METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def roundup(x: float) -> float:
    """CVSS roundup function."""
    return math.ceil(x * 10) / 10


def calculate_cvss(vector: str) -> dict:
    """Calculate CVSS v3.1 score from vector string.

    Args:
        vector: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        dict with score, severity, and parsed metrics.
    """
    parts = vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/")
    m = {}
    for part in parts:
        key, val = part.split(":")
        m[key] = val

    scope = m["S"]
    av = METRICS["AV"][m["AV"]]
    ac = METRICS["AC"][m["AC"]]
    pr = METRICS["PR"][scope][m["PR"]]
    ui = METRICS["UI"][m["UI"]]
    c = METRICS["C"][m["C"]]
    i = METRICS["I"][m["I"]]
    a = METRICS["A"][m["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = roundup(min(impact + exploitability, 10))
    else:
        score = roundup(min(1.08 * (impact + exploitability), 10))

    if score == 0.0:
        severity = "None"
    elif score <= 3.9:
        severity = "Low"
    elif score <= 6.9:
        severity = "Medium"
    elif score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"

    return {
        "vector": vector,
        "score": score,
        "severity": severity,
        "metrics": m,
        "impact_subscore": round(impact, 1),
        "exploitability_subscore": round(exploitability, 1),
    }


def score_to_severity(score: float) -> str:
    """Convert numeric CVSS score to severity label."""
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    return "Critical"
