"""Security Posture Score calculator."""

from vapt.models.score import CategoryScore, PostureScore


# Category weights from VAPT methodology
CATEGORY_WEIGHTS = {
    "injection": 0.20,
    "authentication": 0.15,
    "authorization": 0.12,
    "api": 0.12,
    "ssl": 0.10,
    "headers": 0.08,
    "network": 0.08,
    "scan": 0.07,
    "logic": 0.05,
    "recon": 0.03,
}

# Display names
CATEGORY_NAMES = {
    "injection": "Injection",
    "authentication": "Authentication",
    "authorization": "Authorization",
    "api": "API Security",
    "ssl": "SSL/TLS",
    "headers": "Security Headers",
    "network": "Network Exposure",
    "scan": "Web App Surface",
    "logic": "Business Logic",
    "recon": "Recon Exposure",
}

SEVERITY_PENALTIES = {
    "Critical": 40,
    "High": 25,
    "Medium": 15,
    "Low": 5,
    "Info": 0,
}


def calculate_posture_score(findings: list) -> PostureScore:
    """Calculate Security Posture Score from findings.

    Args:
        findings: List of Finding objects or dicts with 'category' and 'severity'.

    Returns:
        PostureScore with overall score, rating, and category breakdown.
    """
    # Accumulate penalties per category
    penalties = {cat: 0 for cat in CATEGORY_WEIGHTS}
    finding_counts = {cat: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
                      for cat in CATEGORY_WEIGHTS}

    total = 0
    for f in findings:
        cat = f.category if hasattr(f, 'category') else f.get("category", "")
        sev = f.severity if hasattr(f, 'severity') else f.get("severity", "Info")
        cat = cat.lower()
        total += 1
        if cat in penalties:
            penalties[cat] += SEVERITY_PENALTIES.get(sev, 0)
            finding_counts[cat][sev] = finding_counts[cat].get(sev, 0) + 1

    # Calculate per-category scores
    categories = []
    for cat, weight in CATEGORY_WEIGHTS.items():
        raw = max(0, 100 - penalties[cat])
        weighted = round(raw * weight, 1)
        categories.append(CategoryScore(
            name=CATEGORY_NAMES.get(cat, cat),
            weight=weight,
            raw_score=raw,
            weighted_score=weighted,
            finding_counts=finding_counts.get(cat, {}),
        ))

    overall = sum(c.weighted_score for c in categories)
    overall = round(min(100, max(0, overall)), 1)

    if overall >= 90:
        rating = "Excellent"
    elif overall >= 70:
        rating = "Good"
    elif overall >= 50:
        rating = "Fair"
    elif overall >= 30:
        rating = "Poor"
    else:
        rating = "Critical"

    return PostureScore(
        overall_score=overall,
        rating=rating,
        categories=categories,
        total_findings=total,
    )
