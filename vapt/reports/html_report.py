"""HTML Report Generator using Jinja2."""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from vapt.models.finding import Finding
from vapt.models.score import PostureScore


TEMPLATE_DIR = Path(__file__).parent / "templates"

# Patterns to redact from evidence fields
_REDACT_PATTERNS = [
    (re.compile(r'(Bearer\s+)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(Authorization:\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(password["\s:=]+)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(token["\s:=]+)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(api[_-]?key["\s:=]+)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(secret["\s:=]+)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(cookie:\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(set-cookie:\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(session[_-]?id["\s:=]+)\S+', re.IGNORECASE), r'\1[REDACTED]'),
]


def _redact_evidence(text: str) -> str:
    """Redact tokens, cookies, passwords, and secrets from evidence text."""
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def generate_html_report(
    findings: list[Finding],
    posture_score: PostureScore,
    target_name: str,
    target_url: str,
    authorization: dict,
    tools_used: list[str],
    scanner_results: list[dict],
    active_mode: bool,
    output_path: str,
) -> str:
    """Generate a self-contained HTML report.

    Produces a single HTML file with all CSS and JS inlined. The report
    mirrors the structure and visual quality of commercial tools like
    Burp Suite Professional.

    Args:
        findings: List of Finding objects (or dicts) from the scan.
        posture_score: Aggregated security posture score.
        target_name: Human-readable name for the target.
        target_url: Base URL that was assessed.
        authorization: Dict with keys ``basis``, ``authorized_by``, ``ref``.
        tools_used: Names of tools invoked during the assessment.
        scanner_results: Per-scanner summary dicts with ``name``,
            ``findings_count``, ``duration``.
        active_mode: Whether active/intrusive testing was performed.
        output_path: Destination file path for the HTML report.

    Returns:
        The resolved *output_path* string.
    """
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")

    # Normalise findings to plain dicts for the template
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(
        [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
        key=lambda f: severity_order.get(f.get("severity", "Info"), 5),
    )

    # Redact sensitive data from evidence fields
    for f in sorted_findings:
        if f.get("evidence_request"):
            f["evidence_request"] = _redact_evidence(f["evidence_request"])
        if f.get("evidence_response"):
            f["evidence_response"] = _redact_evidence(f["evidence_response"])

    # Tally severity counts
    severity_counts: dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }
    for f in sorted_findings:
        sev = f.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    html = template.render(
        title="VAPT Security Assessment Report",
        target_name=target_name,
        target_url=target_url,
        scan_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        authorization=authorization,
        posture_score=posture_score,
        findings=sorted_findings,
        severity_counts=severity_counts,
        tools_used=tools_used,
        scanner_results=scanner_results,
        active_mode=active_mode,
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return output_path


def export_findings_json(
    findings: list[Finding],
    posture_score: PostureScore,
    output_path: str,
) -> str:
    """Export raw findings and posture score as machine-readable JSON.

    Intended for CI/CD pipelines, SIEM ingestion, or downstream
    automation that needs structured data rather than HTML.

    Args:
        findings: List of Finding objects (or dicts).
        posture_score: Aggregated security posture score.
        output_path: Destination file path for the JSON export.

    Returns:
        The resolved *output_path* string.
    """
    findings_dicts = [
        f.to_dict() if hasattr(f, "to_dict") else f for f in findings
    ]

    # Redact sensitive data from evidence fields
    for f in findings_dicts:
        if f.get("evidence_request"):
            f["evidence_request"] = _redact_evidence(f["evidence_request"])
        if f.get("evidence_response"):
            f["evidence_response"] = _redact_evidence(f["evidence_response"])

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "posture_score": posture_score.to_dict(),
        "findings": findings_dicts,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)

    return output_path
