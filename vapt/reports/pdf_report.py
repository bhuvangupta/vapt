"""PDF Report Generator using ReportLab."""

import os
from datetime import datetime, timezone

from vapt.models.finding import Finding
from vapt.models.score import PostureScore

# Severity colors (hex values for both HTML and PDF use)
SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#2563EB",
    "info": "#6B7280",
    "pass": "#16A34A",
}

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


COLORS_RL = {}
if HAS_REPORTLAB:
    COLORS_RL = {
        "critical": colors.HexColor("#DC2626"),
        "high": colors.HexColor("#EA580C"),
        "medium": colors.HexColor("#CA8A04"),
        "low": colors.HexColor("#2563EB"),
        "info": colors.HexColor("#6B7280"),
        "pass": colors.HexColor("#16A34A"),
        "header_bg": colors.HexColor("#1E293B"),
        "header_text": colors.white,
        "row_alt": colors.HexColor("#F8FAFC"),
    }


# ---------------------------------------------------------------------------
# Style factory
# ---------------------------------------------------------------------------

def _build_styles():
    """Create the paragraph styles used throughout the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CoverTitle",
        fontName="Helvetica-Bold",
        fontSize=28,
        leading=34,
        alignment=TA_CENTER,
        spaceAfter=20,
        textColor=colors.HexColor("#1E293B"),
    ))
    styles.add(ParagraphStyle(
        name="CoverTarget",
        fontName="Helvetica",
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        spaceAfter=12,
        textColor=colors.HexColor("#475569"),
    ))
    styles.add(ParagraphStyle(
        name="CoverDate",
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        alignment=TA_CENTER,
        spaceAfter=8,
        textColor=colors.HexColor("#64748B"),
    ))
    styles.add(ParagraphStyle(
        name="Confidential",
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#DC2626"),
    ))
    styles.add(ParagraphStyle(
        name="SectionTitle",
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        spaceAfter=12,
        spaceBefore=24,
        textColor=colors.HexColor("#1E293B"),
    ))
    styles.add(ParagraphStyle(
        name="SubsectionTitle",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        spaceAfter=8,
        spaceBefore=16,
        textColor=colors.HexColor("#334155"),
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        spaceAfter=6,
        spaceBefore=12,
        textColor=colors.HexColor("#1E293B"),
    ))
    styles.add(ParagraphStyle(
        name="BodyText2",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SmallLabel",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748B"),
    ))

    return styles


# ---------------------------------------------------------------------------
# Helper: severity sort key
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4,
}


def _sev_key(finding):
    sev = finding.severity if hasattr(finding, "severity") else finding.get("severity", "Info")
    return _SEVERITY_ORDER.get(sev, 5)


def _get_attr(obj, attr, default=""):
    """Get an attribute from an object or dict."""
    if hasattr(obj, attr):
        return getattr(obj, attr, default)
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return default


def _score_color(score: float):
    """Return a ReportLab color based on score value."""
    if score < 30:
        return COLORS_RL["critical"]
    elif score < 50:
        return COLORS_RL["high"]
    elif score < 70:
        return COLORS_RL["medium"]
    else:
        return COLORS_RL["pass"]


def _severity_color_rl(severity: str):
    """Return the ReportLab color for a severity string."""
    return COLORS_RL.get(severity.lower(), COLORS_RL.get("info", colors.grey))


# ---------------------------------------------------------------------------
# Cover page
# ---------------------------------------------------------------------------

def _build_cover(styles, target_name, target_url):
    """Build cover page elements."""
    elements = []
    elements.append(Spacer(1, 2 * inch))
    elements.append(Paragraph(
        "Vulnerability Assessment<br/>&amp; Penetration Test Report",
        styles["CoverTitle"],
    ))
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph(target_name, styles["CoverTarget"]))
    elements.append(Paragraph(target_url, styles["CoverDate"]))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(
        datetime.now(timezone.utc).strftime("%B %d, %Y  %H:%M UTC"),
        styles["CoverDate"],
    ))
    elements.append(Spacer(1, 1.5 * inch))
    elements.append(Paragraph(
        "CONFIDENTIAL — For authorized recipients only",
        styles["Confidential"],
    ))
    elements.append(PageBreak())
    return elements


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def _build_executive_summary(styles, posture_score, findings):
    """Build the executive summary section."""
    elements = []
    elements.append(Paragraph("Executive Summary", styles["SectionTitle"]))

    # Overall score
    score = posture_score.overall_score
    score_color = _score_color(score)
    score_hex = SEVERITY_COLORS.get("pass") if score >= 70 else (
        SEVERITY_COLORS.get("medium") if score >= 50 else (
            SEVERITY_COLORS.get("high") if score >= 30 else SEVERITY_COLORS.get("critical")
        )
    )
    elements.append(Paragraph(
        f'Security Posture Score: <font color="{score_hex}"><b>{score:.0f}/100 ({posture_score.rating})</b></font>',
        styles["BodyText2"],
    ))
    elements.append(Paragraph(
        f"Total Findings: <b>{posture_score.total_findings}</b>",
        styles["BodyText2"],
    ))
    elements.append(Spacer(1, 0.2 * inch))

    # Severity counts table
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = _get_attr(f, "severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1

    header = ["Severity", "Count"]
    data = [header]
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        data.append([sev, str(counts[sev])])

    table = Table(data, colWidths=[2.5 * inch, 1.5 * inch])
    style_cmds = [
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), COLORS_RL["header_bg"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLORS_RL["header_text"]),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        # Body
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
    ]
    # Zebra striping
    for row_idx in range(1, len(data)):
        if row_idx % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), COLORS_RL["row_alt"]))
        # Color-code severity text
        sev_name = data[row_idx][0]
        sev_color = _severity_color_rl(sev_name)
        style_cmds.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), sev_color))

    table.setStyle(TableStyle(style_cmds))
    elements.append(table)
    elements.append(Spacer(1, 0.3 * inch))
    return elements


# ---------------------------------------------------------------------------
# Category breakdown
# ---------------------------------------------------------------------------

def _build_category_breakdown(styles, posture_score):
    """Build the category breakdown table."""
    elements = []
    elements.append(Paragraph("Category Breakdown", styles["SectionTitle"]))

    header = ["Category", "Weight %", "Score / 100", "Findings"]
    data = [header]

    for cat in posture_score.categories:
        finding_total = sum(cat.finding_counts.values()) if cat.finding_counts else 0
        data.append([
            cat.name,
            f"{cat.weight:.0%}",
            f"{cat.raw_score:.0f}",
            str(finding_total),
        ])

    col_widths = [2.5 * inch, 1.2 * inch, 1.2 * inch, 1.2 * inch]
    table = Table(data, colWidths=col_widths)

    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), COLORS_RL["header_bg"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLORS_RL["header_text"]),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
    ]

    # Zebra striping and score color-coding
    for row_idx in range(1, len(data)):
        if row_idx % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), COLORS_RL["row_alt"]))
        # Color-code the score column
        try:
            score_val = float(data[row_idx][2])
        except (ValueError, IndexError):
            score_val = 100
        style_cmds.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), _score_color(score_val)))
        style_cmds.append(("FONTNAME", (2, row_idx), (2, row_idx), "Helvetica-Bold"))

    table.setStyle(TableStyle(style_cmds))
    elements.append(table)
    elements.append(PageBreak())
    return elements


# ---------------------------------------------------------------------------
# Detailed findings
# ---------------------------------------------------------------------------

def _build_detailed_findings(styles, findings):
    """Build the detailed findings section, sorted by severity."""
    elements = []
    elements.append(Paragraph("Detailed Findings", styles["SectionTitle"]))

    sorted_findings = sorted(findings, key=_sev_key)

    if not sorted_findings:
        elements.append(Paragraph(
            "No findings were identified during the assessment.",
            styles["BodyText2"],
        ))
        return elements

    for idx, finding in enumerate(sorted_findings, 1):
        fid = _get_attr(finding, "id", f"F-{idx:03d}")
        title = _get_attr(finding, "title", "Untitled Finding")
        severity = _get_attr(finding, "severity", "Info")
        sev_hex = SEVERITY_COLORS.get(severity.lower(), SEVERITY_COLORS["info"])

        # Finding title with severity badge + confidence
        confidence = _get_attr(finding, "confidence", "confirmed")
        conf_tag = ""
        if confidence != "confirmed":
            conf_color = "#F59E0B" if confidence == "tentative" else "#6366F1"
            conf_tag = f' <font color="{conf_color}"><b>[{confidence.upper()}]</b></font>'
        elements.append(Paragraph(
            f'<font color="{sev_hex}"><b>[{severity}]</b></font>{conf_tag} '
            f'{fid} — {_escape(title)}',
            styles["FindingTitle"],
        ))

        # Metadata table
        cvss = _get_attr(finding, "cvss_score", 0)
        cvss_vec = _get_attr(finding, "cvss_vector", "")
        cwe = _get_attr(finding, "cwe_id", "")
        cwe_name = _get_attr(finding, "cwe_name", "")
        owasp = _get_attr(finding, "owasp", "")
        confidence_row = confidence
        url = _get_attr(finding, "url", "")
        parameter = _get_attr(finding, "parameter", "")

        meta_data = []
        if cvss:
            meta_data.append(["CVSS Score", f"{cvss} ({cvss_vec})"])
        if cwe:
            cwe_display = f"{cwe} — {cwe_name}" if cwe_name else cwe
            meta_data.append(["CWE", cwe_display])
        if owasp:
            meta_data.append(["OWASP", owasp])
        if url:
            meta_data.append(["URL", _truncate(url, 80)])
        if parameter:
            meta_data.append(["Parameter", parameter])
        if confidence_row != "confirmed":
            meta_data.append(["Confidence", confidence_row.upper()])

        if meta_data:
            meta_table = Table(meta_data, colWidths=[1.2 * inch, 4.8 * inch])
            meta_style = [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748B")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ]
            meta_table.setStyle(TableStyle(meta_style))
            elements.append(meta_table)
            elements.append(Spacer(1, 0.1 * inch))

        # Description
        description = _get_attr(finding, "description", "")
        if description:
            elements.append(Paragraph("<b>Description</b>", styles["SmallLabel"]))
            elements.append(Paragraph(_escape(description), styles["BodyText2"]))

        # Impact
        impact = _get_attr(finding, "impact", "")
        if impact:
            elements.append(Paragraph("<b>Impact</b>", styles["SmallLabel"]))
            elements.append(Paragraph(_escape(impact), styles["BodyText2"]))

        # Remediation
        remediation = _get_attr(finding, "remediation", "")
        if remediation:
            elements.append(Paragraph("<b>Remediation</b>", styles["SmallLabel"]))
            elements.append(Paragraph(_escape(remediation), styles["BodyText2"]))

        elements.append(Spacer(1, 0.15 * inch))

        # Horizontal rule between findings
        if idx < len(sorted_findings):
            hr_data = [["" * 80]]
            hr_table = Table(hr_data, colWidths=[6.2 * inch])
            hr_table.setStyle(TableStyle([
                ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#CBD5E1")),
            ]))
            elements.append(hr_table)
            elements.append(Spacer(1, 0.05 * inch))

    elements.append(PageBreak())
    return elements


# ---------------------------------------------------------------------------
# Methodology
# ---------------------------------------------------------------------------

def _build_methodology(styles, tools_used, active_mode, **kwargs):
    """Build the methodology section."""
    elements = []
    elements.append(Paragraph("Methodology", styles["SectionTitle"]))

    mode_text = (
        "Full assessment including active injection and brute-force tests"
        if active_mode else
        "Passive assessment — no attack payloads were sent to the target"
    )
    elements.append(Paragraph(f"<b>Scan Mode:</b> {mode_text}", styles["BodyText2"]))
    elements.append(Spacer(1, 0.1 * inch))

    if tools_used:
        elements.append(Paragraph("<b>Tools Used:</b>", styles["BodyText2"]))
        tools_text = ", ".join(tools_used) if tools_used else "Python-only (no external tools detected)"
        elements.append(Paragraph(tools_text, styles["BodyText2"]))
    else:
        elements.append(Paragraph(
            "<b>Tools Used:</b> Python-only (no external tools detected)",
            styles["BodyText2"],
        ))

    # Scanner status
    scanner_results = kwargs.get("scanner_results", [])
    if scanner_results:
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("<b>Scanner Status:</b>", styles["BodyText2"]))
        for sr in scanner_results:
            if sr.get("error"):
                elements.append(Paragraph(
                    f"• {sr['name']}: <font color='#DC2626'>ERROR</font> — {sr['error']}",
                    styles["BodyText2"],
                ))
            elif sr.get("skipped"):
                elements.append(Paragraph(
                    f"• {sr['name']}: SKIPPED",
                    styles["BodyText2"],
                ))

    # Limitations
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(Paragraph("<b>Limitations:</b>", styles["BodyText2"]))
    elements.append(Paragraph(
        "Findings marked as 'tentative' are heuristic-based and require manual verification. "
        "Automated scanning cannot replace manual penetration testing.",
        styles["BodyText2"],
    ))

    elements.append(Spacer(1, 0.15 * inch))
    elements.append(Paragraph(
        "This assessment was performed using the VAPT Test Suite, an automated "
        "vulnerability assessment framework. Findings were identified through a "
        "combination of passive analysis and, where authorized, active security "
        "testing techniques.",
        styles["BodyText2"],
    ))

    return elements


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escape(text: str) -> str:
    """Escape text for ReportLab Paragraph XML."""
    if not text:
        return ""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\n", "<br/>")
    )


def _truncate(text: str, max_len: int = 80) -> str:
    """Truncate long strings for display."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf_report(
    findings: list,
    posture_score: PostureScore,
    target_name: str,
    target_url: str,
    authorization: dict,
    tools_used: list[str],
    scanner_results: list[dict],
    active_mode: bool,
    output_path: str,
) -> str:
    """Generate a PDF report and write it to output_path.

    Parameters
    ----------
    findings : list
        List of Finding objects or dicts.
    posture_score : PostureScore
        Calculated posture score with category breakdown.
    target_name : str
        Human-friendly target name.
    target_url : str
        Target URL.
    authorization : dict
        Authorization metadata from config.
    tools_used : list[str]
        Names of external tools that were available.
    scanner_results : list[dict]
        Per-scanner run metadata (name, duration, finding count).
    active_mode : bool
        Whether active testing was performed.
    output_path : str
        Destination file path for the PDF.

    Returns
    -------
    str
        The output_path on success, or empty string on failure.
    """
    if not HAS_REPORTLAB:
        print(
            "WARNING: reportlab is not installed. PDF report skipped. "
            "Install with: pip install reportlab"
        )
        return ""

    styles = _build_styles()

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        title=f"VAPT Report — {target_name}",
        author="VAPT Test Suite",
    )

    elements = []

    # 1. Cover page
    elements.extend(_build_cover(styles, target_name, target_url))

    # 2. Executive summary
    elements.extend(_build_executive_summary(styles, posture_score, findings))

    # 3. Category breakdown
    elements.extend(_build_category_breakdown(styles, posture_score))

    # 4. Detailed findings
    elements.extend(_build_detailed_findings(styles, findings))

    # 5. Methodology
    elements.extend(_build_methodology(styles, tools_used, active_mode, scanner_results=scanner_results))

    try:
        doc.build(elements)
        return output_path
    except Exception as exc:
        print(f"WARNING: PDF generation failed: {exc}")
        return ""
