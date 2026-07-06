"""pdf_export.py — ReportLab PDF export for CVE prioritization reports."""

from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from .config import DEMO_MODE

_TIER_COLORS = {
    "CRITICAL": colors.HexColor("#DC2626"),
    "HIGH":     colors.HexColor("#D97706"),
    "MEDIUM":   colors.HexColor("#2563EB"),
    "LOW":      colors.HexColor("#16A34A"),
}

_TIER_BG = {
    "CRITICAL": colors.HexColor("#FEF2F2"),
    "HIGH":     colors.HexColor("#FFFBEB"),
    "MEDIUM":   colors.HexColor("#EFF6FF"),
    "LOW":      colors.HexColor("#F0FDF4"),
}


def generate_pdf(scan) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    story = []

    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=16, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9, leading=13)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.gray)
    bold = ParagraphStyle("bold", parent=styles["Normal"], fontSize=9, leading=13, fontName="Helvetica-Bold")

    # DEMO banner
    if DEMO_MODE:
        story.append(Paragraph(
            "⚠ DEMO MODE — This report uses pre-seeded illustrative data. "
            "Not for operational use.",
            ParagraphStyle("banner", parent=styles["Normal"], fontSize=8,
                           textColor=colors.white,
                           backColor=colors.HexColor("#7C3AED"), leading=12)
        ))
        story.append(Spacer(1, 8))

    # Title
    story.append(Paragraph("CVE Prioritization Report", h1))
    story.append(Paragraph(f"<b>{scan.system_name}</b>", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1E3A5F")))
    story.append(Spacer(1, 8))

    # System info table
    info_data = [
        ["System Type", scan.system_type, "Criticality", scan.system_criticality],
        ["Total CVEs", str(scan.total_count), "KEV Count", str(scan.kev_count)],
        ["Assessment Date", datetime.utcnow().strftime("%Y-%m-%d"), "Status", scan.status.replace("_", " ")],
    ]
    info_table = Table(info_data, colWidths=[1.5 * inch, 2.5 * inch, 1.3 * inch, 1.5 * inch])
    info_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 10))

    # Scope notice
    story.append(Paragraph(
        "This report prioritizes CVEs based on CISA KEV catalog status, EPSS exploitation probability "
        "scores, and system criticality. Priority scores are deterministic — Claude explains the "
        "engine's output but does not make the determination. Verify KEV and EPSS data against current "
        "CISA and FIRST.org sources before finalizing patch schedules.",
        small
    ))
    story.append(Spacer(1, 10))

    # Summary counts
    story.append(Paragraph("Priority Summary", h2))
    summary_data = [
        ["Tier", "Count", "Action Window"],
        ["CRITICAL", str(scan.critical_count), "24–48 hours"],
        ["HIGH", str(scan.high_count), "7 days"],
        ["MEDIUM", str(scan.medium_count), "30 days"],
        ["LOW", str(scan.low_count), "Next maintenance window"],
    ]
    sum_table = Table(summary_data, colWidths=[2 * inch, 1 * inch, 3.5 * inch])
    sum_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 10))

    # Vulnerability inventory
    story.append(Paragraph("Vulnerability Inventory", h2))
    vuln_header = ["CVE ID", "Component", "KEV", "EPSS", "Score", "Tier"]
    vuln_data = [vuln_header]
    for item in scan.items:
        vuln_data.append([
            item.cve_id,
            (item.component or "")[:40],
            "YES" if item.in_kev else "NO",
            f"{item.epss_pct}%",
            str(item.priority_score),
            item.priority_tier,
        ])

    vuln_table = Table(vuln_data, colWidths=[1.3 * inch, 2.3 * inch, 0.5 * inch, 0.6 * inch, 0.5 * inch, 1 * inch])
    row_styles = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]
    for row_idx, item in enumerate(scan.items, start=1):
        tier_color = _TIER_COLORS.get(item.priority_tier, colors.gray)
        row_styles.append(("TEXTCOLOR", (5, row_idx), (5, row_idx), tier_color))
        row_styles.append(("FONTNAME", (5, row_idx), (5, row_idx), "Helvetica-Bold"))
        if item.in_kev:
            row_styles.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), colors.HexColor("#DC2626")))
    vuln_table.setStyle(TableStyle(row_styles))
    story.append(vuln_table)
    story.append(Spacer(1, 10))

    # Patch brief
    if scan.patch_brief_text:
        story.append(Paragraph("Patch Prioritization Brief", h2))
        for line in scan.patch_brief_text.split("\n"):
            line = line.strip()
            if not line:
                story.append(Spacer(1, 4))
            elif line.startswith("## "):
                story.append(Paragraph(line[3:], h2))
            elif line.startswith("### "):
                story.append(Paragraph(line[4:], bold))
            elif line.startswith("**") and line.endswith("**"):
                story.append(Paragraph(line.replace("**", ""), bold))
            else:
                story.append(Paragraph(line, body))

    doc.build(story)
    return buf.getvalue()
