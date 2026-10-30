"""
PDF report generation.

Upgrades over the original version:
  - Color-coded risk badge (green/amber/red) instead of a plain number.
  - Renders the scan's structured indicators/events as an actual table
    instead of a raw Python dict dump.
  - Adds a generation timestamp and a short methodology footer so reports
    are self-explanatory when shared outside the app.
"""
import ast
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)


def _risk_color(score):
    if score >= 70:
        return colors.HexColor("#c0392b")   # red
    if score >= 40:
        return colors.HexColor("#e67e22")   # amber
    return colors.HexColor("#27ae60")       # green


def _risk_label(score):
    if score >= 70:
        return "HIGH RISK"
    if score >= 40:
        return "MEDIUM RISK"
    return "LOW RISK"


def _coerce_result(result):
    """result is usually stored as str(dict) in SQLite; parse it back safely."""
    if isinstance(result, dict):
        return result
    try:
        return ast.literal_eval(result)
    except Exception:
        return {"raw": str(result)}


def _indicator_rows(result_dict):
    """Pull out the most relevant list-of-things field for a table, across
    scan types (URL indicators, log events, pcap suspicious connections,
    file indicators)."""
    for key in ("indicators", "events", "suspicious_connections", "port_scan_indicators"):
        val = result_dict.get(key)
        if val:
            return key, val
    return None, []


def create_pdf_report(username, scan_type, target, score, result, output, workflow=None):
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    result_dict = _coerce_result(result)
    risk_color = _risk_color(score)
    risk_label = _risk_label(score)

    story = [
        Paragraph("CyberSentinel AI: A Cloud-Based Unified Cyber Threat Detection and Risk Analysis Platform", title_style),
        Spacer(1, 4),
        Paragraph("Security Analysis Report", styles["Heading2"]),
        Spacer(1, 4),
        Paragraph(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                  styles["Normal"]),
        Spacer(1, 14),
        HRFlowable(width="100%", color=colors.HexColor("#dddddd")),
        Spacer(1, 10),
    ]

    meta_table = Table([
        ["User", username],
        ["Scan Type", scan_type],
        ["Target", str(target)[:120]],
        ["Risk Score", f"{score}/100"],
        ["Verdict", risk_label],
    ], colWidths=[4 * cm, 11 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (1, 3), (1, 4), risk_color),
        ("FONTNAME", (1, 3), (1, 4), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#eeeeee")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    workflow = workflow or {}
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(
        f"{_risk_label(score)} triage score: {score}/100. This score reflects the configured educational heuristics and is not a probability of compromise. "
        "Validate the supporting evidence with independent telemetry before making a response decision.", styles["BodyText"]))
    assessment = result_dict.get("assessment", {})
    if assessment:
        story.append(Paragraph(
            f"Evidence strength: {assessment.get('confidence', 'unknown')} (heuristic, not calibrated). "
            f"{assessment.get('confidence_basis', '')}", styles["BodyText"]))
    if workflow:
        workflow_rows = [["Investigation status", str(workflow.get("status", "New"))],
                         ["Owner", str(workflow.get("owner", "") or "Unassigned")],
                         ["Analyst notes", str(workflow.get("note", "") or "None")[:1000]]]
        story.extend([Spacer(1, 8), Table(workflow_rows, colWidths=[4 * cm, 11 * cm]), Spacer(1, 12)])

    story.append(Paragraph("Analysis Details", styles["Heading2"]))
    candidate_rows = []
    for field in ("indicators", "events", "suspicious_connections", "port_scan_indicators",
                  "beaconing_indicators", "dns_anomalies", "brute_force_source_ips"):
        value = result_dict.get(field)
        if isinstance(value, list) and value:
            candidate_rows.extend((field, item) for item in value[:40])
    if candidate_rows:
        story.append(Paragraph("Findings and evidence", styles["Italic"]))
        story.append(Spacer(1, 6))
        table_data = [["#", "Source", "Detail"]]
        for i, (field, item) in enumerate(candidate_rows[:80], 1):
            text = item if isinstance(item, str) else str(item)
            table_data.append([str(i), field.replace("_", " ").title(), Paragraph(text[:500].replace("&", "&amp;"), styles["BodyText"])])
        detail_table = Table(table_data, colWidths=[0.8 * cm, 3.2 * cm, 11 * cm])
        detail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
        ]))
        story.append(detail_table)
    else:
        story.append(Paragraph("No discrete indicators were recorded for this scan; "
                                "see raw summary below.", styles["BodyText"]))
        story.append(Spacer(1, 8))
        summary_text = str(result_dict)[:2000].replace("&", "&amp;")
        story.append(Paragraph(summary_text, styles["BodyText"]))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#dddddd")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Methodology and limitations: scores combine rule-based heuristics with, where applicable, a trained classifier. "
        "The URL classifier is trained on synthetic examples. PCAP outliers are relative to one capture, and pattern matches may be benign. "
        "Treat results as decision support, not a definitive verdict.", styles["Italic"]))

    SimpleDocTemplate(output, pagesize=A4,
                       topMargin=2 * cm, bottomMargin=2 * cm).build(story)
    return output
