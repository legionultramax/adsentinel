"""PDF executive summary report — one-page overview via WeasyPrint (optional)."""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from adsentinel import __version__
from adsentinel.logging_config import get_logger
from adsentinel.scoring.posture import (
    calculate_category_scores,
    calculate_posture_score,
    get_grade,
    get_grade_color,
)

logger = get_logger(__name__)


def generate_pdf_report(scan_result: Any, output_path: str) -> None:
    """Generate a PDF executive summary report.

    Requires WeasyPrint: pip install adsentinel[pdf]
    Falls back to saving an HTML file if WeasyPrint is not installed.
    """
    findings = scan_result.all_findings
    score = calculate_posture_score(findings)
    grade = get_grade(score)
    grade_color = get_grade_color(grade)
    category_scores = calculate_category_scores(findings)

    by_severity = {
        "CRITICAL": scan_result.critical_count,
        "HIGH": scan_result.high_count,
        "MEDIUM": scan_result.medium_count,
        "LOW": scan_result.low_count,
        "INFO": scan_result.info_count,
    }

    # Top findings (highest severity first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 5))
    top_findings = sorted_findings[:15]

    html_content = _build_pdf_html(
        scan_result, score, grade, grade_color,
        by_severity, category_scores, top_findings,
    )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(str(path))
        logger.info("pdf_report_generated", path=output_path)
    except ImportError:
        # Save as HTML with .pdf.html extension as fallback
        fallback = str(path) + ".html"
        with open(fallback, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.warning("weasyprint_not_installed", fallback=fallback,
                       hint="Install with: pip install adsentinel[pdf]")


def _build_pdf_html(
    scan_result: Any, score: float, grade: str, grade_color: str,
    by_severity: Dict[str, int], category_scores: Dict[str, float],
    top_findings: List[Any],
) -> str:
    """Build the HTML that will be converted to PDF."""
    domain = html.escape(scan_result.config_summary.get("domain", "Unknown"))
    scan_date = scan_result.scan_start.strftime("%Y-%m-%d %H:%M UTC")

    # Category rows
    cat_rows = ""
    for cat, cat_score in sorted(category_scores.items(), key=lambda x: x[1]):
        bar_color = "#44ff44" if cat_score >= 80 else "#ffcc00" if cat_score >= 60 else "#ff8800" if cat_score >= 40 else "#ff4444"
        cat_rows += f"""
        <tr>
            <td>{html.escape(cat)}</td>
            <td>
                <div style="background:#333;border-radius:4px;overflow:hidden;height:16px;">
                    <div style="width:{cat_score}%;background:{bar_color};height:100%;"></div>
                </div>
            </td>
            <td style="text-align:center;">{cat_score:.0f}</td>
        </tr>"""

    # Top findings rows
    finding_rows = ""
    sev_colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44aaff", "INFO": "#888"}
    for f in top_findings:
        sc = sev_colors.get(f.severity.value, "#888")
        finding_rows += f"""
        <tr>
            <td style="font-family:monospace;">{html.escape(f.id)}</td>
            <td><span style="color:{sc};font-weight:bold;">{f.severity.value}</span></td>
            <td>{html.escape(f.title[:80])}</td>
            <td style="text-align:center;">{f.affected_count}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
@page {{ size: A4; margin: 1.5cm; }}
body {{
    font-family: 'Helvetica Neue', Arial, sans-serif;
    color: #e6edf3;
    background: #0d1117;
    font-size: 10px;
    line-height: 1.5;
}}
.header {{
    text-align: center;
    border-bottom: 2px solid #30363d;
    padding-bottom: 12px;
    margin-bottom: 16px;
}}
.header h1 {{ font-size: 22px; margin: 0; }}
.header .sub {{ color: #8b949e; font-size: 11px; }}
.score-box {{
    text-align: center;
    margin: 12px 0;
}}
.score-box .grade {{
    font-size: 48px;
    font-weight: bold;
    color: {grade_color};
}}
.score-box .num {{ color: #8b949e; font-size: 14px; }}
.stats {{
    display: flex;
    justify-content: space-around;
    margin: 12px 0;
}}
.stat {{
    text-align: center;
    padding: 8px 16px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
}}
.stat .n {{ font-size: 20px; font-weight: bold; }}
.stat .l {{ color: #8b949e; font-size: 9px; }}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 8px 0;
}}
th, td {{
    padding: 4px 8px;
    border: 1px solid #30363d;
    font-size: 9px;
}}
th {{ background: #161b22; text-align: left; }}
h2 {{ font-size: 13px; margin: 12px 0 6px; border-bottom: 1px solid #30363d; padding-bottom: 4px; }}
.footer {{
    text-align: center;
    color: #8b949e;
    font-size: 8px;
    margin-top: 12px;
    border-top: 1px solid #30363d;
    padding-top: 6px;
}}
</style>
</head>
<body>

<div class="header">
    <h1>ADSentinel — Security Assessment</h1>
    <div class="sub">{domain} &mdash; {scan_date}</div>
</div>

<div class="score-box">
    <div class="grade">{grade}</div>
    <div class="num">{score}/100 — Security Posture Score</div>
</div>

<div class="stats">
    <div class="stat"><div class="n" style="color:#ff4444">{by_severity['CRITICAL']}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:#ff8800">{by_severity['HIGH']}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:#ffcc00">{by_severity['MEDIUM']}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:#44aaff">{by_severity['LOW']}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n" style="color:#888">{by_severity['INFO']}</div><div class="l">Info</div></div>
    <div class="stat"><div class="n">{scan_result.total_checks}</div><div class="l">Checks Run</div></div>
</div>

<h2>Category Scores</h2>
<table>
    <tr><th>Category</th><th style="width:50%;">Score</th><th>Value</th></tr>
    {cat_rows}
</table>

<h2>Top Findings</h2>
<table>
    <tr><th>ID</th><th>Severity</th><th>Finding</th><th>Affected</th></tr>
    {finding_rows}
</table>

<div class="footer">
    Generated by ADSentinel v{__version__} &mdash; {scan_date} &mdash;
    {scan_result.total_checks} checks &mdash; {len(scan_result.all_findings)} findings
</div>

</body>
</html>"""
