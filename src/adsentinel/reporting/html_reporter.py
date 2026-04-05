"""Interactive HTML report generator — dark-theme, self-contained, filterable, with charts."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from adsentinel import __version__
from adsentinel.logging_config import get_logger
from adsentinel.models.severity import Severity
from adsentinel.scoring.posture import (
    calculate_category_scores,
    calculate_posture_score,
    get_grade,
    get_grade_color,
)

logger = get_logger(__name__)


def generate_html_report(scan_result: Any, output_path: str) -> None:
    """Generate a self-contained interactive HTML report."""
    findings = scan_result.all_findings
    score = calculate_posture_score(findings)
    grade = get_grade(score)
    grade_color = get_grade_color(grade)
    category_scores = calculate_category_scores(findings)

    # Group findings
    by_severity: Dict[str, int] = {
        "CRITICAL": scan_result.critical_count,
        "HIGH": scan_result.high_count,
        "MEDIUM": scan_result.medium_count,
        "LOW": scan_result.low_count,
        "INFO": scan_result.info_count,
    }

    by_category: Dict[str, List] = {}
    for f in findings:
        if f.category not in by_category:
            by_category[f.category] = []
        by_category[f.category].append(f)

    # Build MITRE technique data
    mitre_data = _build_mitre_data(findings)
    mitre_json = json.dumps(mitre_data)

    # Category chart data
    cat_labels = json.dumps(list(category_scores.keys()))
    cat_scores = json.dumps([round(v, 1) for v in category_scores.values()])
    cat_counts = json.dumps([len(by_category.get(c, [])) for c in category_scores.keys()])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ADSentinel Security Assessment — {html.escape(scan_result.config_summary.get('domain', 'Unknown'))}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script>
// Fallback: if Chart.js CDN failed (offline/airgapped), show a message in chart containers
window.addEventListener('load', function() {{
    if (typeof Chart === 'undefined') {{
        document.querySelectorAll('canvas').forEach(function(c) {{
            var p = document.createElement('p');
            p.style.cssText = 'color:#8b949e;text-align:center;padding:2em;font-style:italic;';
            p.textContent = 'Charts unavailable (offline mode). Data tables below contain all findings.';
            c.parentNode.replaceChild(p, c);
        }});
    }}
}});
</script>
<style>
:root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --accent: #58a6ff;
    --critical: #ff4444;
    --high: #ff8800;
    --medium: #ffcc00;
    --low: #44aaff;
    --info: #888888;
    --success: #44ff44;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
}}
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
header {{
    text-align: center;
    padding: 40px 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 32px;
}}
header h1 {{ font-size: 2.5em; margin-bottom: 8px; }}
header .subtitle {{ color: var(--text-secondary); font-size: 1.1em; }}
.score-ring {{
    width: 200px; height: 200px;
    margin: 32px auto;
    position: relative;
}}
.score-ring svg {{ transform: rotate(-90deg); }}
.score-ring .score-text {{
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}}
.score-ring .grade {{ font-size: 3em; font-weight: bold; color: {grade_color}; }}
.score-ring .score-num {{ font-size: 1.2em; color: var(--text-secondary); }}
.stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin: 32px 0;
}}
.stat-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
}}
.stat-card .number {{ font-size: 2.5em; font-weight: bold; }}
.stat-card .label {{ color: var(--text-secondary); margin-top: 4px; }}
.stat-card.critical .number {{ color: var(--critical); }}
.stat-card.high .number {{ color: var(--high); }}
.stat-card.medium .number {{ color: var(--medium); }}
.stat-card.low .number {{ color: var(--low); }}
.stat-card.info .number {{ color: var(--info); }}
.charts-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin: 32px 0;
}}
@media (max-width: 900px) {{
    .charts-grid {{ grid-template-columns: 1fr; }}
}}
.chart-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
}}
.chart-card h3 {{
    margin-bottom: 16px;
    color: var(--text-primary);
    font-size: 1.1em;
}}
.chart-card canvas {{ max-height: 300px; }}
.mitre-section {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin: 32px 0;
}}
.mitre-section h3 {{ margin-bottom: 16px; }}
.mitre-grid {{
    display: flex; flex-wrap: wrap; gap: 8px;
}}
.mitre-tag {{
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 12px;
    font-family: monospace;
    cursor: default;
    transition: transform 0.1s;
}}
.mitre-tag:hover {{ transform: scale(1.05); }}
.mitre-tag.sev-critical {{ background: rgba(255,68,68,0.25); color: var(--critical); border: 1px solid var(--critical); }}
.mitre-tag.sev-high {{ background: rgba(255,136,0,0.25); color: var(--high); border: 1px solid var(--high); }}
.mitre-tag.sev-medium {{ background: rgba(255,204,0,0.25); color: var(--medium); border: 1px solid var(--medium); }}
.mitre-tag.sev-low {{ background: rgba(68,170,255,0.25); color: var(--low); border: 1px solid var(--low); }}
.mitre-tag.sev-info {{ background: rgba(136,136,136,0.25); color: var(--info); border: 1px solid var(--info); }}
.controls {{
    display: flex; flex-wrap: wrap; gap: 12px;
    align-items: center;
    margin: 24px 0;
    padding: 16px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
}}
.controls input[type="text"] {{
    flex: 1; min-width: 250px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 14px;
}}
.controls input[type="text"]::placeholder {{ color: var(--text-secondary); }}
.filter-btn {{
    padding: 6px 16px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-tertiary);
    color: var(--text-primary);
    cursor: pointer;
    font-size: 13px;
    transition: all 0.2s;
}}
.filter-btn:hover {{ border-color: var(--accent); }}
.filter-btn.active {{ background: var(--accent); color: #000; border-color: var(--accent); }}
.finding {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 12px;
    overflow: hidden;
    transition: all 0.2s;
}}
.finding:hover {{ border-color: var(--accent); }}
.finding-header {{
    display: flex; align-items: center; gap: 12px;
    padding: 16px 20px;
    cursor: pointer;
    user-select: none;
}}
.finding-header:hover {{ background: var(--bg-tertiary); }}
.severity-badge {{
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
    white-space: nowrap;
}}
.severity-badge.CRITICAL {{ background: rgba(255,68,68,0.2); color: var(--critical); border: 1px solid var(--critical); }}
.severity-badge.HIGH {{ background: rgba(255,136,0,0.2); color: var(--high); border: 1px solid var(--high); }}
.severity-badge.MEDIUM {{ background: rgba(255,204,0,0.2); color: var(--medium); border: 1px solid var(--medium); }}
.severity-badge.LOW {{ background: rgba(68,170,255,0.2); color: var(--low); border: 1px solid var(--low); }}
.severity-badge.INFO {{ background: rgba(136,136,136,0.2); color: var(--info); border: 1px solid var(--info); }}
.finding-id {{ color: var(--text-secondary); font-family: monospace; min-width: 70px; }}
.finding-title {{ flex: 1; font-weight: 500; }}
.finding-count {{ color: var(--text-secondary); font-size: 13px; }}
.finding-chevron {{ color: var(--text-secondary); transition: transform 0.2s; }}
.finding.open .finding-chevron {{ transform: rotate(90deg); }}
.finding-body {{
    display: none;
    padding: 0 20px 20px;
    border-top: 1px solid var(--border);
}}
.finding.open .finding-body {{ display: block; }}
.finding-body h4 {{ color: var(--accent); margin: 16px 0 8px; font-size: 13px; text-transform: uppercase; }}
.finding-body p {{ color: var(--text-secondary); margin-bottom: 8px; }}
.finding-body pre {{
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    font-size: 13px;
    overflow-x: auto;
    color: var(--success);
    font-family: 'Consolas', 'Monaco', monospace;
}}
.finding-body .affected-list {{
    max-height: 200px; overflow-y: auto;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 13px;
    font-family: monospace;
}}
.finding-body .compliance-tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}
.compliance-tag {{
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-secondary);
}}
.category-section {{ margin: 32px 0; }}
.category-header {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 12px 0;
    border-bottom: 2px solid var(--border);
    margin-bottom: 16px;
}}
.category-header h2 {{ font-size: 1.3em; }}
.category-score {{ color: var(--text-secondary); }}
.summary-row {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
    margin: 16px 0;
    padding: 16px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
}}
.summary-item {{
    text-align: center;
}}
.summary-item .value {{ font-size: 1.4em; font-weight: bold; color: var(--accent); }}
.summary-item .desc {{ color: var(--text-secondary); font-size: 13px; }}
footer {{
    text-align: center;
    padding: 32px 0;
    color: var(--text-secondary);
    border-top: 1px solid var(--border);
    margin-top: 48px;
    font-size: 13px;
}}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>ADSentinel</h1>
    <div class="subtitle">Active Directory Security Assessment Report</div>
    <div class="subtitle" style="margin-top:8px;">
        {html.escape(scan_result.config_summary.get('domain', ''))} &mdash;
        {scan_result.scan_start.strftime('%Y-%m-%d %H:%M UTC')}
    </div>

    <div class="score-ring">
        <svg width="200" height="200" viewBox="0 0 200 200">
            <circle cx="100" cy="100" r="85" fill="none" stroke="{_dim(grade_color)}" stroke-width="12"/>
            <circle cx="100" cy="100" r="85" fill="none" stroke="{grade_color}" stroke-width="12"
                    stroke-dasharray="{score / 100 * 534} 534"
                    stroke-linecap="round"/>
        </svg>
        <div class="score-text">
            <div class="grade">{grade}</div>
            <div class="score-num">{score}/100</div>
        </div>
    </div>
</header>

<div class="stats-grid">
    <div class="stat-card critical">
        <div class="number">{by_severity['CRITICAL']}</div>
        <div class="label">Critical</div>
    </div>
    <div class="stat-card high">
        <div class="number">{by_severity['HIGH']}</div>
        <div class="label">High</div>
    </div>
    <div class="stat-card medium">
        <div class="number">{by_severity['MEDIUM']}</div>
        <div class="label">Medium</div>
    </div>
    <div class="stat-card low">
        <div class="number">{by_severity['LOW']}</div>
        <div class="label">Low</div>
    </div>
    <div class="stat-card info">
        <div class="number">{by_severity['INFO']}</div>
        <div class="label">Info</div>
    </div>
</div>

<div class="summary-row">
    <div class="summary-item">
        <div class="value">{scan_result.total_checks}</div>
        <div class="desc">Checks Executed</div>
    </div>
    <div class="summary-item">
        <div class="value">{len(findings)}</div>
        <div class="desc">Total Findings</div>
    </div>
    <div class="summary-item">
        <div class="value">{scan_result.duration_seconds:.1f}s</div>
        <div class="desc">Scan Duration</div>
    </div>
</div>

<div class="charts-grid">
    <div class="chart-card">
        <h3>Findings by Severity</h3>
        <canvas id="severityChart"></canvas>
    </div>
    <div class="chart-card">
        <h3>Category Scores</h3>
        <canvas id="categoryChart"></canvas>
    </div>
</div>

{_render_mitre_section(mitre_data)}

<div class="controls">
    <input type="text" id="searchBox" placeholder="Search findings..." onkeyup="filterFindings()">
    <button class="filter-btn active" onclick="toggleFilter(this, 'all')">All</button>
    <button class="filter-btn" onclick="toggleFilter(this, 'CRITICAL')">Critical</button>
    <button class="filter-btn" onclick="toggleFilter(this, 'HIGH')">High</button>
    <button class="filter-btn" onclick="toggleFilter(this, 'MEDIUM')">Medium</button>
    <button class="filter-btn" onclick="toggleFilter(this, 'LOW')">Low</button>
    <button class="filter-btn" onclick="toggleFilter(this, 'INFO')">Info</button>
</div>

{_render_findings(findings, by_category, category_scores)}

<footer>
    Generated by ADSentinel v{__version__} &mdash; {scan_result.scan_start.strftime('%Y-%m-%d %H:%M UTC')}
    &mdash; Scan duration: {scan_result.duration_seconds:.1f}s
    &mdash; {scan_result.total_checks} checks executed
</footer>

</div>

<script>
let activeFilter = 'all';

function toggleFilter(btn, severity) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = severity;
    filterFindings();
}}

function filterFindings() {{
    const search = document.getElementById('searchBox').value.toLowerCase();
    document.querySelectorAll('.finding').forEach(el => {{
        const sev = el.dataset.severity;
        const text = el.textContent.toLowerCase();
        const sevMatch = activeFilter === 'all' || sev === activeFilter;
        const searchMatch = !search || text.includes(search);
        el.style.display = sevMatch && searchMatch ? '' : 'none';
    }});
    document.querySelectorAll('.category-section').forEach(sec => {{
        const visible = sec.querySelectorAll('.finding:not([style*="display: none"])');
        sec.style.display = visible.length > 0 ? '' : 'none';
    }});
}}

function toggleFinding(el) {{
    el.closest('.finding').classList.toggle('open');
}}

// Charts
document.addEventListener('DOMContentLoaded', function() {{
    Chart.defaults.color = '#8b949e';
    Chart.defaults.borderColor = '#30363d';

    // Severity Doughnut
    new Chart(document.getElementById('severityChart'), {{
        type: 'doughnut',
        data: {{
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{{
                data: [{by_severity['CRITICAL']}, {by_severity['HIGH']}, {by_severity['MEDIUM']}, {by_severity['LOW']}, {by_severity['INFO']}],
                backgroundColor: ['#ff4444', '#ff8800', '#ffcc00', '#44aaff', '#888888'],
                borderColor: '#161b22',
                borderWidth: 3,
            }}]
        }},
        options: {{
            responsive: true,
            cutout: '60%',
            plugins: {{
                legend: {{ position: 'bottom', labels: {{ padding: 16, usePointStyle: true }} }}
            }}
        }}
    }});

    // Category Scores Bar
    new Chart(document.getElementById('categoryChart'), {{
        type: 'bar',
        data: {{
            labels: {cat_labels},
            datasets: [{{
                label: 'Score',
                data: {cat_scores},
                backgroundColor: {cat_scores}.map(s => s >= 80 ? '#44ff44' : s >= 60 ? '#ffcc00' : s >= 40 ? '#ff8800' : '#ff4444'),
                borderRadius: 4,
                barThickness: 20,
            }}]
        }},
        options: {{
            indexAxis: 'y',
            responsive: true,
            scales: {{
                x: {{ min: 0, max: 100, grid: {{ color: '#21262d' }} }},
                y: {{ grid: {{ display: false }}, ticks: {{ font: {{ size: 11 }} }} }}
            }},
            plugins: {{
                legend: {{ display: false }}
            }}
        }}
    }});
}});
</script>
</body>
</html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info("html_report_generated", path=output_path, findings=len(findings))


def _build_mitre_data(findings: List[Any]) -> List[Dict[str, str]]:
    """Extract unique MITRE ATT&CK techniques from findings with max severity."""
    technique_map: Dict[str, Dict[str, str]] = {}
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    for f in findings:
        for m in f.compliance.mitre_attack:
            tid = m.technique_id
            sev = f.severity.value
            if tid not in technique_map or severity_rank.get(sev, 5) < severity_rank.get(technique_map[tid]["severity"], 5):
                technique_map[tid] = {
                    "id": tid,
                    "name": m.technique_name,
                    "tactic": m.tactic,
                    "severity": sev,
                }

    return sorted(technique_map.values(), key=lambda t: severity_rank.get(t["severity"], 5))


def _render_mitre_section(mitre_data: List[Dict[str, str]]) -> str:
    """Render MITRE ATT&CK technique coverage section."""
    if not mitre_data:
        return ""

    tags = []
    for t in mitre_data:
        sev_class = f"sev-{t['severity'].lower()}"
        tags.append(
            f'<span class="mitre-tag {sev_class}" title="{html.escape(t["tactic"])}: {html.escape(t["name"])}">'
            f'{html.escape(t["id"])} — {html.escape(t["name"])}'
            f'</span>'
        )

    return f"""
<div class="mitre-section">
    <h3>MITRE ATT&amp;CK Coverage ({len(mitre_data)} techniques)</h3>
    <div class="mitre-grid">
        {"".join(tags)}
    </div>
</div>"""


def _render_findings(
    findings: List[Any],
    by_category: Dict[str, List],
    category_scores: Dict[str, float],
) -> str:
    """Render all findings grouped by category."""
    sorted_cats = sorted(by_category.keys(), key=lambda c: category_scores.get(c, 100))

    sections = []
    for cat in sorted_cats:
        cat_findings = by_category[cat]
        cat_score = category_scores.get(cat, 100)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        cat_findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))

        finding_html = "\n".join(_render_finding(f) for f in cat_findings)

        sections.append(f"""
<div class="category-section">
    <div class="category-header">
        <h2>{html.escape(cat)}</h2>
        <span class="category-score">{len(cat_findings)} findings &mdash; Score: {cat_score:.0f}/100</span>
    </div>
    {finding_html}
</div>""")

    return "\n".join(sections)


def _render_finding(f: Any) -> str:
    """Render a single finding as an expandable card."""
    affected_html = ""
    if f.affected_objects:
        items = "\n".join(
            f"  {html.escape(obj.sam_account_name or obj.dn)}"
            for obj in f.affected_objects[:30]
        )
        more = f"\n  ... and {f.affected_count - 30} more" if f.affected_count > 30 else ""
        affected_html = f"""
            <h4>Affected Objects ({f.affected_count})</h4>
            <div class="affected-list"><pre>{items}{more}</pre></div>"""

    remediation_html = ""
    if f.remediation.description:
        remediation_html = f"""
            <h4>Remediation</h4>
            <p>{html.escape(f.remediation.description)}</p>"""
        if f.remediation.powershell_command:
            remediation_html += f"\n            <pre>{html.escape(f.remediation.powershell_command)}</pre>"

    compliance_html = ""
    tags = []
    for m in f.compliance.mitre_attack:
        tags.append(f'<span class="compliance-tag">MITRE {html.escape(m.technique_id)}</span>')
    for c in f.compliance.cis_controls:
        tags.append(f'<span class="compliance-tag">CIS {html.escape(c)}</span>')
    for n in f.compliance.nist_800_53:
        tags.append(f'<span class="compliance-tag">NIST {html.escape(n)}</span>')
    for s in f.compliance.stig_rules:
        tags.append(f'<span class="compliance-tag">STIG {html.escape(s)}</span>')
    if tags:
        compliance_html = f"""
            <h4>Compliance Mapping</h4>
            <div class="compliance-tags">{"".join(tags)}</div>"""

    return f"""
<div class="finding" data-severity="{f.severity.value}">
    <div class="finding-header" onclick="toggleFinding(this)">
        <span class="finding-id">{html.escape(f.id)}</span>
        <span class="severity-badge {f.severity.value}">{f.severity.value}</span>
        <span class="finding-title">{html.escape(f.title)}</span>
        <span class="finding-count">{f.affected_count} affected</span>
        <span class="finding-chevron">&#9654;</span>
    </div>
    <div class="finding-body">
        <p>{html.escape(f.description)}</p>
        {affected_html}
        {remediation_html}
        {compliance_html}
    </div>
</div>"""


def _dim(color: str) -> str:
    """Create a dimmed version of a hex color."""
    return color + "33"
