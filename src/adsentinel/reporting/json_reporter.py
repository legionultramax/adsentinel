"""JSON report generator — structured output for SIEM/SOAR and machine consumption."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from adsentinel import __version__
from adsentinel.logging_config import get_logger
from adsentinel.scoring.posture import calculate_category_scores, calculate_posture_score, get_grade

logger = get_logger(__name__)


def generate_json_report(scan_result: Any, output_path: str) -> None:
    """Generate a structured JSON report."""
    findings = scan_result.all_findings

    score = calculate_posture_score(findings)
    grade = get_grade(score)
    category_scores = calculate_category_scores(findings)

    report = {
        "metadata": {
            "tool": "ADSentinel",
            "version": __version__,
            "scan_start": scan_result.scan_start.isoformat(),
            "scan_end": scan_result.scan_end.isoformat() if scan_result.scan_end else None,
            "duration_seconds": round(scan_result.duration_seconds, 2),
            "target": scan_result.config_summary,
        },
        "summary": {
            "posture_score": score,
            "grade": grade,
            "total_findings": len(findings),
            "severity_counts": {
                "CRITICAL": scan_result.critical_count,
                "HIGH": scan_result.high_count,
                "MEDIUM": scan_result.medium_count,
                "LOW": scan_result.low_count,
                "INFO": scan_result.info_count,
            },
            "checks_run": scan_result.total_checks,
            "checks_passed": scan_result.checks_passed,
            "checks_failed": scan_result.checks_failed,
            "checks_skipped": scan_result.checks_skipped,
            "category_scores": category_scores,
        },
        "findings": [_serialize_finding(f) for f in findings],
        "errors": scan_result.collection_errors,
        "exit_code": scan_result.exit_code,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info("json_report_generated", path=output_path, findings=len(findings))


def _serialize_finding(finding: Any) -> Dict[str, Any]:
    """Serialize a Finding to a JSON-compatible dict."""
    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "category": finding.category,
        "affected_count": finding.affected_count,
        "affected_objects": [
            {
                "dn": obj.dn,
                "sam_account_name": obj.sam_account_name,
                "object_type": obj.object_type,
            }
            for obj in finding.affected_objects[:100]  # Limit for report size
        ],
        "remediation": {
            "description": finding.remediation.description,
            "powershell_command": finding.remediation.powershell_command,
            "manual_steps": finding.remediation.manual_steps,
            "references": finding.remediation.references,
        },
        "compliance": {
            "mitre_attack": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                }
                for m in finding.compliance.mitre_attack
            ],
            "cis_controls": finding.compliance.cis_controls,
            "nist_800_53": finding.compliance.nist_800_53,
            "stig_rules": finding.compliance.stig_rules,
        },
        "source": finding.source,
        "timestamp": finding.timestamp.isoformat(),
    }
