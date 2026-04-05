"""CSV report generator — for SIEM/SOAR ingestion."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


def generate_csv_report(scan_result: Any, output_path: str) -> None:
    """Generate a CSV report of all findings."""
    findings = scan_result.all_findings

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID", "Title", "Severity", "Category", "Affected Count",
            "Description", "Remediation", "PowerShell Command",
            "MITRE ATT&CK", "CIS Controls", "NIST 800-53", "Source",
        ])

        for finding in findings:
            mitre_ids = "; ".join(m.technique_id for m in finding.compliance.mitre_attack)
            cis = "; ".join(finding.compliance.cis_controls)
            nist = "; ".join(finding.compliance.nist_800_53)

            writer.writerow([
                finding.id,
                finding.title,
                finding.severity.value,
                finding.category,
                finding.affected_count,
                finding.description,
                finding.remediation.description,
                finding.remediation.powershell_command,
                mitre_ids,
                cis,
                nist,
                finding.source,
            ])

    logger.info("csv_report_generated", path=output_path, findings=len(findings))
