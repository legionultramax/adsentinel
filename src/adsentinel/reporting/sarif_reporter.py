"""SARIF v2.1.0 reporter — GitHub Advanced Security / CodeQL integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from adsentinel import __version__
from adsentinel.logging_config import get_logger

logger = get_logger(__name__)

# SARIF severity mapping
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def generate_sarif_report(scan_result: Any, output_path: str) -> None:
    """Generate a SARIF v2.1.0 report for GitHub Advanced Security."""
    findings = scan_result.all_findings

    rules = _build_rules(findings)
    results = _build_results(findings)

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ADSentinel",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/your-org/adsentinel",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan_result.scan_start.isoformat() + "Z",
                        "endTimeUtc": (scan_result.scan_end.isoformat() + "Z") if scan_result.scan_end else None,
                    }
                ],
            }
        ],
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    logger.info("sarif_report_generated", path=output_path, findings=len(findings))


def _build_rules(findings: List[Any]) -> List[Dict[str, Any]]:
    """Build SARIF rule definitions from unique check IDs."""
    seen = set()
    rules = []
    for f in findings:
        if f.id in seen:
            continue
        seen.add(f.id)

        tags = [f.category]
        for m in f.compliance.mitre_attack:
            tags.append(f"MITRE:{m.technique_id}")
        for n in f.compliance.nist_800_53:
            tags.append(f"NIST:{n}")
        for c in f.compliance.cis_controls:
            tags.append(f"CIS:{c}")

        rule: Dict[str, Any] = {
            "id": f.id,
            "name": f.id.replace("-", ""),
            "shortDescription": {"text": f.title[:200]},
            "fullDescription": {"text": f.description},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(f.severity.value, "note"),
            },
            "properties": {
                "tags": tags,
                "security-severity": str(_security_severity(f.severity.value)),
            },
        }

        if f.remediation.description:
            rule["help"] = {
                "text": f.remediation.description,
                "markdown": f"**Remediation:** {f.remediation.description}",
            }

        rules.append(rule)

    return rules


def _build_results(findings: List[Any]) -> List[Dict[str, Any]]:
    """Build SARIF results from findings."""
    results = []
    for f in findings:
        result: Dict[str, Any] = {
            "ruleId": f.id,
            "level": _SARIF_LEVEL.get(f.severity.value, "note"),
            "message": {
                "text": f"{f.title}\n\n{f.description}",
            },
            "locations": [],
            "properties": {
                "severity": f.severity.value,
                "category": f.category,
                "affected_count": f.affected_count,
            },
        }

        # Add affected objects as related locations
        for i, obj in enumerate(f.affected_objects[:10]):
            result["locations"].append({
                "logicalLocations": [
                    {
                        "name": obj.sam_account_name or obj.dn,
                        "fullyQualifiedName": obj.dn,
                        "kind": obj.object_type,
                    }
                ],
            })

        # If no locations, add a placeholder
        if not result["locations"]:
            result["locations"].append({
                "logicalLocations": [
                    {
                        "name": f.category,
                        "kind": "domain",
                    }
                ],
            })

        # Add compliance as fingerprints
        if f.compliance.mitre_attack:
            result["fingerprints"] = {
                "mitre_attack": ",".join(m.technique_id for m in f.compliance.mitre_attack),
            }

        results.append(result)

    return results


def _security_severity(severity: str) -> float:
    """Map severity to SARIF security-severity score (0.0-10.0)."""
    return {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 3.0,
        "INFO": 1.0,
    }.get(severity, 1.0)
