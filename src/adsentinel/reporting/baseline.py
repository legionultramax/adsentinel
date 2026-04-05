"""Differential scanning — save baselines, compare scans, track trends."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from adsentinel import __version__
from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


class BaselineEntry:
    """A single finding snapshot for baseline comparison."""

    def __init__(self, finding_id: str, title: str, severity: str, category: str,
                 affected_count: int, fingerprint: str) -> None:
        self.finding_id = finding_id
        self.title = title
        self.severity = severity
        self.category = category
        self.affected_count = affected_count
        self.fingerprint = fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "affected_count": self.affected_count,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BaselineEntry:
        return cls(
            finding_id=data["finding_id"],
            title=data["title"],
            severity=data["severity"],
            category=data["category"],
            affected_count=data["affected_count"],
            fingerprint=data["fingerprint"],
        )

    @classmethod
    def from_finding(cls, finding: Any) -> BaselineEntry:
        fingerprint = f"{finding.id}:{finding.title}"
        return cls(
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            category=finding.category,
            affected_count=finding.affected_count,
            fingerprint=fingerprint,
        )


class Baseline:
    """A complete scan baseline for comparison."""

    def __init__(self, scan_time: datetime, domain: str,
                 entries: List[BaselineEntry], score: float, grade: str) -> None:
        self.scan_time = scan_time
        self.domain = domain
        self.entries = entries
        self.score = score
        self.grade = grade

    def save(self, path: str) -> None:
        """Save baseline to a JSON file."""
        data = {
            "version": __version__,
            "scan_time": self.scan_time.isoformat(),
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "finding_count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
        }
        filepath = Path(path)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("baseline_saved", path=path, findings=len(self.entries))

    @classmethod
    def _parse_iso_datetime(cls, value: str) -> datetime:
        """Parse an ISO format datetime string, compatible with Python 3.9+."""
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            # Python 3.9/3.10 can't parse +00:00 suffix; strip it and add UTC
            clean = value.replace("+00:00", "").replace("Z", "")
            dt = datetime.fromisoformat(clean)
            return dt.replace(tzinfo=timezone.utc)

    @classmethod
    def load(cls, path: str) -> Baseline:
        """Load a baseline from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        try:
            return cls(
                scan_time=cls._parse_iso_datetime(data["scan_time"]),
                domain=data["domain"],
                entries=[BaselineEntry.from_dict(e) for e in data["entries"]],
                score=data["score"],
                grade=data["grade"],
            )
        except KeyError as e:
            raise ValueError(f"Invalid baseline file: missing key {e}") from e

    @classmethod
    def from_scan_result(cls, scan_result: Any, score: float, grade: str) -> Baseline:
        """Create a baseline from a scan result."""
        entries = [BaselineEntry.from_finding(f) for f in scan_result.all_findings]
        return cls(
            scan_time=scan_result.scan_start,
            domain=scan_result.config_summary.get("domain", ""),
            entries=entries,
            score=score,
            grade=grade,
        )


class DiffResult:
    """Result of comparing two baselines."""

    def __init__(self) -> None:
        self.new_findings: List[BaselineEntry] = []
        self.resolved_findings: List[BaselineEntry] = []
        self.unchanged_findings: List[BaselineEntry] = []
        self.regression_findings: List[BaselineEntry] = []  # resolved then re-appeared
        self.score_delta: float = 0.0
        self.previous_score: float = 0.0
        self.current_score: float = 0.0
        self.previous_grade: str = ""
        self.current_grade: str = ""

    @property
    def improved(self) -> bool:
        return self.score_delta > 0

    @property
    def summary(self) -> Dict[str, Any]:
        return {
            "new": len(self.new_findings),
            "resolved": len(self.resolved_findings),
            "unchanged": len(self.unchanged_findings),
            "score_delta": round(self.score_delta, 1),
            "previous_score": self.previous_score,
            "current_score": self.current_score,
            "previous_grade": self.previous_grade,
            "current_grade": self.current_grade,
            "improved": self.improved,
        }


def compare_baselines(previous: Baseline, current: Baseline) -> DiffResult:
    """Compare two baselines and produce a diff."""
    diff = DiffResult()
    diff.previous_score = previous.score
    diff.current_score = current.score
    diff.score_delta = current.score - previous.score
    diff.previous_grade = previous.grade
    diff.current_grade = current.grade

    prev_fps: Set[str] = {e.fingerprint for e in previous.entries}
    curr_fps: Set[str] = {e.fingerprint for e in current.entries}

    # New findings = in current but not in previous
    for entry in current.entries:
        if entry.fingerprint not in prev_fps:
            diff.new_findings.append(entry)
        else:
            diff.unchanged_findings.append(entry)

    # Resolved findings = in previous but not in current
    for entry in previous.entries:
        if entry.fingerprint not in curr_fps:
            diff.resolved_findings.append(entry)

    return diff


def generate_diff_report(diff: DiffResult) -> str:
    """Generate a human-readable diff report."""
    lines = [
        "=" * 60,
        "ADSentinel — Differential Scan Report",
        "=" * 60,
        "",
        f"Score: {diff.previous_score} ({diff.previous_grade}) → {diff.current_score} ({diff.current_grade})",
        f"Delta: {'+' if diff.score_delta >= 0 else ''}{diff.score_delta:.1f}",
        "",
    ]

    if diff.new_findings:
        lines.append(f"NEW FINDINGS ({len(diff.new_findings)}):")
        lines.append("-" * 40)
        for f in diff.new_findings:
            lines.append(f"  [{f.severity}] {f.finding_id}: {f.title}")
        lines.append("")

    if diff.resolved_findings:
        lines.append(f"RESOLVED ({len(diff.resolved_findings)}):")
        lines.append("-" * 40)
        for f in diff.resolved_findings:
            lines.append(f"  [{f.severity}] {f.finding_id}: {f.title}")
        lines.append("")

    lines.append(f"Unchanged: {len(diff.unchanged_findings)}")
    lines.append("=" * 60)

    return "\n".join(lines)
