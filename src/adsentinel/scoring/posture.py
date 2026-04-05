"""Posture scoring — logarithmic weighted algorithm."""

from __future__ import annotations

import math
from typing import Dict, List, Optional

from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity


def calculate_posture_score(findings: List[Finding]) -> float:
    """Calculate overall posture score (0-100) using logarithmic dampening.

    Formula per severity:
        penalty = weight * log2(1 + count)

    This means:
        - First finding of each severity hurts the most
        - Additional findings of the same severity have diminishing impact
        - A domain with 100 LOW findings isn't penalized as much as one with 5 CRITICAL

    Score = max(0, 100 - sum(penalties))
    """
    counts = _count_by_severity(findings)

    total_penalty = 0.0
    for severity, count in counts.items():
        if count > 0:
            weight = severity.weight
            penalty = weight * math.log2(1 + count)
            total_penalty += penalty

    return max(0.0, min(100.0, round(100.0 - total_penalty, 1)))


def calculate_category_scores(findings: List[Finding]) -> Dict[str, float]:
    """Calculate posture score per category."""
    by_category: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.category not in by_category:
            by_category[f.category] = []
        by_category[f.category].append(f)

    return {cat: calculate_posture_score(cat_findings) for cat, cat_findings in by_category.items()}


def get_grade(score: float) -> str:
    """Convert a posture score to a letter grade."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


def get_grade_color(grade: str) -> str:
    """Get HTML color for a grade."""
    return {
        "A": "#44ff44",
        "B": "#88cc00",
        "C": "#ffcc00",
        "D": "#ff8800",
        "F": "#ff4444",
    }.get(grade, "#888888")


def _count_by_severity(findings: List[Finding]) -> Dict[Severity, int]:
    """Count findings by severity."""
    counts: Dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts
