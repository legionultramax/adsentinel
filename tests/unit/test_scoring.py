"""Unit tests for posture scoring."""

from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity
from adsentinel.scoring.posture import (
    calculate_posture_score,
    calculate_category_scores,
    get_grade,
    get_grade_color,
)


def _make_finding(severity: Severity, category: str = "Test") -> Finding:
    return Finding(
        id="TEST-001",
        title="Test",
        description="Test",
        severity=severity,
        category=category,
    )


class TestPostureScoring:
    def test_perfect_score(self):
        assert calculate_posture_score([]) == 100.0

    def test_one_critical(self):
        score = calculate_posture_score([_make_finding(Severity.CRITICAL)])
        assert 70 < score < 80  # One critical: 100 - 25*log2(2) = 75

    def test_one_high(self):
        score = calculate_posture_score([_make_finding(Severity.HIGH)])
        assert 85 < score < 95  # One high: 100 - 10*log2(2) = 90

    def test_info_no_penalty(self):
        findings = [_make_finding(Severity.INFO) for _ in range(100)]
        assert calculate_posture_score(findings) == 100.0

    def test_many_criticals_floor(self):
        findings = [_make_finding(Severity.CRITICAL) for _ in range(100)]
        score = calculate_posture_score(findings)
        assert score == 0.0  # Should hit floor

    def test_logarithmic_dampening(self):
        one = calculate_posture_score([_make_finding(Severity.HIGH)])
        ten = calculate_posture_score([_make_finding(Severity.HIGH) for _ in range(10)])
        # 10 findings should NOT be 10x the penalty of 1 finding
        penalty_one = 100 - one
        penalty_ten = 100 - ten
        assert penalty_ten < penalty_one * 5  # Much less than linear

    def test_mixed_severities(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
            _make_finding(Severity.LOW),
        ]
        score = calculate_posture_score(findings)
        assert 40 < score < 70


class TestGrading:
    def test_grade_a(self):
        assert get_grade(95) == "A"
        assert get_grade(90) == "A"

    def test_grade_b(self):
        assert get_grade(85) == "B"
        assert get_grade(80) == "B"

    def test_grade_c(self):
        assert get_grade(75) == "C"

    def test_grade_d(self):
        assert get_grade(65) == "D"

    def test_grade_f(self):
        assert get_grade(50) == "F"
        assert get_grade(0) == "F"

    def test_grade_color(self):
        assert get_grade_color("A").startswith("#")
        assert get_grade_color("F").startswith("#")


class TestCategoryScores:
    def test_category_separation(self):
        findings = [
            _make_finding(Severity.CRITICAL, "Kerberos"),
            _make_finding(Severity.LOW, "Password Policy"),
        ]
        scores = calculate_category_scores(findings)
        assert "Kerberos" in scores
        assert "Password Policy" in scores
        assert scores["Kerberos"] < scores["Password Policy"]
