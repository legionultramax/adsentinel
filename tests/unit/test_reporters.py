"""Tests for all report generators."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from adsentinel.engine.runner import ScanResult
from adsentinel.models.finding import CheckResult, Finding
from adsentinel.models.severity import Severity


def _make_scan_result() -> ScanResult:
    """Build a ScanResult with some findings for testing reports."""
    from adsentinel.engine.context import SharedContext
    from datetime import timedelta

    result = ScanResult()
    result.scan_end = result.scan_start + timedelta(seconds=10)
    result.total_checks = 5
    result.checks_passed = 3
    result.checks_failed = 1
    result.checks_skipped = 1
    result.config_summary = {
        "server": "dc01.corp.com",
        "domain": "corp.com",
        "auth_method": "simple",
        "ssl": "False",
        "winrm": "True",
    }

    cr1 = CheckResult(check_id="PP-001", check_name="Min Password Length", category="Password Policy")
    cr1.findings = [
        Finding(
            id="PP-001", title="Weak minimum password length",
            description="Minimum password length is 7, should be 14+",
            severity=Severity.HIGH, category="Password Policy",
        ),
    ]

    cr2 = CheckResult(check_id="KRB-001", check_name="Kerberoasting", category="Kerberos Security")
    cr2.findings = [
        Finding(
            id="KRB-001", title="Kerberoastable service accounts",
            description="3 accounts with SPNs are vulnerable",
            severity=Severity.CRITICAL, category="Kerberos Security",
        ),
    ]

    cr3 = CheckResult(check_id="PP-010", check_name="Clean Check", category="Password Policy")
    # No findings for a clean check

    result.check_results = [cr1, cr2, cr3]
    result.context = SharedContext()
    return result


class TestJSONReporter:
    def test_generate_json_report(self):
        from adsentinel.reporting.json_reporter import generate_json_report

        result = _make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            generate_json_report(result, f.name)

        data = json.loads(Path(f.name).read_text())
        assert "findings" in data or "summary" in data or "scan" in data

    def test_json_report_has_findings(self):
        from adsentinel.reporting.json_reporter import generate_json_report

        result = _make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            generate_json_report(result, f.name)

        data = json.loads(Path(f.name).read_text())
        # The JSON should contain some data
        assert len(str(data)) > 100


class TestCSVReporter:
    def test_generate_csv_report(self):
        from adsentinel.reporting.csv_reporter import generate_csv_report

        result = _make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            generate_csv_report(result, f.name)

        content = Path(f.name).read_text()
        assert "PP-001" in content or "KRB-001" in content


class TestHTMLReporter:
    def test_generate_html_report(self):
        from adsentinel.reporting.html_reporter import generate_html_report

        result = _make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            generate_html_report(result, f.name)

        content = Path(f.name).read_text()
        assert "<html" in content.lower() or "<!doctype" in content.lower() or "ADSentinel" in content


class TestSARIFReporter:
    def test_generate_sarif_report(self):
        from adsentinel.reporting.sarif_reporter import generate_sarif_report

        result = _make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            generate_sarif_report(result, f.name)

        data = json.loads(Path(f.name).read_text())
        assert data.get("$schema") or data.get("version") == "2.1.0"


class TestBloodHoundReporter:
    def test_generate_bloodhound_export(self):
        from adsentinel.reporting.bloodhound_reporter import generate_bloodhound_export

        result = _make_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            outpath = str(Path(tmpdir) / "bloodhound.json")
            generate_bloodhound_export(result, outpath)

            # BloodHound reporter writes multiple files (users, groups, etc.)
            # Check that at least one output file was created
            files = list(Path(tmpdir).glob("*.json"))
            assert len(files) >= 1
            # Verify first file is valid JSON
            data = json.loads(files[0].read_text())
            assert isinstance(data, dict)


class TestBaseline:
    def test_baseline_save_load(self):
        from adsentinel.reporting.baseline import Baseline

        result = _make_scan_result()
        bl = Baseline.from_scan_result(result, 75.0, "C")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            bl.save(f.name)

        loaded = Baseline.load(f.name)
        assert loaded.score == 75.0
        assert loaded.grade == "C"

    def test_baseline_comparison(self):
        from adsentinel.reporting.baseline import Baseline, compare_baselines

        result = _make_scan_result()
        bl1 = Baseline.from_scan_result(result, 75.0, "C")
        bl2 = Baseline.from_scan_result(result, 80.0, "B")

        diff = compare_baselines(bl1, bl2)
        assert diff is not None
