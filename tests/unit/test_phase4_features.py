"""Unit tests for Phase 4 features: baseline, SARIF, BloodHound, attack paths."""

import json
import os
import tempfile
from datetime import datetime, timezone

import pytest

from adsentinel.models.finding import Finding, Remediation
from adsentinel.models.compliance import ComplianceMapping, MitreAttack
from adsentinel.models.severity import Severity
from adsentinel.reporting.baseline import (
    Baseline,
    BaselineEntry,
    DiffResult,
    compare_baselines,
    generate_diff_report,
)
from adsentinel.reporting.sarif_reporter import generate_sarif_report
from adsentinel.reporting.bloodhound_reporter import generate_bloodhound_export
from adsentinel.reporting.attack_paths import (
    AttackPath,
    AttackStep,
    analyze_attack_paths,
    generate_attack_path_report,
)
from tests.conftest import make_user, make_computer


# ============================================================================
# Mock scan result for reporter tests
# ============================================================================

class MockScanResult:
    def __init__(self, findings=None, context=None):
        self._findings = findings or []
        self.scan_start = datetime(2026, 4, 4, 12, 0, 0, tzinfo=timezone.utc)
        self.scan_end = datetime(2026, 4, 4, 12, 1, 30, tzinfo=timezone.utc)
        self.config_summary = {"domain": "corp.com", "server": "dc01.corp.com"}
        self.total_checks = 152
        self.checks_passed = 140
        self.checks_failed = 2
        self.checks_skipped = 10
        self.collection_errors = []
        self.context = context
        self.check_results = []

    @property
    def all_findings(self):
        return self._findings

    @property
    def critical_count(self):
        return sum(1 for f in self._findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for f in self._findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self):
        return sum(1 for f in self._findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self):
        return sum(1 for f in self._findings if f.severity == Severity.LOW)

    @property
    def info_count(self):
        return sum(1 for f in self._findings if f.severity == Severity.INFO)

    @property
    def duration_seconds(self):
        return 90.0

    @property
    def exit_code(self):
        if self.critical_count > 0:
            return 2
        if self.high_count > 0:
            return 1
        return 0


def _make_finding(check_id="PP-001", title="Test Finding", severity=Severity.HIGH,
                  category="Password Policy", mitre_id=None):
    mitre = []
    if mitre_id:
        mitre = [MitreAttack(technique_id=mitre_id, technique_name="Test", tactic="Test")]
    return Finding(
        id=check_id,
        title=title,
        description="Test description",
        severity=severity,
        category=category,
        compliance=ComplianceMapping(
            mitre_attack=mitre,
            nist_800_53=["AC-6"],
        ),
        remediation=Remediation(description="Fix it"),
    )


# ============================================================================
# Baseline / Differential scanning
# ============================================================================

class TestBaseline:
    def test_save_and_load(self):
        entries = [
            BaselineEntry("PP-001", "Weak Password", "HIGH", "Password Policy", 5, "PP-001:Weak Password"),
            BaselineEntry("KRB-001", "Kerberoasting", "CRITICAL", "Kerberos", 3, "KRB-001:Kerberoasting"),
        ]
        baseline = Baseline(
            scan_time=datetime(2026, 4, 4, tzinfo=timezone.utc),
            domain="corp.com",
            entries=entries,
            score=65.0,
            grade="C",
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            baseline.save(path)
            loaded = Baseline.load(path)
            assert loaded.domain == "corp.com"
            assert loaded.score == 65.0
            assert loaded.grade == "C"
            assert len(loaded.entries) == 2
        finally:
            os.unlink(path)

    def test_from_scan_result(self):
        findings = [_make_finding(), _make_finding("KRB-001", "Kerberoasting", Severity.CRITICAL)]
        result = MockScanResult(findings)
        bl = Baseline.from_scan_result(result, 70.0, "C")
        assert len(bl.entries) == 2
        assert bl.score == 70.0


class TestDiffResult:
    def test_compare_new_findings(self):
        prev = Baseline(
            scan_time=datetime(2026, 4, 1, tzinfo=timezone.utc),
            domain="corp.com",
            entries=[BaselineEntry("PP-001", "Old", "HIGH", "PP", 1, "PP-001:Old")],
            score=80.0, grade="B",
        )
        curr = Baseline(
            scan_time=datetime(2026, 4, 4, tzinfo=timezone.utc),
            domain="corp.com",
            entries=[
                BaselineEntry("PP-001", "Old", "HIGH", "PP", 1, "PP-001:Old"),
                BaselineEntry("KRB-001", "New", "CRITICAL", "Kerb", 3, "KRB-001:New"),
            ],
            score=60.0, grade="C",
        )
        diff = compare_baselines(prev, curr)
        assert len(diff.new_findings) == 1
        assert diff.new_findings[0].finding_id == "KRB-001"
        assert len(diff.resolved_findings) == 0
        assert len(diff.unchanged_findings) == 1
        assert diff.score_delta == -20.0
        assert not diff.improved

    def test_compare_resolved_findings(self):
        prev = Baseline(
            scan_time=datetime(2026, 4, 1, tzinfo=timezone.utc),
            domain="corp.com",
            entries=[
                BaselineEntry("PP-001", "Old", "HIGH", "PP", 1, "PP-001:Old"),
                BaselineEntry("KRB-001", "Gone", "CRITICAL", "Kerb", 3, "KRB-001:Gone"),
            ],
            score=60.0, grade="C",
        )
        curr = Baseline(
            scan_time=datetime(2026, 4, 4, tzinfo=timezone.utc),
            domain="corp.com",
            entries=[BaselineEntry("PP-001", "Old", "HIGH", "PP", 1, "PP-001:Old")],
            score=80.0, grade="B",
        )
        diff = compare_baselines(prev, curr)
        assert len(diff.resolved_findings) == 1
        assert diff.resolved_findings[0].finding_id == "KRB-001"
        assert diff.improved

    def test_diff_report_text(self):
        diff = DiffResult()
        diff.previous_score = 60.0
        diff.current_score = 80.0
        diff.score_delta = 20.0
        diff.previous_grade = "C"
        diff.current_grade = "B"
        diff.new_findings = []
        diff.resolved_findings = [BaselineEntry("KRB-001", "Fixed", "CRITICAL", "Kerb", 1, "fp")]
        diff.unchanged_findings = [BaselineEntry("PP-001", "Same", "HIGH", "PP", 1, "fp2")]
        text = generate_diff_report(diff)
        assert "RESOLVED (1)" in text
        assert "KRB-001" in text
        assert "60" in text and "80" in text


# ============================================================================
# SARIF reporter
# ============================================================================

class TestSARIFReporter:
    def test_generate_sarif(self):
        findings = [
            _make_finding("PP-001", "Weak Password Length", Severity.HIGH, mitre_id="T1110"),
            _make_finding("KRB-001", "Kerberoasting", Severity.CRITICAL, "Kerberos Security", "T1558.003"),
        ]
        result = MockScanResult(findings)
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            path = f.name
        try:
            generate_sarif_report(result, path)
            with open(path) as f:
                sarif = json.load(f)
            assert sarif["version"] == "2.1.0"
            assert len(sarif["runs"]) == 1
            run = sarif["runs"][0]
            assert run["tool"]["driver"]["name"] == "ADSentinel"
            assert len(run["results"]) == 2
            assert len(run["tool"]["driver"]["rules"]) == 2
            # Check severity mapping
            crit_result = [r for r in run["results"] if r["ruleId"] == "KRB-001"][0]
            assert crit_result["level"] == "error"
        finally:
            os.unlink(path)


# ============================================================================
# BloodHound exporter
# ============================================================================

class TestBloodHoundExporter:
    def test_generate_export(self, context):
        result = MockScanResult(context=context)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "bh_export.json")
            generate_bloodhound_export(result, out)

            base = out.replace(".json", "")
            # Check files were created
            assert os.path.exists(f"{base}_users.json")
            assert os.path.exists(f"{base}_groups.json")
            assert os.path.exists(f"{base}_computers.json")
            assert os.path.exists(f"{base}_domains.json")

            # Validate user export
            with open(f"{base}_users.json") as f:
                users = json.load(f)
            assert users["meta"]["type"] == "users"
            assert users["meta"]["count"] == len(context.users)
            assert users["data"][0]["ObjectIdentifier"].startswith("S-1-5-")

            # Validate group export
            with open(f"{base}_groups.json") as f:
                groups = json.load(f)
            assert groups["meta"]["type"] == "groups"
            assert groups["meta"]["count"] == len(context.groups)

            # Validate computer export
            with open(f"{base}_computers.json") as f:
                comps = json.load(f)
            assert comps["meta"]["type"] == "computers"

    def test_no_context(self):
        result = MockScanResult(context=None)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "bh.json")
            generate_bloodhound_export(result, out)
            # Should not crash, no files created


# ============================================================================
# Attack path analysis
# ============================================================================

class TestAttackPaths:
    def test_kerberoast_path(self, context):
        findings = [_make_finding("KRB-001", "Kerberoastable", Severity.CRITICAL)]
        paths = analyze_attack_paths(context, findings)
        # svc_admin is kerberoastable + in DA
        kerberoast_paths = [p for p in paths if "Kerberoasting" in p.name]
        assert len(kerberoast_paths) == 1
        assert kerberoast_paths[0].risk == "CRITICAL"
        assert kerberoast_paths[0].step_count >= 3

    def test_unconstrained_coerce_path(self, context):
        findings = []
        paths = analyze_attack_paths(context, findings)
        unconst_paths = [p for p in paths if "Unconstrained" in p.name]
        # SRV001 has unconstrained delegation (non-DC)
        assert len(unconst_paths) == 1

    def test_rbcd_path(self, context):
        context.domain_info.machine_account_quota = 10
        findings = []
        paths = analyze_attack_paths(context, findings)
        rbcd_paths = [p for p in paths if "RBCD" in p.name]
        assert len(rbcd_paths) == 1

    def test_narrative_format(self):
        path = AttackPath("Test Path", "Test description", "HIGH")
        path.add_step(AttackStep("Step1", "Do thing", "A", "B"))
        path.add_step(AttackStep("Step2", "Do other", "B", "C"))
        narrative = path.narrative()
        assert "Step 1: Step1" in narrative
        assert "Step 2: Step2" in narrative
        assert "A → B" in narrative

    def test_report_generation(self, context):
        findings = [_make_finding()]
        paths = analyze_attack_paths(context, findings)
        report = generate_attack_path_report(paths)
        assert "Attack Path Analysis" in report

    def test_no_paths(self):
        from adsentinel.engine.context import SharedContext
        ctx = SharedContext()
        ctx.domain_info.machine_account_quota = 0
        paths = analyze_attack_paths(ctx, [])
        report = generate_attack_path_report(paths)
        assert "No critical attack paths" in report

    def test_attack_path_dict(self):
        path = AttackPath("TestPath", "desc", "CRITICAL")
        path.add_step(AttackStep("T1", "desc1", "A", "B", "CHK-001"))
        d = path.to_dict()
        assert d["name"] == "TestPath"
        assert len(d["steps"]) == 1
        assert "narrative" in d
