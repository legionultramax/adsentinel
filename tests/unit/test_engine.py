"""Tests for the scan engine, context, and plugin loader."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from adsentinel.engine.context import SharedContext
from adsentinel.engine.runner import ScanEngine, ScanResult
from adsentinel.models.finding import CheckResult, Finding
from adsentinel.models.severity import Severity


class TestSharedContext:
    def test_default_values(self):
        ctx = SharedContext()
        assert ctx.users == []
        assert ctx.groups == []
        assert ctx.computers == []
        assert ctx.trusts == []
        assert ctx.gpos == []
        assert ctx.certificate_templates == []
        assert ctx.privileged_groups == {}
        assert ctx.user_group_membership == {}
        assert ctx.collection_errors == []

    def test_domain_info_default(self):
        ctx = SharedContext()
        assert ctx.domain_info is not None
        assert ctx.domain_info.dns_name == ""

    def test_password_policy_default(self):
        ctx = SharedContext()
        assert ctx.password_policy is not None


class TestScanResult:
    def test_empty_result(self):
        result = ScanResult()
        assert result.all_findings == []
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.medium_count == 0
        assert result.low_count == 0
        assert result.info_count == 0
        assert result.exit_code == 0
        assert result.total_checks == 0

    def test_exit_code_critical(self):
        result = ScanResult()
        cr = CheckResult(check_id="TEST-001", check_name="Test", category="Test")
        cr.findings = [
            Finding(id="TEST-001", title="Crit", description="x", severity=Severity.CRITICAL, category="Test"),
        ]
        result.check_results = [cr]
        assert result.exit_code == 2

    def test_exit_code_high(self):
        result = ScanResult()
        cr = CheckResult(check_id="TEST-001", check_name="Test", category="Test")
        cr.findings = [
            Finding(id="TEST-001", title="High", description="x", severity=Severity.HIGH, category="Test"),
        ]
        result.check_results = [cr]
        assert result.exit_code == 1

    def test_exit_code_medium_only(self):
        result = ScanResult()
        cr = CheckResult(check_id="TEST-001", check_name="Test", category="Test")
        cr.findings = [
            Finding(id="TEST-001", title="Med", description="x", severity=Severity.MEDIUM, category="Test"),
        ]
        result.check_results = [cr]
        assert result.exit_code == 0

    def test_findings_by_severity(self):
        result = ScanResult()
        cr = CheckResult(check_id="TEST-001", check_name="Test", category="Test")
        cr.findings = [
            Finding(id="T-1", title="Crit", description="x", severity=Severity.CRITICAL, category="Test"),
            Finding(id="T-2", title="High1", description="x", severity=Severity.HIGH, category="Test"),
            Finding(id="T-3", title="High2", description="x", severity=Severity.HIGH, category="Test"),
        ]
        result.check_results = [cr]
        assert result.critical_count == 1
        assert result.high_count == 2

    def test_duration(self):
        result = ScanResult()
        result.scan_end = result.scan_start + timedelta(seconds=5.5)
        assert abs(result.duration_seconds - 5.5) < 0.1

    def test_duration_no_end(self):
        result = ScanResult()
        assert result.duration_seconds == 0.0


class TestScanEngine:
    @patch("adsentinel.engine.runner.WinRMSource")
    @patch("adsentinel.engine.runner.LDAPSource")
    def test_engine_handles_connection_failure(self, mock_ldap_cls, mock_winrm_cls):
        from adsentinel.config import ScanConfig
        from adsentinel.exceptions import ConnectionError

        config = ScanConfig(server="dc01", domain="corp.com")
        mock_ldap = MagicMock()
        mock_ldap.connect.side_effect = ConnectionError("Connection refused")
        mock_ldap_cls.return_value = mock_ldap
        mock_winrm_cls.return_value = MagicMock()

        engine = ScanEngine(config)
        result = engine.run()

        assert len(result.collection_errors) > 0
        assert "Connection refused" in result.collection_errors[0]
