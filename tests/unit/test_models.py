"""Unit tests for core data models."""

from adsentinel.models.severity import Severity
from adsentinel.models.finding import Finding, AffectedObject, Remediation, CheckResult
from adsentinel.models.compliance import ComplianceMapping, MitreAttack
from adsentinel.models.domain import ADUser, ADGroup, ADComputer, PasswordPolicy


class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_weights(self):
        assert Severity.CRITICAL.weight == 25.0
        assert Severity.HIGH.weight == 10.0
        assert Severity.MEDIUM.weight == 3.0
        assert Severity.LOW.weight == 1.0
        assert Severity.INFO.weight == 0.0

    def test_severity_colors(self):
        assert Severity.CRITICAL.color.startswith("#")
        assert Severity.HIGH.color.startswith("#")


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            id="PP-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category="Password Policy",
        )
        assert f.id == "PP-001"
        assert f.severity == Severity.HIGH
        assert f.affected_count == 0

    def test_finding_with_mitre(self):
        f = Finding(
            id="KRB-001",
            title="Kerberoasting",
            description="Test",
            severity=Severity.CRITICAL,
            category="Kerberos Security",
            compliance=ComplianceMapping(
                mitre_attack=[
                    MitreAttack(technique_id="T1558.003", technique_name="Kerberoasting", tactic="Credential Access")
                ]
            ),
        )
        assert f.mitre_ids == ["T1558.003"]

    def test_check_result(self):
        r = CheckResult(check_id="PP-001", check_name="Test", category="Password Policy")
        assert r.findings == []
        assert r.error is None
        assert not r.skipped


class TestADUser:
    def test_kerberoastable(self):
        user = ADUser(sam_account_name="svc", enabled=True, spn_list=["HTTP/web01"])
        assert user.is_kerberoastable

    def test_not_kerberoastable_disabled(self):
        user = ADUser(sam_account_name="svc", enabled=False, spn_list=["HTTP/web01"])
        assert not user.is_kerberoastable

    def test_not_kerberoastable_no_spn(self):
        user = ADUser(sam_account_name="user1", enabled=True, spn_list=[])
        assert not user.is_kerberoastable

    def test_asrep_roastable(self):
        user = ADUser(sam_account_name="user1", enabled=True, dont_require_preauth=True)
        assert user.is_asrep_roastable

    def test_has_weak_encryption(self):
        user = ADUser(sam_account_name="old_svc", use_des_key_only=True)
        assert user.has_weak_encryption


class TestADGroup:
    def test_is_security_group(self):
        group = ADGroup(sam_account_name="DA", group_type=-2147483646)
        assert group.is_security_group

    def test_is_not_security_group(self):
        group = ADGroup(sam_account_name="Dist", group_type=2)
        assert not group.is_security_group


class TestADComputer:
    def test_has_laps(self):
        from datetime import datetime, timezone
        comp = ADComputer(
            sam_account_name="WS001$",
            laps_password_expiry=datetime.now(timezone.utc),
        )
        assert comp.has_laps

    def test_no_laps(self):
        comp = ADComputer(sam_account_name="WS002$")
        assert not comp.has_laps
