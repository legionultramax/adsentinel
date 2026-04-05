"""Unit tests for Kerberos Security checks."""

from datetime import datetime, timedelta, timezone

import pytest

from adsentinel.checks.kerberos.kerberoasting import *
from tests.conftest import make_user, make_computer


class TestKRB001Kerberoasting:
    def test_kerberoastable_found(self, context):
        check = KRB001_KerberoastableAccounts(context)
        findings = check.run()
        assert len(findings) == 1
        # Should find both svc_sql and svc_admin
        assert findings[0].affected_count >= 2

    def test_no_kerberoastable(self, context):
        for user in context.users:
            user.spn_list = []
        check = KRB001_KerberoastableAccounts(context)
        assert len(check.run()) == 0

    def test_privileged_is_critical(self, context):
        check = KRB001_KerberoastableAccounts(context)
        findings = check.run()
        assert findings[0].severity.value == "CRITICAL"  # Because svc_admin is privileged


class TestKRB002ASREPRoasting:
    def test_found(self, context):
        check = KRB002_ASREPRoastable(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_not_found(self, context):
        for user in context.users:
            user.dont_require_preauth = False
        check = KRB002_ASREPRoastable(context)
        assert len(check.run()) == 0


class TestKRB003UnconstrainedDelegation:
    def test_found(self, context):
        check = KRB003_UnconstrainedDelegation(context)
        findings = check.run()
        # Should find svc_unconstrained user + SRV001 computer
        assert len(findings) >= 1


class TestKRB005RBCD:
    def test_found(self, context):
        check = KRB005_RBCD(context)
        findings = check.run()
        assert len(findings) == 1


class TestKRB006DES:
    def test_des_found(self, context):
        check = KRB006_DESEncryption(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"


class TestKRB007ProtectedUsersEmpty:
    def test_empty(self, context):
        check = KRB007_ProtectedUsersEmpty(context)
        findings = check.run()
        assert len(findings) == 1

    def test_non_empty(self, context):
        for group in context.groups:
            if group.sam_account_name == "Protected Users":
                group.member_dns = ["CN=admin,CN=Users,DC=corp,DC=com"]
        check = KRB007_ProtectedUsersEmpty(context)
        assert len(check.run()) == 0


class TestKRB008T4D:
    def test_found(self, context):
        check = KRB008_T4DWithoutConstraint(context)
        findings = check.run()
        assert len(findings) == 1


class TestKRB010ShadowCredentials:
    def test_found(self, context):
        check = KRB010_ShadowCredentials(context)
        findings = check.run()
        assert len(findings) == 1


class TestKRB015LAPS:
    def test_low_coverage(self, context):
        check = KRB015_LAPSNotDeployed(context)
        findings = check.run()
        # 1 of 5 computers has LAPS = 20% coverage
        assert len(findings) == 1
        assert "LAPS" in findings[0].title

    def test_full_coverage(self, context):
        now = datetime.now(timezone.utc) + timedelta(days=30)
        for comp in context.computers:
            comp.laps_password_expiry = now
        check = KRB015_LAPSNotDeployed(context)
        assert len(check.run()) == 0
