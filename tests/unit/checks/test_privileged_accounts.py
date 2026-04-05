"""Unit tests for Privileged Accounts checks."""

from datetime import datetime, timedelta, timezone

import pytest

from adsentinel.checks.privileged_accounts.builtin_groups import *
from tests.conftest import make_user, make_group


class TestPA001DomainAdminCount:
    def test_excessive_da(self, context):
        # Add more members to Domain Admins
        da_group = context.groups[0]  # Domain Admins
        for i in range(10):
            user = make_user(f"extra_admin_{i}", admin_count=1, member_of=[da_group.dn], sid_rid=2000 + i)
            context.users.append(user)
            da_group.member_dns.append(user.dn)

        check = PA001_DomainAdminCount(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_acceptable_da(self, context):
        # Context has 3 DA members, which is <= 5
        check = PA001_DomainAdminCount(context)
        findings = check.run()
        assert len(findings) == 0


class TestPA002EnterpriseAdmins:
    def test_too_many_ea(self, context):
        check = PA002_EnterpriseAdmins(context)
        findings = check.run()
        # EA has 2 members (admin + stale_admin)
        assert len(findings) == 1

    def test_single_ea(self, context):
        ea_group = context.groups[1]
        ea_group.member_dns = [ea_group.member_dns[0]]  # Keep only one
        check = PA002_EnterpriseAdmins(context)
        assert len(check.run()) == 0


class TestPA003SchemaAdmins:
    def test_non_empty(self, context):
        check = PA003_SchemaAdmins(context)
        findings = check.run()
        assert len(findings) == 1

    def test_empty_sa(self, context):
        sa_group = context.groups[2]
        sa_group.member_dns = []
        check = PA003_SchemaAdmins(context)
        assert len(check.run()) == 0


class TestPA005StaleAdmins:
    def test_stale_admin_found(self, context):
        check = PA005_StaleAdmins(context)
        findings = check.run()
        assert len(findings) == 1
        assert "stale" in findings[0].title.lower()


class TestPA006KerberoastableAdmins:
    def test_found(self, context):
        check = PA006_KerberoastableAdmins(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"


class TestPA008ProtectedUsers:
    def test_unprotected_admins(self, context):
        check = PA008_AdminsNotProtectedUsers(context)
        findings = check.run()
        assert len(findings) == 1


class TestPA011MachineAccountQuota:
    def test_nonzero_quota(self, context):
        context.domain_info.machine_account_quota = 10
        check = PA011_MachineAccountQuota(context)
        findings = check.run()
        assert len(findings) == 1

    def test_zero_quota(self, context):
        context.domain_info.machine_account_quota = 0
        check = PA011_MachineAccountQuota(context)
        assert len(check.run()) == 0


class TestPA012KrbtgtAge:
    def test_old_krbtgt(self, context):
        check = PA012_KrbtgtPasswordAge(context)
        findings = check.run()
        assert len(findings) == 1
        assert "KRBTGT" in findings[0].title


class TestPA013RecycleBin:
    def test_disabled(self, context):
        context.domain_info.ad_recycle_bin_enabled = False
        check = PA013_RecycleBinDisabled(context)
        findings = check.run()
        assert len(findings) == 1

    def test_enabled(self, context):
        context.domain_info.ad_recycle_bin_enabled = True
        check = PA013_RecycleBinDisabled(context)
        assert len(check.run()) == 0
