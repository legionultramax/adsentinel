"""Unit tests for Phase 2 check categories: ACL, Auth, Trust, DNS, Replication, Operational, GPO, Object."""

from datetime import datetime, timedelta, timezone

import pytest

from adsentinel.models.domain import ADTrust, DomainController
from tests.conftest import make_computer, make_group, make_user

# Import all check classes
from adsentinel.checks.acl_dacl.dangerous_aces import *
from adsentinel.checks.authentication.ntlm_config import *
from adsentinel.checks.trust_security.trust_config import *
from adsentinel.checks.dns_security.zone_config import *
from adsentinel.checks.replication.dcsync import *
from adsentinel.checks.operational.audit_policy import *
from adsentinel.checks.gpo_security.gpo_config import *
from adsentinel.checks.object_security.object_config import *


# ============================================================================
# ACL/DACL checks
# ============================================================================

class TestACL001PreWin2000:
    def test_members_found(self, context):
        context.groups.append(make_group(
            "Pre-Windows 2000 Compatible Access", sid_rid=554,
            members=["CN=Authenticated Users,CN=Builtin,DC=corp,DC=com"],
        ))
        check = ACL001_PreWin2000Group(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_no_prewin2000_group(self, context):
        check = ACL001_PreWin2000Group(context)
        assert len(check.run()) == 0


class TestACL002AdminSDHolder:
    def test_orphaned_admincount(self, context):
        # Add many users with adminCount=1 but not in privileged groups
        for i in range(15):
            context.users.append(make_user(f"orphan_{i}", admin_count=1, sid_rid=2000 + i))
        check = ACL002_AdminSDHolderModified(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_few_orphans_ok(self, context):
        for i in range(3):
            context.users.append(make_user(f"orphan_{i}", admin_count=1, sid_rid=2000 + i))
        check = ACL002_AdminSDHolderModified(context)
        assert len(check.run()) == 0


class TestACL005ComputerOwnership:
    def test_high_maq(self, context):
        context.domain_info.machine_account_quota = 10
        check = ACL005_ComputerObjectOwnership(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_zero_maq_ok(self, context):
        context.domain_info.machine_account_quota = 0
        check = ACL005_ComputerObjectOwnership(context)
        assert len(check.run()) == 0


# ============================================================================
# Authentication checks
# ============================================================================

class TestAUTH001NTLMv1:
    def test_ntlmv1_allowed(self, context):
        context.registry_values["LmCompatibilityLevel"] = "2"
        check = AUTH001_NTLMv1(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_ntlmv2_only(self, context):
        context.registry_values["LmCompatibilityLevel"] = "5"
        check = AUTH001_NTLMv1(context)
        assert len(check.run()) == 0

    def test_no_data(self, context):
        check = AUTH001_NTLMv1(context)
        assert len(check.run()) == 0


class TestAUTH002WDigest:
    def test_wdigest_enabled(self, context):
        context.registry_values["UseLogonCredential"] = "1"
        check = AUTH002_WDigest(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_wdigest_disabled(self, context):
        context.registry_values["UseLogonCredential"] = "0"
        check = AUTH002_WDigest(context)
        assert len(check.run()) == 0


class TestAUTH003SMBSigning:
    def test_smb_signing_not_required(self, context):
        context.smb_config = {"RequireSecuritySignature": False}
        check = AUTH003_SMBSigning(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_smb_signing_required(self, context):
        context.smb_config = {"RequireSecuritySignature": True}
        check = AUTH003_SMBSigning(context)
        assert len(check.run()) == 0


class TestAUTH004SMBv1:
    def test_smbv1_enabled(self, context):
        context.smb_config = {"EnableSMB1Protocol": True}
        check = AUTH004_SMBv1(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_smbv1_disabled(self, context):
        context.smb_config = {"EnableSMB1Protocol": False}
        check = AUTH004_SMBv1(context)
        assert len(check.run()) == 0


class TestAUTH005LDAPSigning:
    def test_ldap_signing_not_required(self, context):
        context.registry_values["LDAPServerIntegrity"] = "1"
        check = AUTH005_LDAPSigning(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_ldap_signing_required(self, context):
        context.registry_values["LDAPServerIntegrity"] = "2"
        check = AUTH005_LDAPSigning(context)
        assert len(check.run()) == 0


class TestAUTH009AnonymousBind:
    def test_low_functional_level(self, context):
        context.domain_info.domain_functional_level = 2
        check = AUTH009_AnonymousBind(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_high_functional_level(self, context):
        context.domain_info.domain_functional_level = 7
        check = AUTH009_AnonymousBind(context)
        assert len(check.run()) == 0


class TestAUTH011PasswordNotReqd:
    def test_computers_passwd_notreqd(self, context):
        from adsentinel.constants import UAC_PASSWD_NOTREQD
        context.computers.append(make_computer("BAD_PC"))
        context.computers[-1].user_account_control = UAC_PASSWD_NOTREQD
        check = AUTH011_PasswordNotReqdComputers(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"


class TestAUTH012StaleComputerPasswords:
    def test_stale_computers(self, context):
        now = datetime.now(timezone.utc)
        for i in range(15):
            c = make_computer(f"STALE_{i}")
            c.last_logon = now - timedelta(days=180)
            context.computers.append(c)
        check = AUTH012_StaleComputerPasswords(context)
        findings = check.run()
        assert len(findings) == 1


# ============================================================================
# Trust Security checks
# ============================================================================

class TestTR001BidirectionalTrusts:
    def test_bidi_trust(self, context):
        context.trusts = [ADTrust(dn="CN=partner,CN=System,DC=corp,DC=com",
                                   trusted_domain="partner.com", trust_direction=3)]
        check = TR001_BidirectionalTrusts(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_one_way_trust(self, context):
        context.trusts = [ADTrust(dn="CN=partner,CN=System,DC=corp,DC=com",
                                   trusted_domain="partner.com", trust_direction=2)]
        check = TR001_BidirectionalTrusts(context)
        assert len(check.run()) == 0


class TestTR002SIDFiltering:
    def test_sid_filtering_disabled(self, context):
        context.trusts = [ADTrust(dn="t1", trusted_domain="evil.com", sid_filtering_enabled=False)]
        check = TR002_SIDFilteringDisabled(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_sid_filtering_enabled(self, context):
        context.trusts = [ADTrust(dn="t1", trusted_domain="good.com", sid_filtering_enabled=True)]
        check = TR002_SIDFilteringDisabled(context)
        assert len(check.run()) == 0


class TestTR005ExternalTrusts:
    def test_downlevel_trust(self, context):
        context.trusts = [ADTrust(dn="t1", trusted_domain="old.com", trust_type=1)]
        check = TR005_TrustToOldDomain(context)
        findings = check.run()
        assert len(findings) == 1

    def test_no_downlevel(self, context):
        context.trusts = [ADTrust(dn="t1", trusted_domain="new.com", trust_type=2)]
        check = TR005_TrustToOldDomain(context)
        assert len(check.run()) == 0


# ============================================================================
# DNS Security checks
# ============================================================================

class TestDNS002DynamicUpdates:
    def test_zones_found(self, context):
        context.dns_zones = [{"name": "corp.com"}, {"name": "sub.corp.com"}]
        check = DNS002_DynamicUpdates(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "INFO"

    def test_no_zones(self, context):
        context.dns_zones = []
        check = DNS002_DynamicUpdates(context)
        assert len(check.run()) == 0


class TestDNS005WildcardRecords:
    def test_wildcard_found(self, context):
        context.dns_zones = [{"name": "*.corp.com"}]
        check = DNS005_DangerousRecords(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_no_wildcard(self, context):
        context.dns_zones = [{"name": "corp.com"}]
        check = DNS005_DangerousRecords(context)
        assert len(check.run()) == 0


# ============================================================================
# Replication checks
# ============================================================================

class TestREP001DCCount:
    def test_single_dc(self, context):
        check = REP001_DCCount(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_multiple_dcs(self, context):
        context.domain_info.domain_controllers.append(
            DomainController(hostname="DC02.corp.com", os_version="Windows Server 2019")
        )
        check = REP001_DCCount(context)
        assert len(check.run()) == 0


class TestREP004DCOSVersions:
    def test_mixed_os(self, context):
        context.domain_info.domain_controllers = [
            DomainController(hostname="DC01.corp.com", os_version="Windows Server 2016"),
            DomainController(hostname="DC02.corp.com", os_version="Windows Server 2019"),
            DomainController(hostname="DC03.corp.com", os_version="Windows Server 2022"),
        ]
        check = REP004_DCOSVersions(context)
        findings = check.run()
        assert len(findings) == 1

    def test_uniform_os(self, context):
        context.domain_info.domain_controllers = [
            DomainController(hostname="DC01.corp.com", os_version="Windows Server 2022"),
            DomainController(hostname="DC02.corp.com", os_version="Windows Server 2022"),
        ]
        check = REP004_DCOSVersions(context)
        assert len(check.run()) == 0


class TestREP005Tombstone:
    def test_short_tombstone(self, context):
        context.domain_info.tombstone_lifetime = 60
        check = REP005_TombstoneLifetime(context)
        findings = check.run()
        assert len(findings) == 1

    def test_adequate_tombstone(self, context):
        context.domain_info.tombstone_lifetime = 180
        check = REP005_TombstoneLifetime(context)
        assert len(check.run()) == 0


# ============================================================================
# Operational checks
# ============================================================================

class TestOPS001AuditPolicy:
    def test_audit_not_collected(self, context):
        context.audit_policy = None
        check = OPS001_AuditPolicyNotCollected(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "INFO"

    def test_missing_categories(self, context):
        context.audit_policy = {
            "Logon": "Success",
            "Account Logon": "No Auditing",
            "Account Management": "",
            "Directory Service Access": "Success and Failure",
            "Policy Change": "Success and Failure",
        }
        check = OPS001_AuditPolicyNotCollected(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_all_configured(self, context):
        context.audit_policy = {
            "Logon": "Success and Failure",
            "Account Logon": "Success and Failure",
            "Account Management": "Success and Failure",
            "Directory Service Access": "Success and Failure",
            "Policy Change": "Success and Failure",
        }
        check = OPS001_AuditPolicyNotCollected(context)
        assert len(check.run()) == 0


class TestOPS003PowerShellLogging:
    def test_not_enabled(self, context):
        context.registry_values["EnableScriptBlockLogging"] = "0"
        check = OPS003_PowerShellLogging(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_enabled(self, context):
        context.registry_values["EnableScriptBlockLogging"] = "1"
        check = OPS003_PowerShellLogging(context)
        assert len(check.run()) == 0


class TestOPS005PrintSpooler:
    def test_spooler_running(self, context):
        context.service_statuses["Spooler"] = "Running"
        check = OPS005_PrintSpoolerOnDC(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_spooler_stopped(self, context):
        context.service_statuses["Spooler"] = "Stopped"
        check = OPS005_PrintSpoolerOnDC(context)
        assert len(check.run()) == 0


class TestOPS006PrivilegedServiceAccounts:
    def test_svc_in_da(self, context):
        # svc_admin has SPN and is in DA group
        check = OPS006_ScheduledTaskAudit(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"


class TestOPS008DescriptionAudit:
    def test_password_in_group_desc(self, context):
        context.groups.append(make_group("TestGroup", sid_rid=9999))
        context.groups[-1].description = "Service password is P@ss123"
        check = OPS008_DescriptionAudit(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_clean_descriptions(self, context):
        for g in context.groups:
            g.description = "Normal group description"
        check = OPS008_DescriptionAudit(context)
        assert len(check.run()) == 0


# ============================================================================
# GPO Security checks
# ============================================================================

class TestGPO002DefaultDomainPolicy:
    def test_disabled(self, context):
        context.gpos = [{"display_name": "Default Domain Policy", "is_disabled": True}]
        check = GPO002_DefaultDomainPolicy(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_enabled(self, context):
        context.gpos = [{"display_name": "Default Domain Policy", "is_disabled": False}]
        check = GPO002_DefaultDomainPolicy(context)
        assert len(check.run()) == 0


class TestGPO004DisabledGPOs:
    def test_many_disabled(self, context):
        context.gpos = [
            {"display_name": f"GPO_{i}", "is_disabled": True} for i in range(10)
        ]
        check = GPO004_DisabledGPOs(context)
        findings = check.run()
        assert len(findings) == 1

    def test_few_disabled(self, context):
        context.gpos = [
            {"display_name": "GPO_1", "is_disabled": True},
            {"display_name": "GPO_2", "is_disabled": False},
        ]
        check = GPO004_DisabledGPOs(context)
        assert len(check.run()) == 0


class TestGPO006ExcessiveGPOs:
    def test_excessive(self, context):
        context.gpos = [{"display_name": f"GPO_{i}", "is_disabled": False} for i in range(150)]
        check = GPO006_GPOCount(context)
        findings = check.run()
        assert len(findings) == 1

    def test_normal_count(self, context):
        context.gpos = [{"display_name": f"GPO_{i}", "is_disabled": False} for i in range(50)]
        check = GPO006_GPOCount(context)
        assert len(check.run()) == 0


class TestGPO008GPOSysvol:
    def test_missing_path(self, context):
        context.gpos = [{"display_name": "Bad GPO", "file_sys_path": ""}]
        check = GPO008_GPOSysvol(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_has_path(self, context):
        context.gpos = [{"display_name": "Good GPO", "file_sys_path": "\\\\corp.com\\SysVol\\corp.com\\Policies\\{guid}"}]
        check = GPO008_GPOSysvol(context)
        assert len(check.run()) == 0


# ============================================================================
# Object Security checks
# ============================================================================

class TestOBJ001EmptyGroups:
    def test_many_empty_groups(self, context):
        for i in range(25):
            context.groups.append(make_group(f"Empty_Group_{i}", sid_rid=4000 + i, members=[]))
        check = OBJ001_EmptyGroups(context)
        findings = check.run()
        assert len(findings) == 1

    def test_few_empty_ok(self, context):
        context.groups.append(make_group("Small_Empty", sid_rid=4000, members=[]))
        check = OBJ001_EmptyGroups(context)
        assert len(check.run()) == 0


class TestOBJ005SIDHistory:
    def test_sid_history_found(self, context):
        context.users.append(make_user("migrated", sid_rid=5000))
        context.users[-1].sid_history = ["S-1-5-21-999999-999999-999999-1234"]
        check = OBJ005_SIDHistoryPresent(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_no_sid_history(self, context):
        check = OBJ005_SIDHistoryPresent(context)
        assert len(check.run()) == 0


class TestOBJ007DuplicateSPNs:
    def test_duplicate_spn(self, context):
        context.users.append(make_user("dup1", spns=["HTTP/web01.corp.com"], sid_rid=6000))
        context.users.append(make_user("dup2", spns=["HTTP/web01.corp.com"], sid_rid=6001))
        check = OBJ007_DuplicateSPNs(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_unique_spns(self, context):
        check = OBJ007_DuplicateSPNs(context)
        # svc_sql and svc_admin have different SPNs
        assert len(check.run()) == 0


class TestOBJ008ComputersInDefault:
    def test_many_in_default(self, context):
        for i in range(15):
            context.computers.append(make_computer(f"DEFAULT_{i}"))
        check = OBJ008_ComputersInDefaultOU(context)
        findings = check.run()
        assert len(findings) == 1

    def test_moved_computers(self, context):
        context.computers = []
        c = make_computer("MOVED01")
        c.dn = "CN=MOVED01,OU=Workstations,DC=corp,DC=com"
        context.computers.append(c)
        check = OBJ008_ComputersInDefaultOU(context)
        assert len(check.run()) == 0
