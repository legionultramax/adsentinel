"""Unit tests for Phase 3 check categories: ADCS, Coercion, Hybrid/Cloud, Tiered Admin, SCCM."""

from datetime import datetime, timedelta, timezone

import pytest

from adsentinel.models.domain import ADTrust, DomainController
from tests.conftest import make_computer, make_group, make_user

# Import all check classes
from adsentinel.checks.adcs.esc_checks import *
from adsentinel.checks.coercion.coercion_checks import *
from adsentinel.checks.hybrid_cloud.hybrid_checks import *
from adsentinel.checks.tiered_admin.tier_checks import *
from adsentinel.checks.sccm.sccm_checks import *


# ============================================================================
# AD CS ESC checks
# ============================================================================

def _make_template(**overrides):
    """Create a test certificate template dict."""
    base = {
        "dn": "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com",
        "name": "TestTemplate",
        "display_name": "Test Template",
        "name_flag": 0,
        "enrollment_flag": 0,
        "ra_signature": 0,
        "ekus": [],
        "schema_version": 2,
        "enrollee_supplies_subject": False,
        "enrollee_supplies_san": False,
        "no_security_extension": False,
        "requires_manager_approval": False,
        "requires_ra_signature": False,
        "allows_client_auth": False,
        "allows_any_purpose": False,
        "is_request_agent": False,
    }
    base.update(overrides)
    return base


class TestADCS001ESC1:
    def test_esc1_vulnerable(self, context):
        context.certificate_templates = [_make_template(
            name="VulnTemplate",
            enrollee_supplies_subject=True,
            allows_client_auth=True,
        )]
        check = ADCS001_ESC1(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_esc1_manager_approval_safe(self, context):
        context.certificate_templates = [_make_template(
            enrollee_supplies_subject=True,
            allows_client_auth=True,
            requires_manager_approval=True,
        )]
        check = ADCS001_ESC1(context)
        assert len(check.run()) == 0

    def test_esc1_no_client_auth_safe(self, context):
        context.certificate_templates = [_make_template(
            enrollee_supplies_subject=True,
            allows_client_auth=False,
        )]
        check = ADCS001_ESC1(context)
        assert len(check.run()) == 0


class TestADCS002ESC2:
    def test_any_purpose(self, context):
        context.certificate_templates = [_make_template(
            allows_any_purpose=True,
        )]
        check = ADCS002_ESC2(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_explicit_eku_safe(self, context):
        context.certificate_templates = [_make_template(
            allows_any_purpose=False,
        )]
        check = ADCS002_ESC2(context)
        assert len(check.run()) == 0


class TestADCS003ESC3:
    def test_request_agent(self, context):
        context.certificate_templates = [_make_template(
            is_request_agent=True,
        )]
        check = ADCS003_ESC3(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"


class TestADCS006ESC6:
    def test_san_flag_on_ca(self, context):
        context.enrollment_services = [{
            "dn": "CN=CA01,CN=Enrollment Services,...",
            "name": "CA01",
            "san_flag_enabled": True,
            "has_http_enrollment": False,
            "enrollment_servers": [],
        }]
        check = ADCS006_ESC6(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_san_flag_off(self, context):
        context.enrollment_services = [{
            "dn": "CN=CA01,...",
            "name": "CA01",
            "san_flag_enabled": False,
            "has_http_enrollment": False,
            "enrollment_servers": [],
        }]
        check = ADCS006_ESC6(context)
        assert len(check.run()) == 0


class TestADCS008ESC8:
    def test_http_enrollment(self, context):
        context.enrollment_services = [{
            "dn": "CN=CA01,...",
            "name": "CA01",
            "san_flag_enabled": False,
            "has_http_enrollment": True,
            "enrollment_servers": ["http://ca01.corp.com/certsrv"],
        }]
        check = ADCS008_ESC8(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"


class TestADCS009ESC9:
    def test_no_security_ext(self, context):
        context.certificate_templates = [_make_template(
            no_security_extension=True,
            allows_client_auth=True,
        )]
        check = ADCS009_ESC9(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"


class TestADCS010ESC10:
    def test_weak_mapping(self, context):
        context.registry_values["StrongCertificateBindingEnforcement"] = "1"
        check = ADCS010_ESC10(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_strong_mapping(self, context):
        context.registry_values["StrongCertificateBindingEnforcement"] = "2"
        check = ADCS010_ESC10(context)
        assert len(check.run()) == 0


class TestADCS013Inventory:
    def test_adcs_present(self, context):
        context.certificate_authorities = [{"name": "CA01"}]
        context.enrollment_services = [{"name": "ES01"}]
        context.certificate_templates = [_make_template()]
        check = ADCS013_NoCAS(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "INFO"

    def test_no_adcs(self, context):
        check = ADCS013_NoCAS(context)
        assert len(check.run()) == 0


# ============================================================================
# Coercion checks
# ============================================================================

class TestCOER001PrintSpooler:
    def test_spooler_running(self, context):
        context.service_statuses["Spooler"] = "Running"
        check = COER001_PrintSpooler(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_spooler_stopped(self, context):
        context.service_statuses["Spooler"] = "Stopped"
        check = COER001_PrintSpooler(context)
        assert len(check.run()) == 0


class TestCOER004ShadowCredentials:
    def test_shadow_creds_found(self, context):
        # shadow_cred_user already in context
        check = COER004_ShadowCredentials(context)
        findings = check.run()
        assert len(findings) == 1

    def test_no_shadow_creds(self, context):
        for u in context.users:
            u.ms_ds_key_credential_link = []
        for c in context.computers:
            c.ms_ds_key_credential_link = []
        check = COER004_ShadowCredentials(context)
        assert len(check.run()) == 0


class TestCOER006UnconstrainedCoerce:
    def test_non_dc_unconstrained(self, context):
        # SRV001 is trusted_for_delegation and not a DC
        check = COER006_UnconstrainedDelegCoerce(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"


class TestCOER007NTLMRelayMitigation:
    def test_missing_protections(self, context):
        context.smb_config = {"RequireSecuritySignature": False}
        context.registry_values["LDAPServerIntegrity"] = "1"
        context.registry_values["LdapEnforceChannelBinding"] = "0"
        check = COER007_NTLMRelayMitigation(context)
        findings = check.run()
        assert len(findings) == 1
        assert "3 gaps" in findings[0].title


class TestCOER008RBCD:
    def test_rbcd_with_maq(self, context):
        context.domain_info.machine_account_quota = 10
        # SRV002 has RBCD configured
        check = COER008_RBCDAbuse(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_no_maq(self, context):
        context.domain_info.machine_account_quota = 0
        check = COER008_RBCDAbuse(context)
        assert len(check.run()) == 0


# ============================================================================
# Hybrid/Cloud checks
# ============================================================================

class TestHYB001AADConnect:
    def test_sync_account_found(self, context):
        context.users.append(make_user("MSOL_abc123", sid_rid=7001))
        check = HYB001_AADConnectAccount(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_no_sync_account(self, context):
        check = HYB001_AADConnectAccount(context)
        assert len(check.run()) == 0


class TestHYB004SeamlessSSO:
    def test_old_password(self, context):
        sso = make_computer("AZUREADSSOACC")
        sso.password_last_set = datetime.now(timezone.utc) - timedelta(days=100)
        context.computers.append(sso)
        check = HYB004_SeamlessSSO(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_fresh_password(self, context):
        sso = make_computer("AZUREADSSOACC")
        sso.password_last_set = datetime.now(timezone.utc) - timedelta(days=10)
        context.computers.append(sso)
        check = HYB004_SeamlessSSO(context)
        assert len(check.run()) == 0

    def test_no_sso_account(self, context):
        check = HYB004_SeamlessSSO(context)
        assert len(check.run()) == 0


class TestHYB005PrivSynced:
    def test_admins_with_upn(self, context):
        check = HYB005_OnPremAdminSynced(context)
        findings = check.run()
        # admin and stale_admin and svc_admin have UPN + admin_count
        assert len(findings) == 1


# ============================================================================
# Tiered Admin checks
# ============================================================================

class TestTIER001AdminLogon:
    def test_unrestricted_admins(self, context):
        check = TIER001_AdminsLogonWorkstations(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"


class TestTIER002ServiceTiering:
    def test_svc_in_da(self, context):
        check = TIER002_ServiceAccountTiering(context)
        findings = check.run()
        # svc_admin has SPN + is in DA
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"


class TestTIER004SensitiveNotDelegated:
    def test_priv_without_flag(self, context):
        check = TIER004_DCSensitiveNotDelegated(context)
        findings = check.run()
        assert len(findings) == 1

    def test_all_sensitive(self, context):
        for u in context.users:
            u.sensitive_and_not_delegated = True
        check = TIER004_DCSensitiveNotDelegated(context)
        assert len(check.run()) == 0


class TestTIER005ProtectedUsers:
    def test_empty_protected_users(self, context):
        check = TIER005_ProtectedUsersAdoption(context)
        findings = check.run()
        assert len(findings) == 1


class TestTIER008GMSA:
    def test_traditional_svc_accounts(self, context):
        check = TIER008_GMSAAdoption(context)
        findings = check.run()
        # svc_sql, svc_admin have SPNs
        # Need 4+ to trigger - add more
        context.users.append(make_user("svc_web", spns=["HTTP/web01.corp.com"], sid_rid=8001))
        context.users.append(make_user("svc_app", spns=["HTTP/app02.corp.com"], sid_rid=8002))
        findings = check.run()
        assert len(findings) == 1


# ============================================================================
# SCCM checks
# ============================================================================

class TestSCCM001NAA:
    def test_naa_found(self, context):
        context.users.append(make_user("sccm_naa", sid_rid=9001))
        check = SCCM001_NAAExposure(context)
        findings = check.run()
        assert len(findings) == 1

    def test_no_naa(self, context):
        check = SCCM001_NAAExposure(context)
        assert len(check.run()) == 0


class TestSCCM004ClientPush:
    def test_push_account(self, context):
        context.users.append(make_user("sccmpush_acct", sid_rid=9002))
        check = SCCM004_ClientPushInstall(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"
