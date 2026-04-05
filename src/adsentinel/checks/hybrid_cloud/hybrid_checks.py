"""Hybrid/Cloud Security checks (HYB-001 to HYB-010)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity


@check
class HYB001_AADConnectAccount(BaseCheck):
    id = "HYB-001"
    name = "Azure AD Connect Sync Account"
    description = "Check for Azure AD Connect sync account with excessive privileges"
    category = "Hybrid/Cloud Security"

    def run(self) -> List[Finding]:
        # AAD Connect creates MSOL_* or AAD_* accounts with DCSync rights
        sync_accounts = [
            u for u in self.context.users
            if u.enabled and (
                u.sam_account_name.upper().startswith("MSOL_")
                or u.sam_account_name.upper().startswith("AAD_")
            )
        ]
        if sync_accounts:
            return [self.finding(
                title=f"{len(sync_accounts)} Azure AD Connect sync accounts detected",
                description=(
                    "Azure AD Connect sync accounts (MSOL_*/AAD_*) have DCSync-equivalent privileges. "
                    "These accounts are high-value targets. Compromising them grants full domain replication rights."
                ),
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in sync_accounts],
                affected_count=len(sync_accounts),
                remediation_desc="Ensure sync accounts are protected. Use a dedicated OU with restricted ACLs. Consider upgrading to cloud sync.",
                mitre=[MitreAttack(technique_id="T1003.006", technique_name="DCSync", tactic="Credential Access")],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class HYB002_AADConnectServer(BaseCheck):
    id = "HYB-002"
    name = "Azure AD Connect Server"
    description = "Check if AAD Connect servers are properly secured"
    category = "Hybrid/Cloud Security"

    def run(self) -> List[Finding]:
        # Look for computers that might be AAD Connect servers
        aad_servers = [
            c for c in self.context.computers
            if c.enabled and any(
                kw in (c.dns_hostname or "").lower()
                for kw in ["aadc", "aadconnect", "dirsync", "aadsync"]
            )
        ]
        if aad_servers:
            return [self.finding(
                title=f"{len(aad_servers)} potential Azure AD Connect servers identified",
                description=(
                    "AAD Connect servers store credentials and have DCSync rights. "
                    "They must be treated as Tier 0 assets with restricted access."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_computer(c) for c in aad_servers],
                affected_count=len(aad_servers),
                remediation_desc="Harden AAD Connect servers as Tier 0. Restrict local admin access. Enable Credential Guard.",
                nist_800_53=["AC-6", "SC-28"],
            )]
        return []


@check
class HYB003_PasswordHashSync(BaseCheck):
    id = "HYB-003"
    name = "Password Hash Sync Awareness"
    description = "Flag presence of AAD Connect which may sync password hashes to Azure AD"
    category = "Hybrid/Cloud Security"

    def run(self) -> List[Finding]:
        has_aad = any(
            u.sam_account_name.upper().startswith("MSOL_") or u.sam_account_name.upper().startswith("AAD_")
            for u in self.context.users if u.enabled
        )
        if has_aad:
            return [self.finding(
                title="Azure AD Connect detected — verify Password Hash Sync (PHS) configuration",
                description=(
                    "If PHS is enabled, password hashes are synced to Azure AD. Ensure this is intentional "
                    "and that the sync account and server are hardened. Consider PTA or federation as alternatives."
                ),
                severity=Severity.INFO,
                remediation_desc="Review AAD Connect sync method. If PHS is used, ensure Tier 0 protection for the sync infrastructure.",
                nist_800_53=["SC-28"],
            )]
        return []


@check
class HYB004_SeamlessSSO(BaseCheck):
    id = "HYB-004"
    name = "Seamless SSO (AZUREADSSOACC)"
    description = "Check for Seamless SSO computer account"
    category = "Hybrid/Cloud Security"

    def run(self) -> List[Finding]:
        sso_account = None
        for c in self.context.computers:
            if c.sam_account_name.upper() == "AZUREADSSOACC$":
                sso_account = c
                break

        if sso_account:
            from adsentinel.utils.time_utils import days_since
            pwd_age = days_since(sso_account.password_last_set)
            if pwd_age > 30:
                return [self.finding(
                    title=f"Seamless SSO account (AZUREADSSOACC) password is {pwd_age} days old",
                    description=(
                        "The AZUREADSSOACC computer account holds the Kerberos decryption key for Seamless SSO. "
                        "If its password is compromised, attackers can forge Azure AD Kerberos tickets (Silver Ticket). "
                        "Microsoft recommends rotating this password every 30 days."
                    ),
                    severity=Severity.HIGH if pwd_age > 90 else Severity.MEDIUM,
                    affected_objects=[self.affected_computer(sso_account)],
                    affected_count=1,
                    remediation_desc="Rotate the AZUREADSSOACC password every 30 days using Update-AzureADSSOForest.",
                    powershell="Update-AzureADSSOForest -OnPremCredentials $cred",
                    mitre=[MitreAttack(technique_id="T1558.002", technique_name="Silver Ticket", tactic="Credential Access")],
                    nist_800_53=["IA-5"],
                )]
        return []


@check
class HYB005_OnPremAdminSynced(BaseCheck):
    id = "HYB-005"
    name = "Privileged Accounts Synced to Cloud"
    description = "Check if privileged on-prem accounts might be synced to Azure AD"
    category = "Hybrid/Cloud Security"

    def run(self) -> List[Finding]:
        # Privileged accounts should NOT be synced to Azure AD
        # Accounts with adminCount=1 that have a UPN are potentially synced
        synced_admins = [
            u for u in self.context.users
            if u.enabled and u.admin_count == 1 and u.upn
            and self.context.is_privileged_user(u)
            and u.sam_account_name.lower() not in ("administrator", "krbtgt")
        ]
        if synced_admins:
            return [self.finding(
                title=f"{len(synced_admins)} privileged accounts have UPNs (potentially synced to Azure AD)",
                description=(
                    "Privileged on-premises accounts with UPNs may be synced to Azure AD via AAD Connect. "
                    "If synced, compromise of the cloud identity could expose on-premises credentials."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in synced_admins[:50]],
                affected_count=len(synced_admins),
                remediation_desc="Exclude privileged accounts from AAD Connect sync scope. Use separate cloud-only admin accounts.",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class HYB006_CloudOnlyAdmins(BaseCheck):
    id = "HYB-006"
    name = "Dedicated Cloud Admin Accounts"
    description = "Check for dedicated cloud admin naming convention"
    category = "Hybrid/Cloud Security"

    def run(self) -> List[Finding]:
        # Look for cloud admin accounts (common pattern: *-admin, *_cloud, adm-*)
        cloud_admins = [
            u for u in self.context.users
            if u.enabled and u.admin_count == 1
            and any(kw in u.sam_account_name.lower() for kw in ["cloud", "azure", "aad"])
        ]
        # If we have AAD Connect but no cloud-specific admin accounts, warn
        has_aad = any(
            u.sam_account_name.upper().startswith("MSOL_") or u.sam_account_name.upper().startswith("AAD_")
            for u in self.context.users if u.enabled
        )
        if has_aad and not cloud_admins:
            return [self.finding(
                title="No dedicated cloud admin accounts detected in AD",
                description=(
                    "Azure AD Connect is present but no dedicated cloud admin accounts were found in AD. "
                    "Best practice is to use separate, cloud-only admin accounts for Azure AD administration "
                    "to prevent on-premises compromise from reaching the cloud."
                ),
                severity=Severity.LOW,
                remediation_desc="Create dedicated cloud-only admin accounts that are not synced from on-premises AD.",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class HYB007_MSOnlineGPO(BaseCheck):
    id = "HYB-007"
    name = "Microsoft Online Group Policy"
    description = "Check for Microsoft Online-related GPOs"
    category = "Hybrid/Cloud Security"

    def run(self) -> List[Finding]:
        online_gpos = [
            g for g in self.context.gpos
            if any(kw in g.get("display_name", "").lower()
                   for kw in ["office 365", "microsoft online", "azure", "intune"])
        ]
        if online_gpos:
            return [self.finding(
                title=f"{len(online_gpos)} cloud-related GPOs found",
                description="GPOs related to Microsoft Online/Azure services are deployed. Review for proper hybrid integration security.",
                severity=Severity.INFO,
                affected_count=len(online_gpos),
                remediation_desc="Review cloud-related GPOs for security best practices.",
                nist_800_53=["CM-6"],
                details={"gpo_names": [g.get("display_name", "") for g in online_gpos]},
            )]
        return []
