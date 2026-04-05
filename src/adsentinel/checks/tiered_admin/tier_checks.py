"""Tiered Administration checks (TIER-001 to TIER-008)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity


@check
class TIER001_AdminsLogonWorkstations(BaseCheck):
    id = "TIER-001"
    name = "Tier 0 Accounts on Workstations"
    description = "Check if privileged accounts are used on non-Tier 0 systems"
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        # Privileged accounts should only log on to Tier 0 systems (DCs, PAWs)
        # Check if admin accounts have logonWorkstation restrictions
        unrestricted_admins = [
            u for u in self.context.users
            if u.enabled and self.context.is_privileged_user(u)
            and u.sam_account_name.lower() not in ("administrator", "krbtgt")
        ]
        if unrestricted_admins:
            return [self.finding(
                title=f"{len(unrestricted_admins)} Tier 0 accounts have no logon workstation restrictions",
                description=(
                    "Privileged accounts can log on to any workstation. Without logon restrictions, "
                    "credential theft on any compromised workstation exposes Tier 0 credentials."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in unrestricted_admins[:50]],
                affected_count=len(unrestricted_admins),
                remediation_desc="Set logonWorkstation on Tier 0 accounts to limit them to PAWs and DCs only.",
                powershell="Set-ADUser -Identity 'ADMIN' -LogonWorkstations 'PAW01,DC01'",
                mitre=[MitreAttack(technique_id="T1078.002", technique_name="Domain Accounts", tactic="Persistence")],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class TIER002_ServiceAccountTiering(BaseCheck):
    id = "TIER-002"
    name = "Service Account Tier Separation"
    description = "Check for service accounts in privileged groups"
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        svc_in_priv = [
            u for u in self.context.users
            if u.enabled and u.spn_list and self.context.is_privileged_user(u)
            and not u.sam_account_name.endswith("$")
        ]
        if svc_in_priv:
            return [self.finding(
                title=f"{len(svc_in_priv)} service accounts in Tier 0 groups",
                description=(
                    "Service accounts with SPNs in privileged groups violate tier separation. "
                    "These accounts are Kerberoastable and provide a direct path to Tier 0 compromise."
                ),
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in svc_in_priv],
                affected_count=len(svc_in_priv),
                remediation_desc="Remove service accounts from Tier 0 groups. Use gMSAs with least-privilege delegation.",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class TIER003_AdminCountHygiene(BaseCheck):
    id = "TIER-003"
    name = "AdminCount Cleanup"
    description = "Check for orphaned adminCount=1 values"
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        orphaned = [
            u for u in self.context.users
            if u.enabled and u.admin_count == 1
            and not self.context.is_privileged_user(u)
        ]
        if orphaned:
            return [self.finding(
                title=f"{len(orphaned)} accounts have orphaned adminCount=1",
                description=(
                    "Accounts with adminCount=1 but not in privileged groups retain inherited "
                    "AdminSDHolder ACLs. These accounts cannot have their permissions modified "
                    "by normal delegation and may have stale, overly permissive ACLs."
                ),
                severity=Severity.LOW,
                affected_objects=[self.affected_user(u) for u in orphaned[:50]],
                affected_count=len(orphaned),
                remediation_desc="Clear adminCount and reset ACL inheritance on orphaned accounts.",
                powershell="Get-ADUser -Filter {adminCount -eq 1} | ForEach-Object { Set-ADUser $_ -Clear adminCount }",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class TIER004_DCSensitiveNotDelegated(BaseCheck):
    id = "TIER-004"
    name = "Sensitive & Not Delegated on Tier 0"
    description = "Check if Tier 0 accounts have 'Account is sensitive and cannot be delegated'"
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        priv_no_sensitive = [
            u for u in self.context.users
            if u.enabled and self.context.is_privileged_user(u)
            and not u.sensitive_and_not_delegated
            and not u.is_protected_user
        ]
        if priv_no_sensitive:
            return [self.finding(
                title=f"{len(priv_no_sensitive)} Tier 0 accounts without 'sensitive and cannot be delegated'",
                description=(
                    "Privileged accounts without this flag can have their credentials delegated "
                    "through Kerberos delegation, enabling impersonation across services."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in priv_no_sensitive[:50]],
                affected_count=len(priv_no_sensitive),
                remediation_desc="Set 'Account is sensitive and cannot be delegated' on all Tier 0 accounts, or add them to Protected Users.",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class TIER005_ProtectedUsersAdoption(BaseCheck):
    id = "TIER-005"
    name = "Protected Users Group Adoption"
    description = "Check if privileged users are in the Protected Users group"
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        protected_group = None
        for g in self.context.groups:
            if g.sam_account_name.lower() == "protected users":
                protected_group = g
                break

        if not protected_group or not protected_group.member_dns:
            priv_count = len([
                u for u in self.context.users
                if u.enabled and self.context.is_privileged_user(u)
            ])
            if priv_count > 0:
                return [self.finding(
                    title=f"Protected Users group is empty — {priv_count} privileged accounts unprotected",
                    description=(
                        "Protected Users group provides: no NTLM auth, no DES/RC4, no delegation, "
                        "no credential caching, 4-hour TGT lifetime. All Tier 0 accounts should be members."
                    ),
                    severity=Severity.MEDIUM,
                    affected_count=priv_count,
                    remediation_desc="Add all Tier 0 accounts to the Protected Users group after testing compatibility.",
                    powershell="Add-ADGroupMember -Identity 'Protected Users' -Members (Get-ADGroupMember 'Domain Admins')",
                    nist_800_53=["AC-6"],
                )]
        return []


@check
class TIER006_PAWCompliance(BaseCheck):
    id = "TIER-006"
    name = "Privileged Access Workstation (PAW)"
    description = "Check for PAW infrastructure indicators"
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        # Check for PAW-related OUs, groups, or computers
        paw_indicators = [
            c for c in self.context.computers
            if c.enabled and any(
                kw in (c.dns_hostname or "").lower() or kw in c.dn.lower()
                for kw in ["paw", "privileged", "admin-ws", "adminws", "tier0"]
            )
        ]
        if not paw_indicators:
            priv_count = len([u for u in self.context.users if u.enabled and self.context.is_privileged_user(u)])
            if priv_count > 3:
                return [self.finding(
                    title="No Privileged Access Workstation (PAW) infrastructure detected",
                    description=(
                        "No computers with PAW naming conventions were found. Tier 0 accounts should "
                        "only authenticate from hardened PAWs to prevent credential theft."
                    ),
                    severity=Severity.LOW,
                    remediation_desc="Deploy Privileged Access Workstations for Tier 0 administration.",
                    nist_800_53=["AC-6", "SC-39"],
                )]
        return []


@check
class TIER007_CrossTierGroupMembership(BaseCheck):
    id = "TIER-007"
    name = "Cross-Tier Group Nesting"
    description = "Check for Tier 0 groups nested in lower-tier groups"
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        # Check if any privileged groups are nested inside non-privileged groups
        priv_group_dns = set(self.context.privileged_groups.keys())
        cross_tier = []
        for group in self.context.groups:
            if group.dn not in priv_group_dns:
                for member_dn in group.member_dns:
                    if member_dn in priv_group_dns:
                        cross_tier.append((group, member_dn))

        if cross_tier:
            return [self.finding(
                title=f"{len(cross_tier)} cross-tier group nesting violations",
                description="Privileged groups are nested inside non-privileged groups, potentially granting unintended Tier 0 access.",
                severity=Severity.HIGH,
                affected_objects=[
                    AffectedObject(dn=g.dn, sam_account_name=g.sam_account_name, object_type="group",
                                   details={"contains_privileged": nested_dn})
                    for g, nested_dn in cross_tier[:20]
                ],
                affected_count=len(cross_tier),
                remediation_desc="Remove privileged group nesting from non-privileged groups.",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class TIER008_GMSAAdoption(BaseCheck):
    id = "TIER-008"
    name = "gMSA Adoption for Service Accounts"
    description = "Check if traditional service accounts should be converted to gMSAs"
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        traditional_svc = [
            u for u in self.context.users
            if u.enabled and u.spn_list and not u.sam_account_name.endswith("$")
        ]
        if traditional_svc and len(traditional_svc) > 3:
            return [self.finding(
                title=f"{len(traditional_svc)} traditional service accounts should be converted to gMSAs",
                description=(
                    "Traditional service accounts with SPNs use static passwords that are Kerberoastable. "
                    "Group Managed Service Accounts (gMSAs) use 240-character auto-rotating passwords "
                    "that eliminate Kerberoasting risk."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in traditional_svc[:50]],
                affected_count=len(traditional_svc),
                remediation_desc="Convert service accounts to gMSAs where supported.",
                powershell="New-ADServiceAccount -Name 'svc_sql' -DNSHostName 'svc_sql.corp.com' -PrincipalsAllowedToRetrieveManagedPassword 'SQL_Servers$'",
                nist_800_53=["IA-5"],
            )]
        return []
