"""Privileged Accounts checks (PA-001 to PA-015)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import (
    MITRE_ACCOUNT_MANIPULATION,
    MITRE_DCSYNC,
    MITRE_KERBEROASTING,
    MITRE_PERMISSION_GROUPS_DISCOVERY,
    RID_DOMAIN_ADMINS,
    RID_ENTERPRISE_ADMINS,
    RID_KRBTGT,
    RID_SCHEMA_ADMINS,
)
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity
from adsentinel.utils.sid import get_rid
from adsentinel.utils.time_utils import days_since
from adsentinel.utils.well_known import DANGEROUS_BUILTIN_GROUPS


@check
class PA001_DomainAdminCount(BaseCheck):
    id = "PA-001"
    name = "Domain Admins Count"
    description = "Check for excessive Domain Admin membership"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        da_members = self._get_group_members_by_rid(RID_DOMAIN_ADMINS)
        if len(da_members) > 5:
            return [self.finding(
                title=f"Excessive Domain Admin membership ({len(da_members)} members)",
                description=(
                    f"The Domain Admins group has {len(da_members)} members. "
                    "Each Domain Admin is a high-value target. Minimize membership to reduce attack surface."
                ),
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in da_members[:50]],
                affected_count=len(da_members),
                remediation_desc="Reduce Domain Admins to essential personnel only. Use delegated administration for routine tasks.",
                powershell="Get-ADGroupMember 'Domain Admins' -Recursive | Select-Object SamAccountName, objectClass",
                mitre=[MitreAttack(technique_id=MITRE_PERMISSION_GROUPS_DISCOVERY, technique_name="Domain Groups", tactic="Discovery")],
                cis_controls=["5.4", "6.8"],
                nist_800_53=["AC-6"],
                details={"member_count": len(da_members)},
            )]
        return []

    def _get_group_members_by_rid(self, rid: int):
        for group in self.context.groups:
            group_rid = get_rid(group.sid) if group.sid else None
            if group_rid == rid:
                return [u for u in self.context.users if u.dn in group.member_dns]
        return []


@check
class PA002_EnterpriseAdmins(BaseCheck):
    id = "PA-002"
    name = "Enterprise Admins"
    description = "Check Enterprise Admins membership"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        ea_members = []
        for group in self.context.groups:
            if group.sid and get_rid(group.sid) == RID_ENTERPRISE_ADMINS:
                ea_members = [u for u in self.context.users if u.dn in group.member_dns]
                break

        if len(ea_members) > 1:
            return [self.finding(
                title=f"Enterprise Admins has {len(ea_members)} members (should be 0-1)",
                description="Enterprise Admins have forest-wide administrative rights. This group should be empty or contain only the forest root administrator.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in ea_members],
                affected_count=len(ea_members),
                remediation_desc="Remove all members from Enterprise Admins. Add members only when needed for forest-level changes.",
                powershell="Get-ADGroupMember 'Enterprise Admins' | Remove-ADGroupMember 'Enterprise Admins' -Confirm:$false",
                cis_controls=["5.4"],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class PA003_SchemaAdmins(BaseCheck):
    id = "PA-003"
    name = "Schema Admins"
    description = "Check Schema Admins membership"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        sa_members = []
        for group in self.context.groups:
            if group.sid and get_rid(group.sid) == RID_SCHEMA_ADMINS:
                sa_members = [u for u in self.context.users if u.dn in group.member_dns]
                break

        if sa_members:
            return [self.finding(
                title=f"Schema Admins has {len(sa_members)} members (should be 0)",
                description="Schema Admins can modify the AD schema. This group should be empty unless a schema change is in progress.",
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in sa_members],
                affected_count=len(sa_members),
                remediation_desc="Remove all members from Schema Admins. Add members only for schema modifications.",
                powershell="Get-ADGroupMember 'Schema Admins' | Remove-ADGroupMember 'Schema Admins' -Confirm:$false",
                cis_controls=["5.4"],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class PA004_DangerousGroups(BaseCheck):
    id = "PA-004"
    name = "Dangerous Builtin Groups"
    description = "Check membership in dangerous builtin groups"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        findings = []
        for group in self.context.groups:
            name_lower = group.sam_account_name.lower()
            if name_lower in DANGEROUS_BUILTIN_GROUPS and group.member_dns:
                risk_desc = DANGEROUS_BUILTIN_GROUPS[name_lower]
                member_users = [u for u in self.context.users if u.dn in group.member_dns]
                findings.append(self.finding(
                    title=f"'{group.sam_account_name}' has {len(group.member_dns)} members",
                    description=f"The {group.sam_account_name} group has members. Risk: {risk_desc}",
                    severity=Severity.MEDIUM,
                    affected_objects=[self.affected_user(u) for u in member_users[:20]],
                    affected_count=len(group.member_dns),
                    remediation_desc=f"Review and minimize membership in {group.sam_account_name}.",
                    powershell=f"Get-ADGroupMember '{group.sam_account_name}' | Select-Object SamAccountName",
                    mitre=[MitreAttack(technique_id=MITRE_ACCOUNT_MANIPULATION, technique_name="Account Manipulation", tactic="Persistence")],
                    cis_controls=["5.4"],
                    nist_800_53=["AC-6"],
                ))
        return findings


@check
class PA005_StaleAdmins(BaseCheck):
    id = "PA-005"
    name = "Stale Privileged Accounts"
    description = "Check for privileged accounts that haven't logged in recently"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        stale_admins = [
            u for u in self.context.users
            if u.enabled and u.admin_count == 1 and u.is_stale
        ]

        if stale_admins:
            return [self.finding(
                title=f"{len(stale_admins)} privileged accounts are stale (90+ days inactive)",
                description="These admin accounts haven't logged in for over 90 days. Stale privileged accounts are prime targets for attackers.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in stale_admins[:50]],
                affected_count=len(stale_admins),
                remediation_desc="Disable stale privileged accounts and remove from admin groups.",
                powershell="Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | Where-Object {$_.adminCount -eq 1} | Disable-ADAccount",
                cis_controls=["5.3"],
                nist_800_53=["AC-2"],
            )]
        return []


@check
class PA006_KerberoastableAdmins(BaseCheck):
    id = "PA-006"
    name = "Kerberoastable Privileged Accounts"
    description = "Check for privileged accounts with SPNs (Kerberoastable)"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        kerberoastable_admins = [
            u for u in self.context.users
            if u.is_kerberoastable and self.context.is_privileged_user(u)
        ]

        if kerberoastable_admins:
            return [self.finding(
                title=f"{len(kerberoastable_admins)} privileged accounts are Kerberoastable",
                description=(
                    "These privileged accounts have SPNs set, making them vulnerable to Kerberoasting. "
                    "An attacker can request their TGS tickets and crack them offline to obtain the plaintext password."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(u) for u in kerberoastable_admins],
                affected_count=len(kerberoastable_admins),
                remediation_desc="Remove unnecessary SPNs from privileged accounts or convert to gMSA.",
                powershell="Get-ADUser -Filter {adminCount -eq 1 -and ServicePrincipalName -like '*'} -Properties ServicePrincipalName | Select-Object SamAccountName, ServicePrincipalName",
                mitre=[MitreAttack(technique_id=MITRE_KERBEROASTING, technique_name="Kerberoasting", tactic="Credential Access")],
                cis_controls=["5.4"],
                nist_800_53=["AC-6", "IA-5"],
            )]
        return []


@check
class PA007_OrphanedAdminCount(BaseCheck):
    id = "PA-007"
    name = "Orphaned adminCount"
    description = "Check for accounts with adminCount=1 that are not in any privileged group"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        orphaned = [
            u for u in self.context.users
            if u.admin_count == 1 and not self.context.is_privileged_user(u)
        ]

        if orphaned:
            return [self.finding(
                title=f"{len(orphaned)} accounts have orphaned adminCount attribute",
                description=(
                    "These accounts have adminCount=1 but are not members of any privileged group. "
                    "This usually means they were once privileged but their adminCount was never cleared. "
                    "AdminSDHolder protection prevents inheritance of ACL changes."
                ),
                severity=Severity.LOW,
                affected_objects=[self.affected_user(u) for u in orphaned[:50]],
                affected_count=len(orphaned),
                remediation_desc="Clear adminCount and re-enable ACL inheritance on these accounts.",
                powershell="Get-ADUser -Filter {adminCount -eq 1} | Where-Object {(Get-ADPrincipalGroupMembership $_.SamAccountName | Where-Object {$_.SID -like '*-512' -or $_.SID -like '*-519'}).Count -eq 0} | Set-ADUser -Clear adminCount",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class PA008_AdminsNotProtectedUsers(BaseCheck):
    id = "PA-008"
    name = "Admins Not in Protected Users"
    description = "Check if privileged accounts are in the Protected Users group"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        unprotected_admins = [
            u for u in self.context.users
            if u.enabled and self.context.is_privileged_user(u) and not u.is_protected_user
        ]

        if unprotected_admins:
            return [self.finding(
                title=f"{len(unprotected_admins)} privileged accounts are not in the Protected Users group",
                description=(
                    "Protected Users group disables NTLM, WDigest, CredSSP, and Kerberos delegation "
                    "for its members, significantly reducing credential theft risk."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in unprotected_admins[:50]],
                affected_count=len(unprotected_admins),
                remediation_desc="Add privileged accounts to the Protected Users group.",
                powershell="Get-ADGroupMember 'Domain Admins' | Add-ADGroupMember -Identity 'Protected Users' -Members $_",
                cis_controls=["5.4"],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class PA009_SensitiveNotDelegated(BaseCheck):
    id = "PA-009"
    name = "Privileged Accounts Delegation"
    description = "Check if privileged accounts have 'Account is sensitive and cannot be delegated'"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        delegatable_admins = [
            u for u in self.context.users
            if u.enabled and self.context.is_privileged_user(u)
            and not u.sensitive_and_not_delegated and not u.is_protected_user
        ]

        if delegatable_admins:
            return [self.finding(
                title=f"{len(delegatable_admins)} privileged accounts can be delegated",
                description=(
                    "These privileged accounts lack the 'Account is sensitive and cannot be delegated' flag "
                    "and are not in Protected Users. Their credentials can be forwarded via Kerberos delegation."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in delegatable_admins[:50]],
                affected_count=len(delegatable_admins),
                remediation_desc="Set 'Account is sensitive and cannot be delegated' on privileged accounts.",
                powershell="Get-ADUser -Filter {adminCount -eq 1} | Set-ADAccountControl -AccountNotDelegated $true",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class PA010_AdminsWithDESEncryption(BaseCheck):
    id = "PA-010"
    name = "Admins with DES Encryption"
    description = "Check for privileged accounts using DES-only Kerberos encryption"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        des_admins = [
            u for u in self.context.users
            if u.enabled and self.context.is_privileged_user(u) and u.use_des_key_only
        ]

        if des_admins:
            return [self.finding(
                title=f"{len(des_admins)} privileged accounts use DES-only Kerberos encryption",
                description="DES encryption is cryptographically weak and can be cracked quickly.",
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(u) for u in des_admins],
                affected_count=len(des_admins),
                remediation_desc="Remove USE_DES_KEY_ONLY flag from privileged accounts.",
                powershell="Get-ADUser -Filter {UseDESKeyOnly -eq $true -and adminCount -eq 1} | Set-ADAccountControl -UseDESKeyOnly $false",
                nist_800_53=["SC-13"],
            )]
        return []


@check
class PA011_MachineAccountQuota(BaseCheck):
    id = "PA-011"
    name = "Machine Account Quota"
    description = "Check if default machine account quota allows workstation joins"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        maq = self.context.domain_info.machine_account_quota
        if maq > 0:
            return [self.finding(
                title=f"Machine account quota is {maq} (any user can join {maq} machines)",
                description=(
                    f"Any authenticated user can join up to {maq} computer accounts to the domain. "
                    "Attackers can abuse this to create machine accounts for RBCD attacks."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Set ms-DS-MachineAccountQuota to 0.",
                powershell=f"Set-ADDomain -Identity {self.context.domain_info.dns_name} -Replace @{{'ms-DS-MachineAccountQuota'=0}}",
                mitre=[MitreAttack(technique_id=MITRE_ACCOUNT_MANIPULATION, technique_name="Account Manipulation", tactic="Persistence")],
                cis_controls=["5.4"],
                nist_800_53=["CM-6"],
                details={"current_quota": maq},
            )]
        return []


@check
class PA012_KrbtgtPasswordAge(BaseCheck):
    id = "PA-012"
    name = "KRBTGT Password Age"
    description = "Check if the KRBTGT account password has been rotated recently"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        krbtgt = None
        for user in self.context.users:
            if get_rid(user.sid) == RID_KRBTGT:
                krbtgt = user
                break

        if krbtgt:
            age = days_since(krbtgt.password_last_set)
            if age > 180:
                return [self.finding(
                    title=f"KRBTGT password is {age} days old (recommended: rotate every 180 days)",
                    description=(
                        f"The KRBTGT account password hasn't been changed in {age} days. "
                        "The KRBTGT key is used to sign all Kerberos tickets. An attacker who compromises this key "
                        "can forge Golden Tickets for persistent domain access."
                    ),
                    severity=Severity.HIGH if age > 365 else Severity.MEDIUM,
                    affected_objects=[self.affected_user(krbtgt)],
                    remediation_desc="Rotate the KRBTGT password twice (with 12+ hour gap between rotations).",
                    powershell="Reset-KrbtgtKeyInteractive  # Use Microsoft's KRBTGT key rotation script",
                    mitre=[MitreAttack(technique_id="T1558.001", technique_name="Golden Ticket", tactic="Credential Access")],
                    cis_controls=["5.2"],
                    nist_800_53=["IA-5"],
                    details={"password_age_days": age},
                )]
        return []


@check
class PA013_RecycleBinDisabled(BaseCheck):
    id = "PA-013"
    name = "AD Recycle Bin"
    description = "Check if AD Recycle Bin is enabled"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        if not self.context.domain_info.ad_recycle_bin_enabled:
            return [self.finding(
                title="AD Recycle Bin is not enabled",
                description="Without the AD Recycle Bin, deleted objects cannot be easily recovered. Accidental or malicious deletions require authoritative restores.",
                severity=Severity.MEDIUM,
                remediation_desc="Enable the AD Recycle Bin feature.",
                powershell=f"Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target {self.context.domain_info.dns_name}",
                nist_800_53=["CP-9"],
            )]
        return []


@check
class PA014_DomainFunctionalLevel(BaseCheck):
    id = "PA-014"
    name = "Domain Functional Level"
    description = "Check if domain functional level is current"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        fl = self.context.domain_info.domain_functional_level
        fl_name = self.context.domain_info.domain_functional_level_name
        if fl < 7:  # Below Server 2016
            return [self.finding(
                title=f"Domain functional level is {fl_name} (below Server 2016)",
                description=(
                    f"The domain functional level is {fl_name}. Newer levels enable "
                    "security features like Privileged Access Management, Credential Guard integration, "
                    "and improved Kerberos armoring."
                ),
                severity=Severity.MEDIUM if fl < 5 else Severity.LOW,
                remediation_desc="Raise domain functional level after ensuring all DCs support it.",
                powershell="Set-ADDomainMode -Identity (Get-ADDomain) -DomainMode Windows2016Domain",
                nist_800_53=["CM-6"],
                details={"current_level": fl, "current_name": fl_name},
            )]
        return []


@check
class PA015_StaleDCs(BaseCheck):
    id = "PA-015"
    name = "Stale Domain Controllers"
    description = "Check for domain controllers with outdated OS versions"
    category = "Privileged Accounts"

    def run(self) -> List[Finding]:
        outdated_os = ["Windows Server 2008", "Windows Server 2003", "Windows Server 2012"]
        stale_dcs = []
        for dc in self.context.domain_info.domain_controllers:
            if any(old in dc.os_version for old in outdated_os if dc.os_version):
                stale_dcs.append(dc)

        if stale_dcs:
            return [self.finding(
                title=f"{len(stale_dcs)} domain controllers run outdated OS versions",
                description="These DCs run end-of-life operating systems that no longer receive security updates.",
                severity=Severity.CRITICAL,
                affected_objects=[
                    AffectedObject(dn=dc.dn, sam_account_name=dc.hostname, object_type="computer",
                                   details={"os": dc.os_version})
                    for dc in stale_dcs
                ],
                affected_count=len(stale_dcs),
                remediation_desc="Migrate domain controllers to a supported Windows Server version.",
                nist_800_53=["SI-2", "CM-6"],
            )]
        return []
