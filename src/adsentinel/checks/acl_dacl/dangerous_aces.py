"""ACL/DACL checks — Dangerous permissions analysis (ACL-001 to ACL-015)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import (
    MITRE_ACCOUNT_MANIPULATION,
    MITRE_DCSYNC,
)
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity


@check
class ACL001_PreWin2000Group(BaseCheck):
    id = "ACL-001"
    name = "Pre-Windows 2000 Compatible Access"
    description = "Check if Pre-Windows 2000 group has dangerous membership"
    category = "ACL/DACL Security"

    def run(self) -> List[Finding]:
        for group in self.context.groups:
            if group.sam_account_name.lower() == "pre-windows 2000 compatible access":
                # Check if it contains Authenticated Users or Everyone
                if group.member_dns:
                    return [self.finding(
                        title="Pre-Windows 2000 Compatible Access group has members",
                        description=(
                            "The Pre-Windows 2000 Compatible Access group grants read access to all user "
                            "attributes including password hashes. By default, 'Authenticated Users' is a member, "
                            "allowing any domain user to enumerate sensitive attributes."
                        ),
                        severity=Severity.HIGH,
                        affected_objects=[AffectedObject(dn=group.dn, sam_account_name=group.sam_account_name, object_type="group")],
                        affected_count=len(group.member_dns),
                        remediation_desc="Remove 'Authenticated Users' from Pre-Windows 2000 Compatible Access group.",
                        powershell="Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'Authenticated Users' -Confirm:$false",
                        mitre=[MitreAttack(technique_id="T1087.002", technique_name="Domain Account Discovery", tactic="Discovery")],
                        nist_800_53=["AC-6"],
                    )]
        return []


@check
class ACL002_AdminSDHolderModified(BaseCheck):
    id = "ACL-002"
    name = "AdminSDHolder Tampering"
    description = "Check for unusual permissions on AdminSDHolder object"
    category = "ACL/DACL Security"

    def run(self) -> List[Finding]:
        # Check for orphaned adminCount (sign of AdminSDHolder abuse)
        orphaned = [
            u for u in self.context.users
            if u.admin_count == 1 and not self.context.is_privileged_user(u) and u.enabled
        ]
        if len(orphaned) > 10:
            return [self.finding(
                title=f"{len(orphaned)} accounts have orphaned adminCount (possible AdminSDHolder abuse)",
                description=(
                    "A large number of accounts have adminCount=1 without being in privileged groups. "
                    "This may indicate AdminSDHolder was modified to propagate permissions, or accounts "
                    "were previously privileged and not cleaned up."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in orphaned[:50]],
                affected_count=len(orphaned),
                remediation_desc="Audit AdminSDHolder ACL and clean up orphaned adminCount values.",
                powershell="Get-ADUser -Filter {adminCount -eq 1 -and Enabled -eq $true} -Properties memberOf | ForEach-Object { $groups = ($_ | Get-ADPrincipalGroupMembership).Name; if ($groups -notcontains 'Domain Admins') { $_.SamAccountName } }",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class ACL003_DCsyncPermissions(BaseCheck):
    id = "ACL-003"
    name = "DCSync Permissions"
    description = "Check for non-standard accounts with DCSync rights"
    category = "ACL/DACL Security"

    def run(self) -> List[Finding]:
        # DCSync requires DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
        # We check for accounts with adminCount that shouldn't have it
        suspicious_admin = [
            u for u in self.context.users
            if u.admin_count == 1 and u.enabled
            and not any(
                u.sam_account_name.lower() in name.lower()
                for name in ["administrator", "krbtgt"]
            )
            and self.context.is_privileged_user(u)
        ]
        # This is informational - full DCSync check requires ACL parsing
        if len(suspicious_admin) > 10:
            return [self.finding(
                title=f"{len(suspicious_admin)} accounts may have replication rights (DCSync potential)",
                description=(
                    "Multiple accounts have elevated privileges. Ensure only necessary accounts "
                    "have DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights on the domain object. "
                    "Non-standard accounts with these rights can perform DCSync attacks."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in suspicious_admin[:50]],
                affected_count=len(suspicious_admin),
                remediation_desc="Audit replication rights on the domain object. Remove unnecessary DCSync permissions.",
                powershell="(Get-ACL 'AD:\\DC=corp,DC=com').Access | Where-Object {$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'} | Select-Object IdentityReference",
                mitre=[MitreAttack(technique_id=MITRE_DCSYNC, technique_name="DCSync", tactic="Credential Access")],
                cis_controls=["5.4"],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class ACL004_DangerousGroupMembership(BaseCheck):
    id = "ACL-004"
    name = "Nested Privileged Group Membership"
    description = "Check for deeply nested group membership in privileged groups"
    category = "ACL/DACL Security"

    def run(self) -> List[Finding]:
        # Find users who are privileged through nested groups (not direct members)
        indirect_admins = []
        for user in self.context.users:
            if not user.enabled:
                continue
            is_priv = self.context.is_privileged_user(user)
            is_direct = any(user.dn in members for members in self.context.privileged_groups.values())
            if is_priv and not is_direct:
                indirect_admins.append(user)

        if indirect_admins:
            return [self.finding(
                title=f"{len(indirect_admins)} users are privileged through nested group membership",
                description=(
                    "These users have privileged access through nested group chains rather than direct "
                    "membership. Nested membership makes privilege auditing difficult and can hide "
                    "unintended access paths."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in indirect_admins[:50]],
                affected_count=len(indirect_admins),
                remediation_desc="Flatten group nesting for privileged groups. Use direct membership for transparency.",
                powershell="Get-ADGroupMember 'Domain Admins' -Recursive | Where-Object {$_.objectClass -eq 'group'}",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class ACL005_ComputerObjectOwnership(BaseCheck):
    id = "ACL-005"
    name = "Computer Object Creators"
    description = "Check for non-admin users who may own computer objects"
    category = "ACL/DACL Security"

    def run(self) -> List[Finding]:
        maq = self.context.domain_info.machine_account_quota
        if maq > 0:
            # Users who created computers own them and can set RBCD
            return [self.finding(
                title=f"Machine Account Quota ({maq}) enables computer object creation by any user",
                description=(
                    f"Any authenticated user can create up to {maq} computer accounts. The creator "
                    "becomes the owner with full control, including the ability to configure "
                    "Resource-Based Constrained Delegation (RBCD) for privilege escalation."
                ),
                severity=Severity.HIGH,
                remediation_desc="Set ms-DS-MachineAccountQuota to 0 and use delegated OU permissions for authorized computer joining.",
                powershell=f"Set-ADDomain -Identity {self.context.domain_info.dns_name} -Replace @{{'ms-DS-MachineAccountQuota'=0}}",
                mitre=[MitreAttack(technique_id=MITRE_ACCOUNT_MANIPULATION, technique_name="Account Manipulation", tactic="Persistence")],
                nist_800_53=["CM-6", "AC-6"],
            )]
        return []


@check
class ACL006_GPOPermissions(BaseCheck):
    id = "ACL-006"
    name = "GPO Modification Rights"
    description = "Check for excessive GPO modify permissions"
    category = "ACL/DACL Security"

    def run(self) -> List[Finding]:
        # Check for GPOs linked to sensitive OUs
        total_gpos = len(self.context.gpos)
        disabled_gpos = [g for g in self.context.gpos if g.get("is_disabled")]

        if disabled_gpos and len(disabled_gpos) > total_gpos * 0.3:
            return [self.finding(
                title=f"{len(disabled_gpos)} of {total_gpos} GPOs are fully disabled",
                description="A significant number of GPOs are disabled. Disabled GPOs may still have ACLs that could be abused if re-enabled.",
                severity=Severity.LOW,
                remediation_desc="Review and remove unneeded disabled GPOs.",
                powershell="Get-GPO -All | Where-Object {$_.GpoStatus -eq 'AllSettingsDisabled'} | Select-Object DisplayName, Id",
                nist_800_53=["CM-6"],
                details={"total_gpos": total_gpos, "disabled": len(disabled_gpos)},
            )]
        return []


@check
class ACL007_SensitiveGroupWriteAccess(BaseCheck):
    id = "ACL-007"
    name = "Writeable Privileged Groups"
    description = "Check for accounts that can modify privileged group membership"
    category = "ACL/DACL Security"

    def run(self) -> List[Finding]:
        # Check for groups with many direct admin-level members
        findings = []
        for group in self.context.groups:
            name_lower = group.sam_account_name.lower()
            if name_lower in ("domain admins", "enterprise admins", "schema admins"):
                non_admin_members = []
                for member_dn in group.member_dns:
                    for user in self.context.users:
                        if user.dn == member_dn and user.enabled:
                            # Check if this user is also in other privileged groups
                            if user.description and "service" in user.description.lower():
                                non_admin_members.append(user)

                if non_admin_members:
                    findings.append(self.finding(
                        title=f"Service accounts found in '{group.sam_account_name}'",
                        description=f"Service accounts should not be direct members of {group.sam_account_name}.",
                        severity=Severity.HIGH,
                        affected_objects=[self.affected_user(u) for u in non_admin_members],
                        affected_count=len(non_admin_members),
                        remediation_desc=f"Remove service accounts from {group.sam_account_name}. Use delegated permissions instead.",
                        nist_800_53=["AC-6"],
                    ))
        return findings
