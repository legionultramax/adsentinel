"""Object Security checks (OBJ-001 to OBJ-010)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity
from adsentinel.utils.time_utils import days_since


@check
class OBJ001_EmptyGroups(BaseCheck):
    id = "OBJ-001"
    name = "Empty Security Groups"
    description = "Check for empty security groups"
    category = "Object Security"

    def run(self) -> List[Finding]:
        empty = [
            g for g in self.context.groups
            if g.is_security_group and not g.member_dns
            and g.sam_account_name.lower() not in (
                "domain users", "domain computers", "domain guests",
                "domain controllers", "cert publishers", "ras and ias servers",
            )
        ]
        if empty and len(empty) > 20:
            return [self.finding(
                title=f"{len(empty)} empty security groups found",
                description="Empty security groups add complexity without providing access control. They may be used as targets for group policy or ACL assignments.",
                severity=Severity.LOW,
                affected_objects=[self.affected_group(g) for g in empty[:50]],
                affected_count=len(empty),
                remediation_desc="Review and remove unused empty security groups.",
                powershell="Get-ADGroup -Filter {GroupCategory -eq 'Security'} -Properties Members | Where-Object {$_.Members.Count -eq 0}",
                nist_800_53=["AC-2"],
            )]
        return []


@check
class OBJ002_LargeGroups(BaseCheck):
    id = "OBJ-002"
    name = "Excessively Large Groups"
    description = "Check for groups with excessive direct membership"
    category = "Object Security"

    def run(self) -> List[Finding]:
        large = [g for g in self.context.groups if len(g.member_dns) > 500]
        if large:
            return [self.finding(
                title=f"{len(large)} groups have more than 500 direct members",
                description="Very large groups are difficult to audit and may grant overly broad access. Consider using nested groups for manageability.",
                severity=Severity.LOW,
                affected_objects=[
                    AffectedObject(dn=g.dn, sam_account_name=g.sam_account_name, object_type="group",
                                   details={"member_count": len(g.member_dns)})
                    for g in large[:20]
                ],
                affected_count=len(large),
                remediation_desc="Review large groups and consider splitting into role-based sub-groups.",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class OBJ003_DisabledComputersInGroups(BaseCheck):
    id = "OBJ-003"
    name = "Disabled Computers in Security Groups"
    description = "Check for disabled computer accounts still in security groups"
    category = "Object Security"

    def run(self) -> List[Finding]:
        disabled_comps = {c.dn for c in self.context.computers if not c.enabled}
        affected_groups = []
        for group in self.context.groups:
            if group.is_security_group:
                overlap = disabled_comps.intersection(set(group.member_dns))
                if overlap:
                    affected_groups.append((group, len(overlap)))

        if affected_groups:
            total = sum(count for _, count in affected_groups)
            return [self.finding(
                title=f"{total} disabled computers are still members of security groups",
                description="Disabled computer accounts remaining in security groups may grant unintended access if re-enabled.",
                severity=Severity.LOW,
                affected_objects=[
                    AffectedObject(dn=g.dn, sam_account_name=g.sam_account_name, object_type="group",
                                   details={"disabled_member_count": count})
                    for g, count in affected_groups[:20]
                ],
                affected_count=total,
                remediation_desc="Remove disabled computer accounts from security groups.",
                nist_800_53=["AC-2"],
            )]
        return []


@check
class OBJ004_UsersWithoutExpiry(BaseCheck):
    id = "OBJ-004"
    name = "Accounts Without Expiration"
    description = "Check for user accounts without an expiration date"
    category = "Object Security"

    def run(self) -> List[Finding]:
        no_expiry = [
            u for u in self.context.users
            if u.enabled and u.account_expires is None
            and u.sam_account_name not in ("krbtgt", "Guest", "Administrator")
        ]
        # Only flag if a significant percentage
        total_enabled = len([u for u in self.context.users if u.enabled])
        if no_expiry and total_enabled > 50 and len(no_expiry) > total_enabled * 0.9:
            return [self.finding(
                title=f"{len(no_expiry)} of {total_enabled} accounts have no expiration date",
                description="Accounts without expiration dates remain active indefinitely. Contractor and temporary accounts should have defined expiration.",
                severity=Severity.INFO,
                affected_count=len(no_expiry),
                remediation_desc="Set account expiration dates for contractor and temporary accounts.",
                powershell="Search-ADAccount -AccountExpiring -TimeSpan 0 -UsersOnly | Where-Object Enabled",
                nist_800_53=["AC-2"],
            )]
        return []


@check
class OBJ005_SIDHistoryPresent(BaseCheck):
    id = "OBJ-005"
    name = "SID History"
    description = "Check for accounts with SID history (migration remnants)"
    category = "Object Security"

    def run(self) -> List[Finding]:
        sid_history = [u for u in self.context.users if u.enabled and u.sid_history]
        if sid_history:
            return [self.finding(
                title=f"{len(sid_history)} accounts have SID history entries",
                description=(
                    "SID history is used during domain migrations but should be cleaned up afterward. "
                    "Attackers can inject SIDs into sIDHistory to escalate privileges across trust boundaries."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in sid_history[:50]],
                affected_count=len(sid_history),
                remediation_desc="Remove SID history entries after migration is complete.",
                powershell="Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory | Select-Object Name, SIDHistory",
                mitre=[MitreAttack(technique_id="T1134.005", technique_name="SID-History Injection", tactic="Privilege Escalation")],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class OBJ006_StaleDisabledAccounts(BaseCheck):
    id = "OBJ-006"
    name = "Long-Disabled Accounts"
    description = "Check for accounts disabled for more than 1 year"
    category = "Object Security"

    def run(self) -> List[Finding]:
        long_disabled = [
            u for u in self.context.users
            if not u.enabled and days_since(u.last_logon) > 365
            and u.sam_account_name not in ("krbtgt", "Guest")
        ]
        if long_disabled and len(long_disabled) > 50:
            return [self.finding(
                title=f"{len(long_disabled)} accounts have been disabled for over a year",
                description="Long-disabled accounts should be deleted to reduce directory bloat and eliminate re-enablement risk.",
                severity=Severity.LOW,
                affected_count=len(long_disabled),
                remediation_desc="Delete accounts that have been disabled for more than 1 year.",
                powershell="Search-ADAccount -AccountDisabled -UsersOnly | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-365)} | Remove-ADUser",
                nist_800_53=["AC-2"],
            )]
        return []


@check
class OBJ007_DuplicateSPNs(BaseCheck):
    id = "OBJ-007"
    name = "Duplicate SPNs"
    description = "Check for duplicate Service Principal Names"
    category = "Object Security"

    def run(self) -> List[Finding]:
        spn_map: dict[str, list] = {}
        for u in self.context.users:
            if u.enabled and u.spn_list:
                for spn in u.spn_list:
                    spn_lower = spn.lower()
                    if spn_lower not in spn_map:
                        spn_map[spn_lower] = []
                    spn_map[spn_lower].append(u.sam_account_name)

        duplicates = {spn: owners for spn, owners in spn_map.items() if len(owners) > 1}
        if duplicates:
            return [self.finding(
                title=f"{len(duplicates)} duplicate SPNs detected",
                description="Duplicate SPNs cause Kerberos authentication failures. Only one account should own each SPN.",
                severity=Severity.MEDIUM,
                remediation_desc="Resolve duplicate SPNs using setspn -X to identify conflicts.",
                powershell="setspn -X",
                nist_800_53=["IA-5"],
                details={"duplicate_spns": {k: v for k, v in list(duplicates.items())[:10]}},
            )]
        return []


@check
class OBJ008_ComputersInDefaultOU(BaseCheck):
    id = "OBJ-008"
    name = "Computers in Default Container"
    description = "Check for computer accounts in the default Computers container"
    category = "Object Security"

    def run(self) -> List[Finding]:
        default_cn = f"CN=Computers,{self.context.domain_info.base_dn}"
        in_default = [
            c for c in self.context.computers
            if c.dn.upper().endswith(default_cn.upper())
        ]
        if in_default and len(in_default) > 10:
            return [self.finding(
                title=f"{len(in_default)} computers are in the default Computers container",
                description="Computers in the default container don't receive OU-linked GPOs. They should be moved to appropriate OUs for policy enforcement.",
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_computer(c) for c in in_default[:50]],
                affected_count=len(in_default),
                remediation_desc="Move computer accounts to appropriate OUs with security GPOs applied.",
                powershell="Get-ADComputer -Filter * -SearchBase 'CN=Computers,DC=corp,DC=com' | Move-ADObject -TargetPath 'OU=Workstations,DC=corp,DC=com'",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class OBJ009_UsersInDefaultOU(BaseCheck):
    id = "OBJ-009"
    name = "Users in Default Container"
    description = "Check for user accounts in the default Users container"
    category = "Object Security"

    def run(self) -> List[Finding]:
        default_cn = f"CN=Users,{self.context.domain_info.base_dn}"
        builtin_names = {"administrator", "guest", "krbtgt", "defaultaccount"}
        in_default = [
            u for u in self.context.users
            if u.enabled
            and u.dn.upper().endswith(default_cn.upper())
            and u.sam_account_name.lower() not in builtin_names
        ]
        if in_default and len(in_default) > 5:
            return [self.finding(
                title=f"{len(in_default)} user accounts are in the default Users container",
                description="User accounts in the default container may not receive OU-specific GPOs for security hardening.",
                severity=Severity.LOW,
                affected_objects=[self.affected_user(u) for u in in_default[:50]],
                affected_count=len(in_default),
                remediation_desc="Move user accounts to appropriate OUs with security policies.",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class OBJ010_OrphanedForeignSecurityPrincipals(BaseCheck):
    id = "OBJ-010"
    name = "Orphaned Foreign Security Principals"
    description = "Check for unresolvable foreign security principals"
    category = "Object Security"

    def run(self) -> List[Finding]:
        # Foreign security principals from deleted trusts show up as unresolvable SIDs
        # We detect this by checking for groups with member DNs containing "ForeignSecurityPrincipals"
        fsp_members = 0
        for group in self.context.groups:
            for dn in group.member_dns:
                if "ForeignSecurityPrincipals" in dn:
                    fsp_members += 1

        if fsp_members > 20:
            return [self.finding(
                title=f"{fsp_members} foreign security principal memberships found",
                description="Foreign security principals from trusted domains are members of local groups. If the trust is removed, these become orphaned and may indicate stale access.",
                severity=Severity.LOW,
                affected_count=fsp_members,
                remediation_desc="Audit foreign security principals and remove those from deleted trusts.",
                powershell="Get-ADObject -SearchBase 'CN=ForeignSecurityPrincipals,DC=corp,DC=com' -Filter * | Select-Object Name, DistinguishedName",
                nist_800_53=["AC-2"],
            )]
        return []
