"""ACL/DACL checks — Dangerous permissions analysis (ACL-001 to ACL-015)."""

from __future__ import annotations

from typing import Any, Dict, List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.collectors.acl_collector import (
    ADS_RIGHT_DS_WRITE_PROP,
    GUID_GET_CHANGES,
    GUID_GET_CHANGES_ALL,
    GENERIC_ALL,
    WRITE_DACL,
    WRITE_OWNER,
    GENERIC_WRITE,
    build_safe_sids,
)
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
                # The group being enabled is the finding — not whether it has visible members.
                # "Authenticated Users" is a special identity that appears as a default member
                # but may not be returned in member_dns by LDAP. Any non-empty or even empty
                # group that was not explicitly hardened still grants pre-W2K read rights.
                member_count = len(group.member_dns)
                if member_count > 0:
                    detail = f"{member_count} explicit member{'s' if member_count != 1 else ''} enumerated"
                    severity = Severity.HIGH
                else:
                    # Group exists and is enabled — Authenticated Users is the Windows default
                    # and may not surface in member enumeration.
                    detail = "no explicit members enumerated, but 'Authenticated Users' is the Windows default"
                    severity = Severity.HIGH

                return [self.finding(
                    title="Pre-Windows 2000 Compatible Access group is enabled",
                    description=(
                        "The Pre-Windows 2000 Compatible Access group is present and active. "
                        "This group grants read access to all user and group attributes — "
                        "including sensitive fields — to any authenticated user (the default "
                        "membership). This was a compatibility feature for Windows NT 4.0 domains "
                        "and should be empty and unused in any modern environment. "
                        f"Current state: {detail}."
                    ),
                    severity=severity,
                    affected_objects=[AffectedObject(dn=group.dn, sam_account_name=group.sam_account_name, object_type="group")],
                    affected_count=member_count,
                    remediation_desc=(
                        "Remove all members from Pre-Windows 2000 Compatible Access group. "
                        "Verify no legacy applications depend on it, then ensure 'Authenticated Users' "
                        "and 'Everyone' are not members."
                    ),
                    powershell=(
                        "# View current members:\n"
                        "Get-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access'\n\n"
                        "# Remove Authenticated Users:\n"
                        "Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' "
                        "-Members 'Authenticated Users' -Confirm:$false"
                    ),
                    mitre=[MitreAttack(technique_id="T1087.002", technique_name="Domain Account Discovery", tactic="Discovery")],
                    nist_800_53=["AC-6"],
                    details={"explicit_member_count": member_count},
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
class ACL003_AdminCountAnomaly(BaseCheck):
    id = "ACL-003"
    name = "SDProp adminCount Anomaly"
    description = "Detect non-privileged accounts with adminCount=1 left over from past group membership"
    category = "ACL/DACL Security"

    _SAFE_ACCOUNTS = frozenset(["administrator", "krbtgt"])

    def run(self) -> List[Finding]:
        # adminCount=1 means SDProp has stamped this account at some point — it currently
        # or previously belonged to a protected group (DA, EA, Administrators, etc.).
        # When an account later leaves the protected group, adminCount is NOT auto-cleared.
        # These accounts retain hardened ACLs (inheritance blocked), masking any rights
        # they still hold and making them harder to audit. Any non-zero count warrants review.
        # NOTE: Actual DCSync GUID detection is in ACL-010 (binary DACL parsing).
        unexpected = [
            u for u in self.context.users
            if u.admin_count == 1
            and u.enabled
            and u.sam_account_name.lower() not in self._SAFE_ACCOUNTS
            and not self.context.is_privileged_user(u)
        ]

        if not unexpected:
            return []

        count = len(unexpected)
        severity = Severity.HIGH if count > 5 else Severity.MEDIUM

        return [self.finding(
            title=f"{count} non-privileged account{'s' if count != 1 else ''} with adminCount=1 (SDProp anomaly)",
            description=(
                f"{count} enabled account{'s' if count != 1 else ''} "
                f"{'have' if count != 1 else 'has'} adminCount=1 but "
                f"{'are' if count != 1 else 'is'} not a member of any current protected group. "
                "SDProp sets adminCount=1 when an account joins a protected group and never clears "
                "it automatically on removal. These accounts have inheritance-blocked ACLs that "
                "hide any additional rights they may hold, creating a persistent audit blind-spot. "
                "Stale adminCount accounts are also a common persistence technique — an attacker "
                "who temporarily added an account to Domain Admins leaves this marker behind."
            ),
            severity=severity,
            affected_objects=[self.affected_user(u) for u in unexpected[:50]],
            affected_count=count,
            remediation_desc=(
                "Review each account. If no longer requiring protected-group membership: "
                "clear adminCount=0, re-enable ACL inheritance, and confirm no unexpected rights remain."
            ),
            powershell=(
                "# Find accounts with adminCount=1 not in any protected group:\n"
                "Get-ADUser -Filter {adminCount -eq 1 -and Enabled -eq $true} "
                "-Properties adminCount,MemberOf | "
                "Where-Object {$_.MemberOf -notmatch 'Domain Admins|Administrators|Schema Admins|Enterprise Admins'}\n\n"
                "# Clear stale adminCount on a specific account:\n"
                "Set-ADUser <samAccountName> -Clear adminCount"
            ),
            mitre=[MitreAttack(technique_id=MITRE_DCSYNC, technique_name="DCSync", tactic="Credential Access")],
            cis_controls=["5.4"],
            nist_800_53=["AC-6", "AU-2"],
        )]


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
    description = (
        "Parse the real DACL on every GPO object to find non-privileged principals "
        "with write access — GenericWrite, WriteProperty, WriteDACL, or WriteOwner. "
        "Any such principal can modify GPO settings to execute code on all computers "
        "or users in the GPO's scope."
    )
    category = "ACL/DACL Security"

    # Rights that allow modifying a GPO's content or access control
    _DANGEROUS_MASK = WRITE_DACL | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE | ADS_RIGHT_DS_WRITE_PROP

    _MASK_LABELS: Dict[int, str] = {
        WRITE_DACL:              "WriteDACL",
        WRITE_OWNER:             "WriteOwner",
        GENERIC_ALL:             "GenericAll",
        GENERIC_WRITE:           "GenericWrite",
        ADS_RIGHT_DS_WRITE_PROP: "WriteProperty",
    }

    def run(self) -> List[Finding]:
        gpo_keys = [k for k in self.context.acls if k.startswith("gpo:")]

        if not gpo_keys:
            return []

        gpo_names: Dict[str, str] = {
            g["dn"]: g.get("display_name", g["dn"])
            for g in self.context.gpos
            if g.get("dn")
        }

        domain_sid = self.context.domain_info.domain_sid or ""
        safe_sids = build_safe_sids(domain_sid)

        vulnerable: List[Dict[str, Any]] = []
        for key in gpo_keys:
            acl_data = self.context.acls[key]
            dn = acl_data.get("dn", key[4:])
            aces: List[Dict[str, Any]] = acl_data.get("aces", [])
            display_name = gpo_names.get(dn, dn)

            bad_aces = []
            for ace in aces:
                if not ace.get("allowed"):
                    continue
                sid = ace.get("sid", "")
                if not sid or sid in safe_sids:
                    continue
                mask = ace.get("mask", 0)
                dangerous_bits = mask & self._DANGEROUS_MASK
                if not dangerous_bits:
                    continue
                rights = [label for bit, label in self._MASK_LABELS.items() if dangerous_bits & bit]
                bad_aces.append({"sid": sid, "rights": rights, "mask": hex(mask)})

            if bad_aces:
                vulnerable.append({
                    "dn": dn,
                    "display_name": display_name,
                    "bad_aces": bad_aces,
                })

        if not vulnerable:
            return []

        gpo_lines = []
        for v in vulnerable[:20]:
            ace_summary = "; ".join(
                f"{a['sid']} [{', '.join(a['rights'])}]"
                for a in v["bad_aces"][:3]
            )
            gpo_lines.append(f"  • {v['display_name']}: {ace_summary}")

        total_aces = sum(len(v["bad_aces"]) for v in vulnerable)

        return [self.finding(
            title=f"{len(vulnerable)} GPO(s) have non-privileged write access ({total_aces} dangerous ACE(s))",
            description=(
                "Non-privileged principals have write rights on GPO objects in Active Directory. "
                "A principal with GenericWrite, WriteProperty, WriteDACL, or WriteOwner on a GPO "
                "can modify its settings to execute arbitrary code on every computer or user in "
                "the GPO's scope — including Domain Controllers if the GPO is linked to the "
                "Domain Controllers OU. This is one of the highest-impact escalation paths in AD: "
                "a single modified GPO can deploy a malicious startup script or registry run key "
                "to every machine in the domain simultaneously.\n\n"
                "Affected GPOs:\n" + "\n".join(gpo_lines) +
                ("\n  (and more...)" if len(vulnerable) > 20 else "")
            ),
            severity=Severity.HIGH,
            affected_objects=[
                AffectedObject(
                    dn=v["dn"],
                    sam_account_name=v["display_name"],
                    object_type="gpo",
                    details={"dangerous_aces": v["bad_aces"][:10]},
                )
                for v in vulnerable[:50]
            ],
            affected_count=len(vulnerable),
            remediation_desc=(
                "1. For each affected GPO, open Group Policy Management Console → right-click GPO → Edit → Delegation tab → Advanced. "
                "2. Remove any non-administrative principals with 'Edit settings', 'Edit settings, delete, modify security', or full control. "
                "3. Only Domain Admins, Group Policy Creator Owners (scoped to their own GPOs), SYSTEM, "
                "and ENTERPRISE DOMAIN CONTROLLERS should have write access to GPOs. "
                "4. Use Get-GPPermission to audit all GPO delegations in bulk (see PowerShell)."
            ),
            powershell=(
                "# Audit all GPOs for non-default write delegations:\n"
                "Import-Module GroupPolicy\n"
                "Get-GPO -All | ForEach-Object {\n"
                "    $gpo = $_\n"
                "    Get-GPPermission -Guid $gpo.Id -All | Where-Object {\n"
                "        $_.Permission -in @('GpoEdit', 'GpoEditDeleteModifySecurity', 'GpoCustom')\n"
                "    } | Select-Object @{N='GPO';E={$gpo.DisplayName}}, Trustee, Permission\n"
                "} | Format-Table -AutoSize\n\n"
                "# Remove a specific delegation:\n"
                "Set-GPPermission -Name '<GPO Name>' -TargetName '<account>' -TargetType User -PermissionLevel None"
            ),
            mitre=[MitreAttack(
                technique_id="T1484.001",
                technique_name="Group Policy Modification",
                tactic="Defense Evasion",
            )],
            cis_controls=["5.4"],
            nist_800_53=["CM-6", "AC-6"],
            details={
                "vulnerable_gpos": [
                    {"dn": v["dn"], "name": v["display_name"], "ace_count": len(v["bad_aces"])}
                    for v in vulnerable
                ],
                "total_dangerous_aces": total_aces,
            },
        )]


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


@check
class ACL008_ExchangeDangerousGroups(BaseCheck):
    id = "ACL-008"
    name = "Exchange Dangerous Group Membership"
    description = (
        "Detect members of Exchange groups that carry dangerous AD rights: "
        "Exchange Windows Permissions (WriteDACL → DCSync path), "
        "Organization Management (forest-wide control), "
        "and Exchange Trusted Subsystem (attribute write access)."
    )
    category = "ACL/DACL Security"

    # Maps lowercase group name → (severity, risk_title, risk_description)
    _EXCHANGE_GROUPS: Dict[str, Any] = {
        "exchange windows permissions": (
            Severity.CRITICAL,
            "Exchange Windows Permissions",
            (
                "Exchange grants this group WriteDACL on the domain naming context root during installation. "
                "Any member can modify the domain object's DACL to grant themselves DCSync rights "
                "(DS-Replication-Get-Changes-All), then extract every credential in the domain. "
                "This is the PrivExchange / ntlmrelayx --escalate-user escalation path, "
                "reliably exploitable since 2019 (CVE-2019-0686 / PrivExchange). "
                "Even after patching Exchange, the WriteDACL ACE often remains on the domain object."
            ),
        ),
        "organization management": (
            Severity.HIGH,
            "Organization Management",
            (
                "Organization Management is Exchange's top-tier administrative group. Members can reset "
                "passwords on all mail-enabled objects, modify Exchange configuration, and control "
                "delivery rules for the entire organization. Compromise of a member provides "
                "forest-wide email interception and attribute manipulation capabilities."
            ),
        ),
        "exchange trusted subsystem": (
            Severity.MEDIUM,
            "Exchange Trusted Subsystem",
            (
                "Exchange Trusted Subsystem members can write Exchange-related attributes on AD objects. "
                "While lower direct impact, this group is a common stepping stone — attackers who "
                "control an Exchange server (e.g., via a deserialization vulnerability) inherit these "
                "rights and can leverage them toward Organization Management or domain escalation."
            ),
        ),
    }

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for group in self.context.groups:
            key = group.sam_account_name.lower().strip()
            if key not in self._EXCHANGE_GROUPS:
                continue
            if not group.member_dns:
                continue

            severity, display_name, risk_desc = self._EXCHANGE_GROUPS[key]
            member_users = [u for u in self.context.users if u.dn in group.member_dns]
            member_count = len(group.member_dns)

            if key == "exchange windows permissions":
                title = (
                    f"'{display_name}' has {member_count} member(s) — "
                    "WriteDACL on domain NC enables DCSync escalation"
                )
                remediation = (
                    "1. Audit whether the WriteDACL ACE is still present on the domain NC: "
                    "(Get-ACL 'AD:\\DC=domain,DC=com').Access | Where-Object { "
                    "$_.ActiveDirectoryRights -match 'WriteDacl' } | Select-Object IdentityReference. "
                    "2. Remove any member that is not an Exchange service account. "
                    "3. Apply the August 2019 Exchange CU to revoke the over-permissive ACE. "
                    "4. If the ACE persists post-patch, remove it manually with Set-Acl."
                )
                ps = (
                    "# Check for WriteDACL on domain NC granted to Exchange Windows Permissions:\n"
                    "$domainDN = (Get-ADDomain).DistinguishedName\n"
                    "(Get-ACL \"AD:\\$domainDN\").Access | "
                    "Where-Object { $_.IdentityReference -like '*Exchange Windows Permissions*' } | "
                    "Select-Object IdentityReference, ActiveDirectoryRights\n\n"
                    "# List current members:\n"
                    "Get-ADGroupMember 'Exchange Windows Permissions' | "
                    "Select-Object SamAccountName, objectClass"
                )
                mitre = [
                    MitreAttack(technique_id=MITRE_DCSYNC, technique_name="DCSync", tactic="Credential Access"),
                    MitreAttack(technique_id="T1222.001", technique_name="Windows File and Directory Permissions Modification", tactic="Defense Evasion"),
                ]
            elif key == "organization management":
                title = (
                    f"'{display_name}' has {member_count} member(s) — "
                    "forest-wide Exchange administrative rights"
                )
                remediation = (
                    "Reduce membership to the minimum required Exchange administrators. "
                    "Use role-based Exchange Management Shell delegation where possible. "
                    "Ensure members are tier-0 admin accounts with hardened workstations."
                )
                ps = (
                    "Get-ADGroupMember 'Organization Management' -Recursive | "
                    "Select-Object SamAccountName, objectClass, distinguishedName"
                )
                mitre = [
                    MitreAttack(technique_id=MITRE_ACCOUNT_MANIPULATION, technique_name="Account Manipulation", tactic="Persistence"),
                ]
            else:  # exchange trusted subsystem
                title = (
                    f"'{display_name}' has {member_count} member(s) — "
                    "Exchange attribute write access on AD objects"
                )
                remediation = (
                    "This group should only contain the Exchange server computer accounts. "
                    "Remove any user accounts or additional computer accounts."
                )
                ps = (
                    "Get-ADGroupMember 'Exchange Trusted Subsystem' | "
                    "Select-Object SamAccountName, objectClass"
                )
                mitre = [
                    MitreAttack(technique_id=MITRE_ACCOUNT_MANIPULATION, technique_name="Account Manipulation", tactic="Persistence"),
                ]

            findings.append(self.finding(
                title=title,
                description=risk_desc,
                severity=severity,
                affected_objects=[self.affected_user(u) for u in member_users[:20]],
                affected_count=member_count,
                remediation_desc=remediation,
                powershell=ps,
                mitre=mitre,
                cis_controls=["5.4"],
                nist_800_53=["AC-6", "CM-7"],
                details={
                    "group_dn": group.dn,
                    "member_count": member_count,
                    "group": display_name,
                },
            ))

        return findings


@check
class ACL009_AdminSDHolderDACL(BaseCheck):
    id = "ACL-009"
    name = "AdminSDHolder DACL Backdoor"
    description = (
        "Parse the real DACL on CN=AdminSDHolder to find non-default principals with "
        "WriteDACL, WriteOwner, or GenericAll rights that would propagate to all 'protected' AD objects."
    )
    category = "ACL/DACL Security"

    # Rights that grant full control path on AdminSDHolder
    _DANGEROUS_MASK = WRITE_DACL | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE

    # Human-readable labels for the bits we care about
    _MASK_LABELS: Dict[int, str] = {
        WRITE_DACL:    "WriteDACL",
        WRITE_OWNER:   "WriteOwner",
        GENERIC_ALL:   "GenericAll",
        GENERIC_WRITE: "GenericWrite",
    }

    def run(self) -> List[Finding]:
        acl_data: Dict[str, Any] = self.context.acls.get("admin_sd_holder", {})
        aces: List[Dict[str, Any]] = acl_data.get("aces", [])
        parse_error: str = acl_data.get("parse_error", "")

        if parse_error == "fetch_failed":
            return [self.finding(
                title="AdminSDHolder DACL could not be retrieved (insufficient permissions)",
                description=(
                    "The nTSecurityDescriptor attribute on CN=AdminSDHolder,CN=System could not be read. "
                    "This typically means the scanning account lacks read access to the object's security "
                    "descriptor, or the object was inaccessible. The DACL should be audited manually."
                ),
                severity=Severity.MEDIUM,
                remediation_desc=(
                    "Ensure the scanning account has read access to AdminSDHolder, or audit the DACL manually: "
                    "(Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,DC=domain,DC=com').Access"
                ),
                nist_800_53=["AC-6"],
            )]

        if not aces:
            return []

        domain_sid = self.context.domain_info.domain_sid or ""
        safe_sids = build_safe_sids(domain_sid)

        suspicious: List[Dict[str, Any]] = []
        for ace in aces:
            if not ace.get("allowed"):
                continue  # DENY aces are not a backdoor
            sid = ace.get("sid", "")
            if sid in safe_sids:
                continue
            mask = ace.get("mask", 0)
            dangerous_bits = mask & self._DANGEROUS_MASK
            if not dangerous_bits:
                continue
            rights = [label for bit, label in self._MASK_LABELS.items() if dangerous_bits & bit]
            suspicious.append({"sid": sid, "mask": hex(mask), "rights": rights})

        if not suspicious:
            return []

        sid_list = "\n".join(
            f"  • {s['sid']} — {', '.join(s['rights'])} (mask {s['mask']})"
            for s in suspicious
        )
        return [self.finding(
            title=f"AdminSDHolder DACL backdoor: {len(suspicious)} unexpected principal(s) with dangerous rights",
            description=(
                "The SDProp process runs every 60 minutes and propagates the AdminSDHolder DACL to all "
                "protected objects (Domain Admins, Enterprise Admins, KRBTGT, Administrators, etc.). "
                "Any principal with WriteDACL, WriteOwner, or GenericAll on AdminSDHolder effectively "
                "controls ALL protected accounts in the domain — a persistence mechanism that survives "
                "even password resets and group membership changes.\n\n"
                f"Unexpected principals found on CN=AdminSDHolder:\n{sid_list}"
            ),
            severity=Severity.CRITICAL,
            remediation_desc=(
                "1. Immediately remove the unexpected ACE(s) from AdminSDHolder. "
                "2. Wait for SDProp to run (or force: Invoke-SDPropagator) to propagate the clean DACL. "
                "3. Investigate when and how the permission was added (audit logs, Event ID 5136). "
                "4. Treat the domain as potentially compromised until the origin is established."
            ),
            powershell=(
                "# View AdminSDHolder DACL:\n"
                "(Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,(Get-ADDomain).DistinguishedName').Access "
                "| Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType\n\n"
                "# Remove a specific ACE:\n"
                "$acl = Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,(Get-ADDomain).DistinguishedName'\n"
                "$ace = $acl.Access | Where-Object { $_.IdentityReference -eq '<IDENTITY>' }\n"
                "$acl.RemoveAccessRule($ace)\n"
                "Set-Acl -Path 'AD:\\CN=AdminSDHolder,CN=System,(Get-ADDomain).DistinguishedName' -AclObject $acl\n\n"
                "# Force SDProp immediately:\n"
                "$domain = Get-ADObject -SearchBase 'CN=System,(Get-ADDomain).DistinguishedName' "
                "-Filter {Name -eq 'AdminSDHolder'}\n"
                "Set-ADObject $domain -Replace @{adminCount=0}"
            ),
            manual_steps=[
                "Open ADSI Edit and navigate to CN=AdminSDHolder,CN=System,DC=...",
                "Right-click → Properties → Security → Advanced.",
                "Remove any entries that don't belong (anything other than Domain Admins, "
                "Enterprise Admins, SYSTEM, Administrators, Creator Owner, DCs).",
                "Force SDProp: run Invoke-SDPropagator from the Microsoft script gallery, "
                "or restart the KDC to trigger the next cycle.",
                "Review Event ID 5136 (Directory Service Changes) for when the ACE was added.",
            ],
            mitre=[MitreAttack(
                technique_id="T1222.001",
                technique_name="File and Directory Permissions Modification: Windows File and Directory Permissions Modification",
                tactic="Defense Evasion",
            ), MitreAttack(
                technique_id="T1098",
                technique_name="Account Manipulation",
                tactic="Persistence",
            )],
            cis_controls=["5.4", "6.1"],
            nist_800_53=["AC-6", "AU-12"],
            details={
                "admin_sd_holder_dn": acl_data.get("dn", ""),
                "suspicious_aces": suspicious,
                "total_aces_parsed": len(aces),
            },
        )]


@check
class ACL010_DCSync(BaseCheck):
    id = "ACL-010"
    name = "DCSync Rights on Domain NC"
    description = (
        "Parse the real DACL on the domain naming context root to find non-default principals "
        "holding DS-Replication-Get-Changes-All — the right required for a DCSync attack."
    )
    category = "ACL/DACL Security"

    def run(self) -> List[Finding]:
        acl_data: Dict[str, Any] = self.context.acls.get("domain_nc", {})
        aces: List[Dict[str, Any]] = acl_data.get("aces", [])
        parse_error: str = acl_data.get("parse_error", "")

        if parse_error == "fetch_failed":
            return [self.finding(
                title="Domain NC DACL could not be retrieved — DCSync rights unverified",
                description=(
                    "The nTSecurityDescriptor on the domain naming context root could not be read. "
                    "DCSync rights cannot be verified. Audit manually using the PowerShell command below."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Audit DCSync rights manually: see PowerShell command.",
                powershell=(
                    "$domainDN = (Get-ADDomain).DistinguishedName\n"
                    "(Get-ACL \"AD:\\$domainDN\").Access | "
                    "Where-Object { $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } | "
                    "Select-Object IdentityReference, ActiveDirectoryRights"
                ),
                nist_800_53=["AC-6"],
            )]

        if not aces:
            return []

        domain_sid = self.context.domain_info.domain_sid or ""
        safe_sids = build_safe_sids(domain_sid)

        # Track which SIDs hold each DCSync-relevant right
        # A SID needs BOTH Get-Changes + Get-Changes-All for a full DCSync
        # GenericAll on the domain object also confers all extended rights
        sids_get_changes:     set = set()
        sids_get_changes_all: set = set()
        sids_generic_all:     set = set()

        for ace in aces:
            if not ace.get("allowed"):
                continue
            sid = ace.get("sid", "")
            if not sid or sid in safe_sids:
                continue
            mask = ace.get("mask", 0)
            obj_type = ace.get("object_type")  # None for simple ACEs, GUID for object ACEs

            if mask & GENERIC_ALL:
                sids_generic_all.add(sid)
            if obj_type == GUID_GET_CHANGES:
                sids_get_changes.add(sid)
            if obj_type == GUID_GET_CHANGES_ALL:
                sids_get_changes_all.add(sid)

        # Full DCSync = Get-Changes-All (Get-Changes alone is not sufficient)
        # GenericAll implicitly includes all extended rights
        dcsync_sids = (sids_get_changes_all | sids_generic_all) - safe_sids

        if not dcsync_sids:
            return []

        findings = []
        for sid in sorted(dcsync_sids):
            has_both = sid in sids_get_changes and sid in sids_get_changes_all
            via_generic = sid in sids_generic_all

            if via_generic:
                rights_desc = "GenericAll (includes all extended rights — full DCSync capable)"
            elif has_both:
                rights_desc = "DS-Replication-Get-Changes + DS-Replication-Get-Changes-All"
            else:
                rights_desc = "DS-Replication-Get-Changes-All"

            findings.append(self.finding(
                title=f"Unexpected DCSync right: {sid}",
                description=(
                    f"The principal with SID {sid} holds DCSync-capable rights on the domain "
                    f"naming context ({acl_data.get('dn', 'domain NC')}).\n\n"
                    f"Rights: {rights_desc}\n\n"
                    "DCSync (Mimikatz lsadump::dcsync) uses these extended rights to impersonate a "
                    "domain controller and request password hashes for any account — including KRBTGT. "
                    "An attacker with these rights can obtain every domain credential without touching "
                    "a DC interactively, and create Golden Tickets for persistent domain-level access.\n\n"
                    "Legitimate holders: Domain Admins, Enterprise Admins, Domain Controllers, SYSTEM, "
                    "and BUILTIN\\Administrators. Any other principal is unexpected."
                ),
                severity=Severity.CRITICAL,
                remediation_desc=(
                    "1. Immediately investigate the SID to identify the account. "
                    "2. Remove the replication rights from the domain object ACL. "
                    "3. Reset the account's credentials and review its activity logs. "
                    "4. Search for evidence of DCSync usage: Event ID 4662 with "
                    "GUID 1131f6ad in the Security log on domain controllers."
                ),
                powershell=(
                    "# Find all non-default DCSync holders:\n"
                    "$domainDN = (Get-ADDomain).DistinguishedName\n"
                    "(Get-ACL \"AD:\\$domainDN\").Access | Where-Object {\n"
                    "    $_.ObjectType -in @(\n"
                    "        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',\n"  # Get-Changes
                    "        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'\n"   # Get-Changes-All
                    "    )\n"
                    "} | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType\n\n"
                    "# Remove the ACE (replace <IDENTITY> with the account):\n"
                    "$acl = Get-ACL \"AD:\\$domainDN\"\n"
                    "$ace = $acl.Access | Where-Object { $_.IdentityReference -eq '<IDENTITY>' }\n"
                    "$acl.RemoveAccessRule($ace)\n"
                    "Set-Acl -Path \"AD:\\$domainDN\" -AclObject $acl"
                ),
                manual_steps=[
                    "Resolve the SID to an account name: Get-ADObject -Filter {objectSid -eq '<SID>'}",
                    "Check when the ACE was added: Event ID 5136 (Directory Service Changes) in Security log.",
                    "Remove the DCSync right via ADSI Edit or the PowerShell command.",
                    "Reset the account password and enable fine-grained auditing for the domain NC object.",
                    "Search DC Security logs for Event ID 4662 with Properties containing "
                    "1131f6ad to detect if DCSync was already used.",
                ],
                mitre=[MitreAttack(
                    technique_id=MITRE_DCSYNC,
                    technique_name="DCSync",
                    tactic="Credential Access",
                )],
                cis_controls=["5.4"],
                nist_800_53=["AC-6", "AU-12"],
                details={
                    "sid": sid,
                    "rights": rights_desc,
                    "domain_nc_dn": acl_data.get("dn", ""),
                    "via_generic_all": via_generic,
                },
            ))

        return findings
