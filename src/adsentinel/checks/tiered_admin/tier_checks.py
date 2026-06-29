"""Tiered Administration checks (TIER-001 to TIER-009, excluding TIER-003)."""

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
class TIER004_DCSensitiveNotDelegated(BaseCheck):
    id = "TIER-004"
    name = "Privileged Accounts Not Marked Sensitive and Cannot Be Delegated"
    description = (
        "Flag privileged accounts that are not marked 'Account is sensitive and cannot be delegated'. "
        "Without this flag an attacker who compromises a service running with unconstrained delegation "
        "can forward the account's TGT to any backend service."
    )
    category = "Tiered Administration"

    def run(self) -> List[Finding]:
        not_sensitive = [
            u for u in self.context.users
            if u.enabled
            and self.context.is_privileged_user(u)
            and not u.sensitive_and_not_delegated
            and u.sam_account_name.lower() not in ("krbtgt",)
        ]
        if not not_sensitive:
            return []
        return [self.finding(
            title=(
                f"{len(not_sensitive)} privileged account{'s' if len(not_sensitive) != 1 else ''} "
                f"not marked 'sensitive and cannot be delegated'"
            ),
            description=(
                "Tier 0 accounts (Domain Admins, Enterprise Admins, etc.) should have "
                "'Account is sensitive and cannot be delegated' set. Without this flag, if "
                "an account authenticates to a host running an unconstrained delegation service "
                "(e.g., an IIS app pool or SQL Server), the receiving service can harvest and "
                "reuse the account's TGT to authenticate anywhere in the domain — a direct Tier 0 "
                "compromise path.\n\n"
                "This flag also prevents S4U2Proxy abuse: a constrained-delegation service cannot "
                "obtain a forwardable TGT on behalf of these accounts."
            ),
            severity=Severity.MEDIUM,
            affected_objects=[self.affected_user(u) for u in not_sensitive[:50]],
            affected_count=len(not_sensitive),
            remediation_desc=(
                "Enable 'Account is sensitive and cannot be delegated' on all Tier 0 accounts. "
                "Verify no services legitimately require delegation on these accounts — if they do, "
                "that is itself a tiering violation."
            ),
            powershell=(
                "# Flag all Domain Admin accounts as sensitive\n"
                "Get-ADGroupMember 'Domain Admins' | ForEach-Object {\n"
                "    Set-ADAccountControl -Identity $_.DistinguishedName "
                "-AccountNotDelegated $true\n"
                "}\n\n"
                "# Verify\n"
                "Get-ADUser -Filter {adminCount -eq 1} "
                "-Properties AccountNotDelegated | "
                "Where-Object { -not $_.AccountNotDelegated } | "
                "Select-Object SamAccountName"
            ),
            mitre=[
                MitreAttack(
                    technique_id="T1558.001",
                    technique_name="Golden Ticket",
                    tactic="Credential Access",
                ),
                MitreAttack(
                    technique_id="T1550.003",
                    technique_name="Pass the Ticket",
                    tactic="Lateral Movement",
                ),
            ],
            cis_controls=["5.4", "6.3"],
            nist_800_53=["AC-6", "IA-2", "CM-6"],
        )]


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


@check
class TIER009_AuthNPolicyAbsence(BaseCheck):
    id = "TIER-009"
    name = "Authentication Policy / Silo Absence for Tier 0"
    description = (
        "Flag when no Authentication Policies or Silos are deployed and "
        "privileged accounts are unprotected by Kerberos armoring controls."
    )
    category = "Tiered Administration"

    # Domain functional level 6 = Windows Server 2012 R2 (feature introduction)
    _MIN_FL_FOR_AUTHN_POLICY = 6

    def run(self) -> List[Finding]:
        fl = self.context.domain_info.domain_functional_level
        if fl < self._MIN_FL_FOR_AUTHN_POLICY:
            # Feature unavailable on this domain level — cannot flag absence
            return []

        policies: list = self.context.raw_entries.get("authn_policies", [])
        silos: list = self.context.raw_entries.get("authn_silos", [])
        assigned: list = self.context.raw_entries.get("authn_silo_members", [])

        # Count enabled Tier 0 accounts (our proxy for "privileged account" population)
        priv_users = [u for u in self.context.users if u.enabled and self.context.is_privileged_user(u)]
        priv_count = len(priv_users)

        if priv_count == 0:
            return []

        findings: List[Finding] = []

        enabled_policies = [p for p in policies if p.get("enabled")]
        enabled_silos = [s for s in silos if s.get("enabled")]

        if not enabled_policies and not enabled_silos:
            # Primary finding: feature not deployed at all
            findings.append(self.finding(
                title=(
                    f"No Authentication Policies or Silos deployed — "
                    f"{priv_count} Tier 0 account{'s' if priv_count != 1 else ''} unprotected"
                ),
                description=(
                    "Authentication Policies (introduced in Windows Server 2012 R2) allow you to "
                    "restrict which hosts a Kerberos TGT can be issued from and cap TGT lifetime for "
                    "privileged accounts. Authentication Silos bind accounts to a policy and enforce "
                    "Kerberos armoring (FAST), preventing credential theft techniques such as "
                    "Pass-the-Ticket and Golden Ticket attacks from operating outside the approved "
                    "access tier.\n\n"
                    "Neither feature is deployed in this domain. All Tier 0 accounts (Domain Admins, "
                    "Enterprise Admins, Schema Admins, etc.) can obtain TGTs from any device, including "
                    "compromised workstations, with no host binding or lifetime restriction enforced "
                    "by the KDC."
                ),
                severity=Severity.HIGH,
                affected_count=priv_count,
                affected_objects=[self.affected_user(u) for u in priv_users[:30]],
                remediation_desc=(
                    "1. Create an Authentication Policy for Tier 0 accounts with a short TGT lifetime "
                    "(e.g., 60 minutes) and restrict allowed-to-authenticate-from hosts to PAWs and DCs.\n"
                    "2. Create an Authentication Silo, assign the policy, and add all Tier 0 accounts "
                    "and their authorised hosts as silo members.\n"
                    "3. Enable Kerberos Armoring (FAST) via GPO: Computer Configuration → Administrative "
                    "Templates → System → KDC → 'Support for Dynamic Access Control and Kerberos armoring' "
                    "→ Enabled.\n"
                    "4. Initially enforce in audit mode (Enforce: No) until logon compatibility is "
                    "confirmed across all Tier 0 service dependencies."
                ),
                powershell=(
                    "# 1. Create Authentication Policy with 60-min TGT for users\n"
                    "New-ADAuthenticationPolicy -Name 'Tier0-AuthNPolicy' "
                    "-UserTGTLifetimeMins 60 -Enforce\n\n"
                    "# 2. Create Authentication Silo and assign the policy\n"
                    "New-ADAuthenticationPolicySilo -Name 'Tier0-Silo' "
                    "-UserAuthenticationPolicy 'Tier0-AuthNPolicy' -Enforce\n\n"
                    "# 3. Grant Domain Admins access to the silo\n"
                    "Grant-ADAuthenticationPolicySiloAccess -Identity 'Tier0-Silo' "
                    "-Account (Get-ADGroupMember 'Domain Admins')\n\n"
                    "# 4. Assign silo to each Tier 0 account\n"
                    "Get-ADGroupMember 'Domain Admins' | ForEach-Object {\n"
                    "    Set-ADAccountAuthenticationPolicySilo -Identity $_.DistinguishedName "
                    "-AuthenticationPolicySilo 'Tier0-Silo'\n"
                    "}\n\n"
                    "# 5. Verify assignments\n"
                    "Get-ADAuthenticationPolicySiloData -Identity 'Tier0-Silo'"
                ),
                mitre=[
                    MitreAttack(
                        technique_id="T1558.001",
                        technique_name="Golden Ticket",
                        tactic="Credential Access",
                    ),
                    MitreAttack(
                        technique_id="T1550.003",
                        technique_name="Pass the Ticket",
                        tactic="Lateral Movement",
                    ),
                    MitreAttack(
                        technique_id="T1078.002",
                        technique_name="Domain Accounts",
                        tactic="Defense Evasion",
                    ),
                ],
                cis_controls=["5.4", "6.3", "6.8"],
                nist_800_53=["AC-2", "AC-6", "IA-2", "SC-8", "CM-6"],
            ))
            return findings

        # Silos/policies exist — check if any privileged accounts are not assigned
        assigned_dns = {entry["dn"].lower() for entry in assigned if entry.get("dn")}
        unassigned_priv = [
            u for u in priv_users
            if u.dn.lower() not in assigned_dns
        ]

        if unassigned_priv:
            silo_names = [s["name"] for s in enabled_silos]
            findings.append(self.finding(
                title=(
                    f"{len(unassigned_priv)} Tier 0 account{'s' if len(unassigned_priv) != 1 else ''} "
                    f"not assigned to any Authentication Silo"
                ),
                description=(
                    f"Authentication Silos are deployed in this domain "
                    f"({', '.join(silo_names) if silo_names else 'unnamed'}), "
                    f"but {len(unassigned_priv)} privileged account(s) have no silo assignment "
                    f"(msDS-AssignedAuthNPolicySilo is not set). Accounts outside a silo receive no "
                    "KDC-enforced host binding or TGT lifetime restriction, leaving them exposed to "
                    "Pass-the-Ticket and Golden Ticket lateral movement from any compromised host."
                ),
                severity=Severity.MEDIUM,
                affected_count=len(unassigned_priv),
                affected_objects=[self.affected_user(u) for u in unassigned_priv[:30]],
                remediation_desc=(
                    "Grant each unassigned Tier 0 account access to the appropriate silo and set "
                    "msDS-AssignedAuthNPolicySilo using Set-ADAccountAuthenticationPolicySilo."
                ),
                powershell=(
                    "# Find Tier 0 accounts not assigned to a silo\n"
                    "Get-ADUser -Filter {adminCount -eq 1} -Properties msDS-AssignedAuthNPolicySilo |\n"
                    "    Where-Object { -not $_.'msDS-AssignedAuthNPolicySilo' } |\n"
                    "    Select-Object SamAccountName, DistinguishedName\n\n"
                    "# Assign to silo (repeat per account)\n"
                    "Grant-ADAuthenticationPolicySiloAccess -Identity 'Tier0-Silo' "
                    "-Account '<SamAccountName>'\n"
                    "Set-ADAccountAuthenticationPolicySilo -Identity '<SamAccountName>' "
                    "-AuthenticationPolicySilo 'Tier0-Silo'"
                ),
                mitre=[
                    MitreAttack(
                        technique_id="T1558.001",
                        technique_name="Golden Ticket",
                        tactic="Credential Access",
                    ),
                    MitreAttack(
                        technique_id="T1550.003",
                        technique_name="Pass the Ticket",
                        tactic="Lateral Movement",
                    ),
                ],
                cis_controls=["5.4", "6.3"],
                nist_800_53=["AC-2", "AC-6", "IA-2"],
            ))

        return findings
