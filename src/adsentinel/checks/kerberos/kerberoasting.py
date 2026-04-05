"""Kerberos Security checks (KRB-001 to KRB-015)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import (
    MITRE_ASREP_ROASTING,
    MITRE_GOLDEN_TICKET,
    MITRE_KERBEROASTING,
    MITRE_UNCONSTRAINED_DELEGATION,
)
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity


@check
class KRB001_KerberoastableAccounts(BaseCheck):
    id = "KRB-001"
    name = "Kerberoastable Accounts"
    description = "Identify accounts with SPNs vulnerable to Kerberoasting"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        kerberoastable = self.context.get_kerberoastable_users()
        # Exclude krbtgt and machine accounts
        kerberoastable = [u for u in kerberoastable if not u.sam_account_name.endswith("$")]

        if kerberoastable:
            priv_count = sum(1 for u in kerberoastable if self.context.is_privileged_user(u))
            sev = Severity.CRITICAL if priv_count > 0 else (Severity.HIGH if len(kerberoastable) > 10 else Severity.MEDIUM)

            return [self.finding(
                title=f"{len(kerberoastable)} accounts are Kerberoastable ({priv_count} privileged)",
                description=(
                    f"Found {len(kerberoastable)} enabled user accounts with SPNs set. "
                    "Any domain user can request TGS tickets for these accounts and attempt "
                    "offline password cracking. "
                    f"{priv_count} of these are privileged accounts."
                ),
                severity=sev,
                affected_objects=[self.affected_user(u) for u in kerberoastable[:50]],
                affected_count=len(kerberoastable),
                remediation_desc="Remove unnecessary SPNs, use gMSA for service accounts, or ensure 25+ character passwords.",
                powershell="Get-ADUser -Filter {ServicePrincipalName -like '*' -and Enabled -eq $true} -Properties ServicePrincipalName | Select-Object SamAccountName, ServicePrincipalName",
                mitre=[MitreAttack(technique_id=MITRE_KERBEROASTING, technique_name="Kerberoasting", tactic="Credential Access")],
                cis_controls=["5.4"],
                nist_800_53=["IA-5", "AC-6"],
                details={"total": len(kerberoastable), "privileged": priv_count},
            )]
        return []


@check
class KRB002_ASREPRoastable(BaseCheck):
    id = "KRB-002"
    name = "AS-REP Roastable Accounts"
    description = "Identify accounts that don't require Kerberos pre-authentication"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        asrep = self.context.get_asrep_roastable_users()
        if asrep:
            priv_count = sum(1 for u in asrep if self.context.is_privileged_user(u))
            return [self.finding(
                title=f"{len(asrep)} accounts don't require Kerberos pre-authentication",
                description=(
                    "These accounts have DONT_REQ_PREAUTH set. Any user can request their AS-REP "
                    "and crack the encrypted portion offline to recover the password."
                ),
                severity=Severity.CRITICAL if priv_count > 0 else Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in asrep[:50]],
                affected_count=len(asrep),
                remediation_desc="Enable Kerberos pre-authentication on all accounts.",
                powershell="Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false",
                mitre=[MitreAttack(technique_id=MITRE_ASREP_ROASTING, technique_name="AS-REP Roasting", tactic="Credential Access")],
                cis_controls=["5.4"],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class KRB003_UnconstrainedDelegation(BaseCheck):
    id = "KRB-003"
    name = "Unconstrained Delegation"
    description = "Identify accounts with unconstrained Kerberos delegation"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        findings = []

        # Check user accounts
        unconstrained_users = [
            u for u in self.context.users
            if u.enabled and u.trusted_for_delegation
        ]
        if unconstrained_users:
            findings.append(self.finding(
                title=f"{len(unconstrained_users)} user accounts have unconstrained delegation",
                description=(
                    "Accounts with unconstrained delegation cache TGTs of all users that authenticate to them. "
                    "An attacker who compromises one can impersonate any user, including Domain Admins."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(u) for u in unconstrained_users],
                affected_count=len(unconstrained_users),
                remediation_desc="Replace unconstrained delegation with constrained delegation or RBCD.",
                powershell="Get-ADUser -Filter {TrustedForDelegation -eq $true -and Enabled -eq $true} | Select-Object SamAccountName",
                mitre=[MitreAttack(technique_id=MITRE_UNCONSTRAINED_DELEGATION, technique_name="Steal or Forge Kerberos Tickets", tactic="Credential Access")],
                nist_800_53=["AC-6"],
            ))

        # Check computer accounts (exclude DCs)
        unconstrained_computers = [
            c for c in self.context.computers
            if c.enabled and c.trusted_for_delegation
            and "Domain Controllers" not in str(c.member_of)
        ]
        if unconstrained_computers:
            findings.append(self.finding(
                title=f"{len(unconstrained_computers)} non-DC computers have unconstrained delegation",
                description="Non-DC computers with unconstrained delegation are high-value targets for credential theft.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_computer(c) for c in unconstrained_computers[:50]],
                affected_count=len(unconstrained_computers),
                remediation_desc="Replace unconstrained delegation with constrained delegation or RBCD.",
                powershell="Get-ADComputer -Filter {TrustedForDelegation -eq $true -and Enabled -eq $true} -Properties memberOf | Where-Object {$_.memberOf -notlike '*Domain Controllers*'}",
                mitre=[MitreAttack(technique_id=MITRE_UNCONSTRAINED_DELEGATION, technique_name="Steal or Forge Kerberos Tickets", tactic="Credential Access")],
                nist_800_53=["AC-6"],
            ))

        return findings


@check
class KRB004_ConstrainedDelegation(BaseCheck):
    id = "KRB-004"
    name = "Constrained Delegation Review"
    description = "Review accounts with constrained delegation for sensitive targets"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        constrained = [
            u for u in self.context.users
            if u.enabled and u.allowed_to_delegate_to
        ]

        # Check for delegation to sensitive services (LDAP, CIFS on DCs)
        sensitive_delegation = []
        for user in constrained:
            for spn in user.allowed_to_delegate_to:
                spn_lower = spn.lower()
                if any(svc in spn_lower for svc in ["ldap/", "cifs/", "host/", "http/"]):
                    sensitive_delegation.append(user)
                    break

        if sensitive_delegation:
            return [self.finding(
                title=f"{len(sensitive_delegation)} accounts have constrained delegation to sensitive services",
                description="Constrained delegation to LDAP, CIFS, or HOST on DCs can enable privilege escalation.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in sensitive_delegation[:50]],
                affected_count=len(sensitive_delegation),
                remediation_desc="Review delegation targets and remove unnecessary delegations.",
                powershell="Get-ADUser -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo | Select-Object SamAccountName, msDS-AllowedToDelegateTo",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class KRB005_RBCD(BaseCheck):
    id = "KRB-005"
    name = "Resource-Based Constrained Delegation"
    description = "Check for RBCD configurations that could enable privilege escalation"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        rbcd_computers = [
            c for c in self.context.computers
            if c.enabled and c.ms_ds_allowed_to_act_on_behalf
        ]

        if rbcd_computers:
            return [self.finding(
                title=f"{len(rbcd_computers)} computers have RBCD configured",
                description=(
                    "Resource-Based Constrained Delegation (RBCD) allows these computers to accept "
                    "delegated authentication. If misconfigured, attackers can use RBCD to impersonate "
                    "any user to these machines."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_computer(c) for c in rbcd_computers[:50]],
                affected_count=len(rbcd_computers),
                remediation_desc="Review RBCD configurations and ensure only authorized principals are listed.",
                powershell="Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class KRB006_DESEncryption(BaseCheck):
    id = "KRB-006"
    name = "DES Kerberos Encryption"
    description = "Check for accounts using weak DES encryption"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        des_users = [u for u in self.context.users if u.enabled and u.use_des_key_only]
        if des_users:
            return [self.finding(
                title=f"{len(des_users)} accounts use DES-only Kerberos encryption",
                description="DES is cryptographically broken. These accounts use weak encryption that can be cracked in minutes.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in des_users[:50]],
                affected_count=len(des_users),
                remediation_desc="Remove USE_DES_KEY_ONLY flag and ensure AES encryption is supported.",
                powershell="Get-ADUser -Filter {UseDESKeyOnly -eq $true -and Enabled -eq $true} | Set-ADAccountControl -UseDESKeyOnly $false",
                nist_800_53=["SC-13"],
            )]
        return []


@check
class KRB007_ProtectedUsersEmpty(BaseCheck):
    id = "KRB-007"
    name = "Protected Users Group"
    description = "Check if the Protected Users group is being utilized"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        protected_users_group = None
        for group in self.context.groups:
            if group.sam_account_name.lower() == "protected users":
                protected_users_group = group
                break

        if protected_users_group and not protected_users_group.member_dns:
            return [self.finding(
                title="Protected Users group is empty",
                description=(
                    "The Protected Users group provides additional protection against credential theft "
                    "(disables NTLM, WDigest, CredSSP, and delegation). No accounts are currently using this protection."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Add privileged accounts to the Protected Users group.",
                powershell="Add-ADGroupMember -Identity 'Protected Users' -Members (Get-ADGroupMember 'Domain Admins')",
                cis_controls=["5.4"],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class KRB008_T4DWithoutConstraint(BaseCheck):
    id = "KRB-008"
    name = "Trusted to Auth for Delegation Without Constraint"
    description = "Check for protocol transition accounts that may enable privilege escalation"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        t4d_users = [
            u for u in self.context.users
            if u.enabled and u.trusted_to_auth_for_delegation
        ]

        if t4d_users:
            return [self.finding(
                title=f"{len(t4d_users)} accounts are trusted to authenticate for delegation (S4U2Self)",
                description=(
                    "These accounts can use protocol transition (S4U2Self) to obtain Kerberos tickets "
                    "on behalf of any user without knowing their password. Combined with S4U2Proxy, "
                    "this can enable full impersonation."
                ),
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in t4d_users],
                affected_count=len(t4d_users),
                remediation_desc="Review and remove unnecessary protocol transition settings.",
                powershell="Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true -and Enabled -eq $true} | Select-Object SamAccountName",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class KRB009_WeakEncryptionPolicy(BaseCheck):
    id = "KRB-009"
    name = "Weak Kerberos Encryption Types"
    description = "Check for accounts configured with RC4-only Kerberos encryption"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        # Accounts where msDS-SupportedEncryptionTypes excludes AES
        # We can infer this from the domain functional level
        fl = self.context.domain_info.domain_functional_level
        if fl < 3:  # Below Server 2008 — AES not natively supported
            return [self.finding(
                title="Domain does not support AES Kerberos encryption natively",
                description=(
                    f"Domain functional level {self.context.domain_info.domain_functional_level_name} "
                    "does not natively support AES Kerberos encryption. All Kerberos tickets use RC4 (NTLM hash), "
                    "which is weaker than AES-256."
                ),
                severity=Severity.HIGH,
                remediation_desc="Raise domain functional level to at least Windows Server 2008.",
                nist_800_53=["SC-13"],
            )]
        return []


@check
class KRB010_ShadowCredentials(BaseCheck):
    id = "KRB-010"
    name = "Shadow Credentials"
    description = "Check for accounts with msDS-KeyCredentialLink set (Shadow Credentials)"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        shadow_creds = [
            u for u in self.context.users
            if u.ms_ds_key_credential_link
        ]

        if shadow_creds:
            priv_count = sum(1 for u in shadow_creds if self.context.is_privileged_user(u))
            sev = Severity.HIGH if priv_count > 0 else Severity.MEDIUM

            return [self.finding(
                title=f"{len(shadow_creds)} accounts have msDS-KeyCredentialLink set ({priv_count} privileged)",
                description=(
                    "msDS-KeyCredentialLink allows certificate-based authentication. If set by an attacker, "
                    "they can authenticate as the target user using a self-signed certificate (Shadow Credentials attack)."
                ),
                severity=sev,
                affected_objects=[self.affected_user(u) for u in shadow_creds[:50]],
                affected_count=len(shadow_creds),
                remediation_desc="Audit msDS-KeyCredentialLink values and remove unauthorized entries.",
                powershell="Get-ADUser -Filter {msDS-KeyCredentialLink -like '*'} -Properties msDS-KeyCredentialLink | Select-Object SamAccountName",
                mitre=[MitreAttack(technique_id="T1556.006", technique_name="Multi-Factor Authentication Interception", tactic="Credential Access")],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class KRB011_ComputerShadowCredentials(BaseCheck):
    id = "KRB-011"
    name = "Computer Shadow Credentials"
    description = "Check for computers with msDS-KeyCredentialLink set"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        shadow_creds = [
            c for c in self.context.computers
            if c.ms_ds_key_credential_link
        ]

        if shadow_creds:
            return [self.finding(
                title=f"{len(shadow_creds)} computers have msDS-KeyCredentialLink set",
                description="Computers with KeyCredentialLink may have Shadow Credentials configured by an attacker or by Windows Hello for Business.",
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_computer(c) for c in shadow_creds[:50]],
                affected_count=len(shadow_creds),
                remediation_desc="Audit computer KeyCredentialLink values for unauthorized entries.",
                powershell="Get-ADComputer -Filter {msDS-KeyCredentialLink -like '*'} -Properties msDS-KeyCredentialLink | Select-Object Name",
                nist_800_53=["IA-5"],
            )]
        return []


@check
class KRB012_ComputerUnconstrained(BaseCheck):
    id = "KRB-012"
    name = "Computers with Unconstrained Delegation"
    description = "Check for non-DC computers with unconstrained delegation"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        unconstrained = [
            c for c in self.context.computers
            if c.enabled and c.trusted_for_delegation
        ]
        # This is covered by KRB-003, so only report if there are a lot
        if len(unconstrained) > 5:
            return [self.finding(
                title=f"High number of computers with unconstrained delegation ({len(unconstrained)})",
                description="A large number of computers have unconstrained delegation, significantly increasing the attack surface.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_computer(c) for c in unconstrained[:50]],
                affected_count=len(unconstrained),
                remediation_desc="Review and convert to constrained delegation or RBCD.",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class KRB013_DelegationToSensitive(BaseCheck):
    id = "KRB-013"
    name = "Delegation to Domain Controllers"
    description = "Check for delegation targeting domain controller services"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        dc_hostnames = {dc.hostname.lower() for dc in self.context.domain_info.domain_controllers if dc.hostname}

        dangerous = []
        for user in self.context.users:
            if not user.enabled or not user.allowed_to_delegate_to:
                continue
            for spn in user.allowed_to_delegate_to:
                # Extract hostname from SPN (service/hostname)
                parts = spn.split("/")
                if len(parts) >= 2:
                    target_host = parts[1].split(":")[0].lower()
                    if target_host in dc_hostnames:
                        dangerous.append(user)
                        break

        if dangerous:
            return [self.finding(
                title=f"{len(dangerous)} accounts have delegation targeting Domain Controllers",
                description="Accounts delegating to DC services (LDAP, CIFS, HOST) can potentially perform DCSync or administrative operations.",
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(u) for u in dangerous],
                affected_count=len(dangerous),
                remediation_desc="Remove delegation to DC services unless absolutely required.",
                nist_800_53=["AC-6"],
                mitre=[MitreAttack(technique_id=MITRE_DCSYNC, technique_name="DCSync", tactic="Credential Access")],
            )]
        return []


@check
class KRB014_StaleKerberoastable(BaseCheck):
    id = "KRB-014"
    name = "Stale Kerberoastable Accounts"
    description = "Check for Kerberoastable accounts with stale passwords"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        from adsentinel.utils.time_utils import days_since
        stale_kerb = [
            u for u in self.context.get_kerberoastable_users()
            if not u.sam_account_name.endswith("$")
            and (u.password_last_set is None or days_since(u.password_last_set) > 365)
        ]

        if stale_kerb:
            return [self.finding(
                title=f"{len(stale_kerb)} Kerberoastable accounts have passwords older than 1 year",
                description="Kerberoastable accounts with old passwords have had more time to be cracked from historical ticket captures.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in stale_kerb[:50]],
                affected_count=len(stale_kerb),
                remediation_desc="Rotate passwords on Kerberoastable accounts. Consider converting to gMSA.",
                powershell="Get-ADUser -Filter {ServicePrincipalName -like '*' -and PasswordLastSet -lt (Get-Date).AddDays(-365)} -Properties PasswordLastSet, ServicePrincipalName",
                mitre=[MitreAttack(technique_id=MITRE_KERBEROASTING, technique_name="Kerberoasting", tactic="Credential Access")],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class KRB015_LAPSNotDeployed(BaseCheck):
    id = "KRB-015"
    name = "LAPS Coverage"
    description = "Check LAPS deployment coverage across workstations and servers"
    category = "Kerberos Security"

    def run(self) -> List[Finding]:
        enabled_computers = [c for c in self.context.computers if c.enabled]
        without_laps = self.context.get_computers_without_laps()

        if not enabled_computers:
            return []

        coverage_pct = ((len(enabled_computers) - len(without_laps)) / len(enabled_computers)) * 100

        if coverage_pct < 80:
            return [self.finding(
                title=f"LAPS coverage is only {coverage_pct:.0f}% ({len(without_laps)} machines without LAPS)",
                description=(
                    f"Only {coverage_pct:.0f}% of enabled computers have LAPS deployed. "
                    "Without LAPS, local administrator passwords are often shared or never rotated, "
                    "enabling lateral movement via Pass-the-Hash."
                ),
                severity=Severity.HIGH if coverage_pct < 50 else Severity.MEDIUM,
                affected_objects=[self.affected_computer(c) for c in without_laps[:50]],
                affected_count=len(without_laps),
                remediation_desc="Deploy LAPS (or Windows LAPS v2) to all managed computers.",
                powershell="Get-ADComputer -Filter {Enabled -eq $true} -Properties ms-Mcs-AdmPwdExpirationTime | Where-Object {$_.'ms-Mcs-AdmPwdExpirationTime' -eq $null} | Select-Object Name",
                mitre=[MitreAttack(technique_id="T1550.002", technique_name="Pass the Hash", tactic="Lateral Movement")],
                cis_controls=["5.2"],
                nist_800_53=["IA-5"],
                details={"coverage_percent": round(coverage_pct, 1), "without_laps": len(without_laps)},
            )]
        return []
