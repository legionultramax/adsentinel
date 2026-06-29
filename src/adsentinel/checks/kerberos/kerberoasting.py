"""Kerberos Security checks (KRB-001 to KRB-016)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import (
    MITRE_ASREP_ROASTING,
    MITRE_DCSYNC,
    MITRE_GOLDEN_TICKET,
    MITRE_KERBEROASTING,
    MITRE_UNCONSTRAINED_DELEGATION,
    RID_KRBTGT,
)
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity
from adsentinel.utils.sid import get_rid


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

        # Check computer accounts (exclude DCs — members of the Domain Controllers group)
        unconstrained_computers = [
            c for c in self.context.computers
            if c.enabled and c.trusted_for_delegation
            and not any("CN=Domain Controllers" in dn for dn in (c.member_of or []))
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
class KRB016_KRBTGTAccountSecurity(BaseCheck):
    """Dedicated security audit of the krbtgt account.

    The krbtgt account is the KDC service account whose NT hash is the domain's
    master Kerberos secret — compromising it yields a Golden Ticket, granting
    unlimited, persistent, domain-wide access.  Any misconfiguration that
    exposes that hash (kerberoastable SPN, AS-REP roastable, delegation) is
    immediately catastrophic.  This check audits four independent attack surfaces
    on the account and fires a separate, targeted finding for each one found.
    """

    id = "KRB-016"
    name = "KRBTGT Account Security Audit"
    description = (
        "Audit the krbtgt account for SPNs (kerberoastable), disabled pre-auth "
        "(AS-REP roastable), and delegation flags — each independently enables "
        "offline recovery of the domain's Kerberos master secret"
    )
    category = "Kerberos Security"

    # kadmin/changepw is the only SPN that can appear by design in mixed
    # Unix environments; it still makes krbtgt roastable, so we flag it
    # but at slightly lower severity and with an extra context note.
    _UNIX_COMPAT_SPN = "kadmin/changepw"

    def run(self) -> List[Finding]:
        # Locate krbtgt by RID 502 — name-rename-proof
        krbtgt = next(
            (u for u in self.context.users if get_rid(u.sid) == RID_KRBTGT),
            None,
        )
        if krbtgt is None:
            return []

        findings: List[Finding] = []

        # ── 1. SPNs present — krbtgt is Kerberoastable ───────────────────────
        if krbtgt.spn_list:
            unix_only = (
                len(krbtgt.spn_list) == 1
                and krbtgt.spn_list[0].lower() == self._UNIX_COMPAT_SPN
            )
            spn_list_str = "\n".join(f"  • {s}" for s in krbtgt.spn_list)
            if unix_only:
                description = (
                    "The krbtgt account has one SPN: kadmin/changepw. "
                    "This SPN exists for MIT Kerberos password-change protocol "
                    "compatibility (RFC 3244) and is sometimes added during "
                    "Unix/Linux realm integration. "
                    "Even so, it makes krbtgt Kerberoastable: any authenticated "
                    "domain user can request a TGS for this SPN and receive a "
                    "ticket encrypted with the krbtgt NT hash. "
                    "Cracking the ticket offline is equivalent to a Golden Ticket "
                    "attack — the recovered hash can forge Kerberos tickets for "
                    "any account in the domain, indefinitely.\n\n"
                    f"SPN present:\n{spn_list_str}"
                )
            else:
                description = (
                    "The krbtgt account has one or more ServicePrincipalNames set. "
                    "No SPN should ever exist on krbtgt in a Windows-only environment. "
                    "Any authenticated domain user can request a TGS ticket for each "
                    "of these SPNs. Each ticket is encrypted with the krbtgt NT hash "
                    "(the domain's Kerberos master key). Cracking any one ticket gives "
                    "an attacker full Golden Ticket capability: they can forge tickets "
                    "for any user — including domain admins — with any group membership, "
                    "with no expiry, without touching a DC again.\n\n"
                    f"SPNs present:\n{spn_list_str}"
                )

            findings.append(self.finding(
                title=(
                    "krbtgt is Kerberoastable — SPN(s) expose the domain Kerberos master secret"
                    if not unix_only else
                    "krbtgt has kadmin/changepw SPN — Kerberoastable (Unix compatibility remnant)"
                ),
                description=description,
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(krbtgt)],
                remediation_desc=(
                    "Remove all SPNs from the krbtgt account immediately:\n"
                    "1. Run: Set-ADUser krbtgt -ServicePrincipalNames @{}\n"
                    "2. Verify: Get-ADUser krbtgt -Properties ServicePrincipalName\n"
                    "3. Rotate the krbtgt password twice (12+ hour gap) to invalidate "
                    "any TGS tickets already issued against the old hash."
                ),
                powershell=(
                    "# Remove all SPNs from krbtgt:\n"
                    "$krbtgt = Get-ADUser krbtgt -Properties ServicePrincipalName\n"
                    "foreach ($spn in $krbtgt.ServicePrincipalName) {\n"
                    "    Set-ADUser krbtgt -ServicePrincipalNames @{Remove = $spn}\n"
                    "}\n\n"
                    "# Verify clean:\n"
                    "Get-ADUser krbtgt -Properties ServicePrincipalName | "
                    "Select-Object -ExpandProperty ServicePrincipalName\n\n"
                    "# Then rotate password twice (wait 10+ hours between runs):\n"
                    "# Use Microsoft's KRBTGT key rotation script (KrbtgtKeys.ps1)"
                ),
                manual_steps=[
                    "Open ADUC, locate the krbtgt account in Users container.",
                    "Open Properties → Attribute Editor → servicePrincipalName.",
                    "Remove all values. Click OK.",
                    "Rotate the krbtgt password twice (≥10 hours between rotations) "
                    "to ensure no previously-issued TGS tickets remain valid.",
                    "If SPN was added for Unix integration, configure the Kerberos "
                    "realm to use a dedicated service account instead of krbtgt.",
                ],
                mitre=[
                    MitreAttack(
                        technique_id=MITRE_KERBEROASTING,
                        technique_name="Kerberoasting",
                        tactic="Credential Access",
                    ),
                    MitreAttack(
                        technique_id=MITRE_GOLDEN_TICKET,
                        technique_name="Golden Ticket",
                        tactic="Credential Access",
                    ),
                ],
                cis_controls=["5.4", "5.5"],
                nist_800_53=["IA-5", "AC-6", "SC-13"],
                details={
                    "spns": krbtgt.spn_list,
                    "unix_compat_only": unix_only,
                },
            ))

        # ── 2. Pre-authentication disabled — krbtgt is AS-REP Roastable ──────
        if krbtgt.dont_require_preauth:
            findings.append(self.finding(
                title="krbtgt has pre-authentication disabled — AS-REP Roastable",
                description=(
                    "The DONT_REQ_PREAUTH flag is set on the krbtgt account. "
                    "This means any unauthenticated network client can send an AS-REQ "
                    "without supplying encrypted pre-auth data and will receive an AS-REP "
                    "whose enc-part is encrypted with the krbtgt NT hash. "
                    "The AS-REP can be captured and cracked offline with no domain credentials "
                    "whatsoever. Successful cracking yields the krbtgt hash — "
                    "equivalent to compromising the entire domain's Kerberos infrastructure.\n\n"
                    "This is an extremely rare configuration and should be treated as evidence "
                    "of either a critical misconfiguration or active adversary tampering."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(krbtgt)],
                remediation_desc=(
                    "1. Re-enable Kerberos pre-authentication on krbtgt immediately.\n"
                    "2. Investigate HOW this flag was set — check AD audit logs for "
                    "   who modified the krbtgt UAC attribute and when.\n"
                    "3. Rotate the krbtgt password twice (10+ hour gap between rotations).\n"
                    "4. Consider a full domain compromise assessment."
                ),
                powershell=(
                    "# Re-enable pre-authentication on krbtgt:\n"
                    "Set-ADAccountControl krbtgt -DoesNotRequirePreAuth $false\n\n"
                    "# Verify:\n"
                    "Get-ADUser krbtgt -Properties DoesNotRequirePreAuth | "
                    "Select-Object DoesNotRequirePreAuth\n\n"
                    "# Audit: who changed krbtgt UAC attribute?\n"
                    "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4738} | "
                    "Where-Object {$_.Message -like '*krbtgt*'} | "
                    "Select-Object TimeCreated, Message | Format-List"
                ),
                mitre=[
                    MitreAttack(
                        technique_id=MITRE_ASREP_ROASTING,
                        technique_name="AS-REP Roasting",
                        tactic="Credential Access",
                    ),
                    MitreAttack(
                        technique_id=MITRE_GOLDEN_TICKET,
                        technique_name="Golden Ticket",
                        tactic="Credential Access",
                    ),
                ],
                cis_controls=["5.4"],
                nist_800_53=["IA-5", "AC-6"],
            ))

        # ── 3. Unconstrained delegation on krbtgt ────────────────────────────
        if krbtgt.trusted_for_delegation:
            findings.append(self.finding(
                title="krbtgt has unconstrained delegation enabled — highly anomalous",
                description=(
                    "TrustedForDelegation is set on the krbtgt account. "
                    "There is no legitimate operational reason for krbtgt to have "
                    "unconstrained Kerberos delegation. When an account with unconstrained "
                    "delegation receives a Kerberos authentication, the KDC embeds a copy "
                    "of the authenticating user's TGT into the service ticket. "
                    "Any service or process running as krbtgt could therefore collect TGTs "
                    "for all authenticating users and use them to impersonate those users "
                    "against any service in the domain.\n\n"
                    "Combined with krbtgt's role as the KDC service account, this flag "
                    "represents a multi-layered privilege escalation path. "
                    "Its presence on krbtgt is a strong indicator of adversary tampering."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(krbtgt)],
                remediation_desc=(
                    "1. Remove the TrustedForDelegation flag from krbtgt.\n"
                    "2. Investigate who set this flag and when (Security event 4738).\n"
                    "3. Rotate krbtgt password twice. Consider a full compromise assessment."
                ),
                powershell=(
                    "# Remove unconstrained delegation from krbtgt:\n"
                    "Set-ADAccountControl krbtgt -TrustedForDelegation $false\n\n"
                    "# Verify:\n"
                    "Get-ADUser krbtgt -Properties TrustedForDelegation | "
                    "Select-Object TrustedForDelegation\n\n"
                    "# Audit: who set delegation on krbtgt?\n"
                    "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4738} | "
                    "Where-Object {$_.Message -like '*krbtgt*'} | Format-List"
                ),
                mitre=[
                    MitreAttack(
                        technique_id=MITRE_UNCONSTRAINED_DELEGATION,
                        technique_name="Steal or Forge Kerberos Tickets",
                        tactic="Credential Access",
                    ),
                ],
                cis_controls=["5.4", "6.8"],
                nist_800_53=["AC-6", "IA-5"],
            ))

        # ── 4. Protocol transition (S4U2Self) on krbtgt ──────────────────────
        if krbtgt.trusted_to_auth_for_delegation:
            findings.append(self.finding(
                title="krbtgt has protocol transition (S4U2Self) enabled — highly anomalous",
                description=(
                    "TrustedToAuthForDelegation is set on the krbtgt account. "
                    "Protocol transition (S4U2Self) allows an account to obtain a service "
                    "ticket for itself on behalf of any user, regardless of whether the "
                    "user authenticated with Kerberos. Combined with S4U2Proxy, it enables "
                    "full impersonation of any domain account to any service. "
                    "There is no legitimate operational scenario requiring protocol "
                    "transition on krbtgt. This is a strong indicator of deliberate "
                    "backdoor installation by an attacker who already had Domain Admin access."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(krbtgt)],
                remediation_desc=(
                    "1. Remove the TrustedToAuthForDelegation flag from krbtgt.\n"
                    "2. Audit Security event 4738 to determine when and by whom this was set.\n"
                    "3. Perform a full domain compromise assessment — this misconfiguration "
                    "   does not appear accidentally."
                ),
                powershell=(
                    "# Remove S4U2Self from krbtgt:\n"
                    "Set-ADAccountControl krbtgt -TrustedToAuthForDelegation $false\n\n"
                    "# Verify:\n"
                    "Get-ADUser krbtgt -Properties TrustedToAuthForDelegation | "
                    "Select-Object TrustedToAuthForDelegation\n\n"
                    "# Audit log:\n"
                    "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4738} | "
                    "Where-Object {$_.Message -like '*krbtgt*'} | Format-List"
                ),
                mitre=[
                    MitreAttack(
                        technique_id=MITRE_UNCONSTRAINED_DELEGATION,
                        technique_name="Steal or Forge Kerberos Tickets",
                        tactic="Credential Access",
                    ),
                ],
                cis_controls=["5.4"],
                nist_800_53=["AC-6"],
            ))

        return findings


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
