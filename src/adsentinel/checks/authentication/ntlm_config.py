"""Authentication Security checks (AUTH-001 to AUTH-012)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import MITRE_NTLM_RELAY, MITRE_PASS_THE_HASH
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity
from adsentinel.utils import safe_int


@check
class AUTH001_NTLMv1(BaseCheck):
    id = "AUTH-001"
    name = "NTLMv1 Authentication"
    description = "Check if NTLMv1 is allowed (requires WinRM)"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        lm_level_raw = self.context.registry_values.get("LmCompatibilityLevel", "")
        lm_level = safe_int(lm_level_raw)
        if lm_level is not None and lm_level < 3:
            return [self.finding(
                title=f"NTLMv1 authentication is allowed (LmCompatibilityLevel={lm_level_raw})",
                description=(
                    "NTLMv1 uses weak encryption that can be cracked almost instantly. "
                    "LmCompatibilityLevel should be set to 5 (send NTLMv2 only, refuse LM & NTLMv1)."
                ),
                severity=Severity.CRITICAL,
                remediation_desc="Set LmCompatibilityLevel to 5 via GPO.",
                powershell="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5",
                mitre=[MitreAttack(technique_id=MITRE_NTLM_RELAY, technique_name="LLMNR/NBT-NS Poisoning and SMB Relay", tactic="Credential Access")],
                cis_controls=["3.10"],
                nist_800_53=["IA-5", "SC-13"],
                stig_rules=["V-73487"],
                source="WinRM",
            )]
        return []


@check
class AUTH002_WDigest(BaseCheck):
    id = "AUTH-002"
    name = "WDigest Authentication"
    description = "Check if WDigest stores cleartext passwords in memory"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        wdigest = self.context.registry_values.get("UseLogonCredential", "")
        if wdigest == "1":
            return [self.finding(
                title="WDigest authentication stores cleartext passwords in memory",
                description=(
                    "WDigest UseLogonCredential is enabled. This causes cleartext passwords to be "
                    "stored in LSASS memory, which tools like Mimikatz can extract."
                ),
                severity=Severity.CRITICAL,
                remediation_desc="Disable WDigest cleartext credential storage.",
                powershell="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0",
                mitre=[MitreAttack(technique_id="T1003.001", technique_name="LSASS Memory", tactic="Credential Access")],
                nist_800_53=["IA-5"],
                source="WinRM",
            )]
        return []


@check
class AUTH003_SMBSigning(BaseCheck):
    id = "AUTH-003"
    name = "SMB Signing"
    description = "Check if SMB signing is required"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        smb = self.context.smb_config
        if smb and not smb.get("RequireSecuritySignature", True):
            return [self.finding(
                title="SMB signing is not required",
                description="Without required SMB signing, attackers can perform SMB relay attacks to impersonate users.",
                severity=Severity.HIGH,
                remediation_desc="Enable required SMB signing on all domain systems via GPO.",
                powershell="Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                mitre=[MitreAttack(technique_id=MITRE_NTLM_RELAY, technique_name="SMB Relay", tactic="Credential Access")],
                cis_controls=["3.10"],
                nist_800_53=["SC-8"],
                source="WinRM",
            )]
        return []


@check
class AUTH004_SMBv1(BaseCheck):
    id = "AUTH-004"
    name = "SMBv1 Protocol"
    description = "Check if SMBv1 is enabled"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        smb = self.context.smb_config
        if smb and smb.get("EnableSMB1Protocol", False):
            return [self.finding(
                title="SMBv1 protocol is enabled",
                description="SMBv1 is vulnerable to EternalBlue and other critical exploits. It should be disabled on all systems.",
                severity=Severity.CRITICAL,
                remediation_desc="Disable SMBv1 on all domain systems.",
                powershell="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                mitre=[MitreAttack(technique_id="T1210", technique_name="Exploitation of Remote Services", tactic="Lateral Movement")],
                cis_controls=["4.8"],
                nist_800_53=["CM-7"],
                source="WinRM",
            )]
        return []


@check
class AUTH005_LDAPSigning(BaseCheck):
    id = "AUTH-005"
    name = "LDAP Signing Requirements"
    description = "Check if LDAP signing is required on domain controllers"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        ldap_signing = safe_int(self.context.registry_values.get("LDAPServerIntegrity", ""))
        if ldap_signing is not None and ldap_signing < 2:
            return [self.finding(
                title="LDAP signing is not required on domain controllers",
                description="Without LDAP signing, attackers can perform LDAP relay attacks or modify LDAP traffic in transit.",
                severity=Severity.HIGH,
                remediation_desc="Set LDAP signing to 'Require signing' via GPO.",
                powershell="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LDAPServerIntegrity' -Value 2",
                mitre=[MitreAttack(technique_id=MITRE_NTLM_RELAY, technique_name="NTLM Relay", tactic="Credential Access")],
                nist_800_53=["SC-8"],
                source="WinRM",
            )]
        return []


@check
class AUTH006_LDAPChannelBinding(BaseCheck):
    id = "AUTH-006"
    name = "LDAP Channel Binding"
    description = "Check if LDAP channel binding is enabled"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        cb = safe_int(self.context.registry_values.get("LdapEnforceChannelBinding", ""))
        if cb is not None and cb < 2:
            return [self.finding(
                title="LDAP channel binding is not enforced",
                description="Without channel binding, LDAP connections are vulnerable to credential relaying attacks.",
                severity=Severity.MEDIUM,
                remediation_desc="Enable LDAP channel binding (set to 2 = Always).",
                powershell="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2",
                nist_800_53=["SC-8"],
                source="WinRM",
            )]
        return []


@check
class AUTH007_NTLMRestrictions(BaseCheck):
    id = "AUTH-007"
    name = "NTLM Restrictions"
    description = "Check if NTLM authentication is restricted"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        restrict_raw = self.context.registry_values.get("RestrictNTLMInDomain", "")
        restrict = safe_int(restrict_raw)
        if restrict is not None and restrict == 0:
            return [self.finding(
                title="NTLM authentication is not restricted in the domain",
                description=(
                    "NTLM authentication is allowed without restrictions. NTLM is vulnerable to relay "
                    "attacks and pass-the-hash. Restricting NTLM forces Kerberos where possible."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Enable NTLM auditing first, then progressively restrict NTLM.",
                powershell="# Step 1: Audit\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -Name 'AuditNTLMInDomain' -Value 7",
                mitre=[MitreAttack(technique_id=MITRE_PASS_THE_HASH, technique_name="Pass the Hash", tactic="Lateral Movement")],
                nist_800_53=["IA-5"],
                source="WinRM",
            )]
        return []


@check
class AUTH008_CredentialGuard(BaseCheck):
    id = "AUTH-008"
    name = "Credential Guard"
    description = "Check if Credential Guard is enabled on DCs"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        cg_raw = self.context.registry_values.get("LsaCfgFlags", "")
        cg = safe_int(cg_raw)
        if cg is not None and cg == 0:
            return [self.finding(
                title="Credential Guard is not enabled",
                description="Credential Guard uses virtualization-based security to protect NTLM hashes and Kerberos TGTs from theft by tools like Mimikatz.",
                severity=Severity.MEDIUM,
                remediation_desc="Enable Credential Guard via GPO on supported hardware.",
                powershell="# Enable via GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security",
                mitre=[MitreAttack(technique_id="T1003.001", technique_name="LSASS Memory", tactic="Credential Access")],
                cis_controls=["10.5"],
                nist_800_53=["SC-39"],
                source="WinRM",
            )]
        return []


@check
class AUTH009_AnonymousBind(BaseCheck):
    id = "AUTH-009"
    name = "LDAP Anonymous Bind"
    description = "Check if anonymous LDAP binds are allowed"
    category = "Authentication Security"

    def run(self) -> List[Finding]:
        # Check dsHeuristics for anonymous bind
        entry = self.context.raw_entries.get("dsHeuristics")
        # Also check domain functional level - newer levels restrict anonymous by default
        fl = self.context.domain_info.domain_functional_level
        if fl < 3:
            return [self.finding(
                title="Domain functional level may allow anonymous LDAP queries",
                description=f"Functional level {self.context.domain_info.domain_functional_level_name} may allow anonymous LDAP binds by default.",
                severity=Severity.MEDIUM,
                remediation_desc="Raise domain functional level and verify anonymous bind is disabled.",
                nist_800_53=["AC-14", "IA-5"],
            )]
        return []


@check
class AUTH010_SmartcardEnforcement(BaseCheck):
    id = "AUTH-010"
    name = "Smartcard Authentication"
    description = "Check if privileged accounts require smartcard authentication"
    category = "Authentication Security"

    def run(self) -> List[Finding]:
        from adsentinel.constants import UAC_SMARTCARD_REQUIRED
        priv_no_sc = [
            u for u in self.context.users
            if u.enabled and self.context.is_privileged_user(u)
            and not (u.user_account_control & UAC_SMARTCARD_REQUIRED)
        ]
        if priv_no_sc:
            return [self.finding(
                title=f"{len(priv_no_sc)} privileged accounts don't require smartcard authentication",
                description="Privileged accounts using only password authentication are vulnerable to credential theft. Smartcard enforcement adds a hardware factor.",
                severity=Severity.LOW,
                affected_objects=[self.affected_user(u) for u in priv_no_sc[:50]],
                affected_count=len(priv_no_sc),
                remediation_desc="Enforce smartcard authentication for privileged accounts.",
                powershell="Get-ADUser -Filter {adminCount -eq 1 -and SmartcardLogonRequired -eq $false -and Enabled -eq $true} | Set-ADUser -SmartcardLogonRequired $true",
                nist_800_53=["IA-2"],
            )]
        return []


@check
class AUTH011_PasswordNotReqdComputers(BaseCheck):
    id = "AUTH-011"
    name = "Computers with PASSWD_NOTREQD"
    description = "Check for computer accounts with PASSWD_NOTREQD flag"
    category = "Authentication Security"

    def run(self) -> List[Finding]:
        from adsentinel.constants import UAC_PASSWD_NOTREQD
        no_pwd_comps = [
            c for c in self.context.computers
            if c.enabled and (c.user_account_control & UAC_PASSWD_NOTREQD)
        ]
        if no_pwd_comps:
            return [self.finding(
                title=f"{len(no_pwd_comps)} computer accounts have PASSWD_NOTREQD flag",
                description="Computer accounts with PASSWD_NOTREQD can have empty passwords, enabling attackers to authenticate as the machine.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_computer(c) for c in no_pwd_comps[:50]],
                affected_count=len(no_pwd_comps),
                remediation_desc="Remove PASSWD_NOTREQD from computer accounts.",
                powershell="Get-ADComputer -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} | Set-ADComputer -PasswordNotRequired $false",
                nist_800_53=["IA-5"],
            )]
        return []


@check
class AUTH012_StaleComputerPasswords(BaseCheck):
    id = "AUTH-012"
    name = "Stale Computer Passwords"
    description = "Check for computers with passwords older than 90 days"
    category = "Authentication Security"

    def run(self) -> List[Finding]:
        stale = [c for c in self.context.computers if c.enabled and c.is_stale]
        if stale and len(stale) > 10:
            return [self.finding(
                title=f"{len(stale)} computers have stale passwords (90+ days)",
                description="Computers that haven't rotated their machine passwords may be offline, decommissioned, or compromised.",
                severity=Severity.MEDIUM if len(stale) < 50 else Severity.HIGH,
                affected_objects=[self.affected_computer(c) for c in stale[:50]],
                affected_count=len(stale),
                remediation_desc="Disable or remove stale computer accounts.",
                powershell="Get-ADComputer -Filter {PasswordLastSet -lt (Get-Date).AddDays(-90) -and Enabled -eq $true} | Disable-ADAccount",
                nist_800_53=["AC-2"],
            )]
        return []
