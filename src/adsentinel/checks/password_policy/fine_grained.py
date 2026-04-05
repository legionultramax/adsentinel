"""Fine-Grained Password Policy checks (PP-011 to PP-020)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import DEFAULT_PASSWORD_MIN_LENGTH, MITRE_BRUTE_FORCE
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity


@check
class PP011_NoFGPP(BaseCheck):
    id = "PP-011"
    name = "Fine-Grained Password Policies"
    description = "Check if FGPPs are defined for privileged accounts"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        if not self.context.fine_grained_policies:
            return [self.finding(
                title="No Fine-Grained Password Policies (FGPP) defined",
                description=(
                    "No FGPPs exist in this domain. Privileged accounts should have stricter "
                    "password policies than standard users. FGPPs allow targeting specific groups "
                    "with stronger requirements."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Create FGPPs for Domain Admins and other privileged groups with stricter requirements.",
                powershell=(
                    "New-ADFineGrainedPasswordPolicy -Name 'Privileged Accounts Policy' "
                    "-Precedence 10 -MinPasswordLength 20 -ComplexityEnabled $true "
                    "-PasswordHistoryCount 24 -MaxPasswordAge 60.00:00:00 "
                    "-LockoutThreshold 3 -LockoutDuration 00:30:00"
                ),
                cis_controls=["5.2"],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class PP012_FGPPWeakLength(BaseCheck):
    id = "PP-012"
    name = "FGPP Minimum Length"
    description = "Check if FGPPs enforce adequate minimum password length"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        findings = []
        for fgpp in self.context.fine_grained_policies:
            if fgpp.min_length < DEFAULT_PASSWORD_MIN_LENGTH:
                findings.append(self.finding(
                    title=f"FGPP '{fgpp.name}' has weak minimum length ({fgpp.min_length})",
                    description=f"Fine-grained policy '{fgpp.name}' only requires {fgpp.min_length} character passwords.",
                    severity=Severity.MEDIUM,
                    affected_objects=[AffectedObject(dn=fgpp.dn, sam_account_name=fgpp.name, object_type="fgpp")],
                    remediation_desc=f"Increase minimum length to at least {DEFAULT_PASSWORD_MIN_LENGTH} characters.",
                    powershell=f"Set-ADFineGrainedPasswordPolicy -Identity '{fgpp.name}' -MinPasswordLength {DEFAULT_PASSWORD_MIN_LENGTH}",
                    nist_800_53=["IA-5"],
                ))
        return findings


@check
class PP013_FGPPNoComplexity(BaseCheck):
    id = "PP-013"
    name = "FGPP Complexity"
    description = "Check if FGPPs enforce password complexity"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        findings = []
        for fgpp in self.context.fine_grained_policies:
            if not fgpp.complexity_enabled:
                findings.append(self.finding(
                    title=f"FGPP '{fgpp.name}' does not require password complexity",
                    description=f"Fine-grained policy '{fgpp.name}' does not enforce complexity requirements.",
                    severity=Severity.MEDIUM,
                    affected_objects=[AffectedObject(dn=fgpp.dn, sam_account_name=fgpp.name, object_type="fgpp")],
                    remediation_desc="Enable complexity requirements on this FGPP.",
                    powershell=f"Set-ADFineGrainedPasswordPolicy -Identity '{fgpp.name}' -ComplexityEnabled $true",
                    nist_800_53=["IA-5"],
                ))
        return findings


@check
class PP014_FGPPReversibleEncryption(BaseCheck):
    id = "PP-014"
    name = "FGPP Reversible Encryption"
    description = "Check if FGPPs have reversible encryption enabled"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        findings = []
        for fgpp in self.context.fine_grained_policies:
            if fgpp.reversible_encryption:
                findings.append(self.finding(
                    title=f"FGPP '{fgpp.name}' enables reversible password encryption",
                    description="Reversible encryption stores passwords in a recoverable format, equivalent to plaintext.",
                    severity=Severity.CRITICAL,
                    affected_objects=[AffectedObject(dn=fgpp.dn, sam_account_name=fgpp.name, object_type="fgpp")],
                    remediation_desc="Disable reversible encryption on this FGPP.",
                    powershell=f"Set-ADFineGrainedPasswordPolicy -Identity '{fgpp.name}' -ReversibleEncryptionEnabled $false",
                    nist_800_53=["IA-5", "SC-28"],
                ))
        return findings


@check
class PP015_FGPPNoLockout(BaseCheck):
    id = "PP-015"
    name = "FGPP Lockout Policy"
    description = "Check if FGPPs have lockout policies configured"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        findings = []
        for fgpp in self.context.fine_grained_policies:
            if fgpp.lockout_threshold == 0:
                findings.append(self.finding(
                    title=f"FGPP '{fgpp.name}' has no account lockout",
                    description=f"Fine-grained policy '{fgpp.name}' does not configure account lockout.",
                    severity=Severity.MEDIUM,
                    affected_objects=[AffectedObject(dn=fgpp.dn, sam_account_name=fgpp.name, object_type="fgpp")],
                    remediation_desc="Configure lockout threshold on this FGPP.",
                    powershell=f"Set-ADFineGrainedPasswordPolicy -Identity '{fgpp.name}' -LockoutThreshold 5 -LockoutDuration 00:30:00",
                    mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                    nist_800_53=["AC-7"],
                ))
        return findings


@check
class PP016_FGPPNotApplied(BaseCheck):
    id = "PP-016"
    name = "FGPP Application"
    description = "Check for FGPPs not applied to any groups or users"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        findings = []
        for fgpp in self.context.fine_grained_policies:
            if not fgpp.applies_to:
                findings.append(self.finding(
                    title=f"FGPP '{fgpp.name}' is not applied to any users or groups",
                    description="This FGPP exists but is not linked to any objects, making it ineffective.",
                    severity=Severity.LOW,
                    affected_objects=[AffectedObject(dn=fgpp.dn, sam_account_name=fgpp.name, object_type="fgpp")],
                    remediation_desc="Apply this FGPP to the appropriate groups.",
                    powershell=f"Add-ADFineGrainedPasswordPolicySubject -Identity '{fgpp.name}' -Subjects 'Domain Admins'",
                ))
        return findings


@check
class PP017_PasswordNotRequired(BaseCheck):
    id = "PP-017"
    name = "Password Not Required"
    description = "Check for accounts with PASSWD_NOTREQD flag"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        no_pwd = [u for u in self.context.get_enabled_users() if u.password_not_required]
        if no_pwd:
            return [self.finding(
                title=f"{len(no_pwd)} accounts have 'Password Not Required' flag set",
                description=(
                    "These accounts can have empty passwords. This flag is often set during migration "
                    "or provisioning and forgotten. Attackers can authenticate with blank passwords."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(u) for u in no_pwd[:50]],
                affected_count=len(no_pwd),
                remediation_desc="Remove PASSWD_NOTREQD flag from all accounts.",
                powershell="Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} | Set-ADUser -PasswordNotRequired $false",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class PP018_NeverSetPassword(BaseCheck):
    id = "PP-018"
    name = "Accounts That Never Set Password"
    description = "Check for enabled accounts that have never changed their password"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        never_set = [
            u for u in self.context.get_enabled_users()
            if u.password_last_set is None
        ]
        if never_set:
            return [self.finding(
                title=f"{len(never_set)} enabled accounts have never set a password",
                description="These accounts may still have their initial provisioned password or a blank password.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in never_set[:50]],
                affected_count=len(never_set),
                remediation_desc="Force password change at next logon for these accounts.",
                powershell="Get-ADUser -Filter {pwdLastSet -eq 0 -and Enabled -eq $true} | Set-ADUser -ChangePasswordAtLogon $true",
                nist_800_53=["IA-5"],
            )]
        return []


@check
class PP019_PasswordInDescription(BaseCheck):
    id = "PP-019"
    name = "Password in Description Field"
    description = "Check for potential passwords stored in user description fields"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        password_keywords = ["password", "pwd", "pass:", "p@ss", "cred"]
        suspicious = []
        for user in self.context.users:
            if user.description:
                desc_lower = user.description.lower()
                if any(kw in desc_lower for kw in password_keywords):
                    suspicious.append(user)

        if suspicious:
            return [self.finding(
                title=f"{len(suspicious)} accounts may have passwords in their description field",
                description="Account description fields contain password-related keywords. Credentials stored in cleartext LDAP attributes are readable by all domain users.",
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_user(u) for u in suspicious[:50]],
                affected_count=len(suspicious),
                remediation_desc="Remove passwords from description fields and reset the affected account passwords.",
                powershell="Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -match 'password|pwd|pass:'} | Select-Object SamAccountName, Description",
                nist_800_53=["IA-5", "SC-28"],
            )]
        return []


@check
class PP020_LMHashStorage(BaseCheck):
    id = "PP-020"
    name = "LM Hash Storage"
    description = "Check for accounts potentially storing LM hashes"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        # LM hashes are stored when passwords are < 15 chars and NoLMHash policy isn't set
        # We check if the domain functional level supports disabling LM hash storage
        fl = self.context.domain_info.domain_functional_level
        if fl < 3:  # Below Server 2008
            return [self.finding(
                title="Domain functional level may allow LM hash storage",
                description=(
                    f"Domain functional level is {self.context.domain_info.domain_functional_level_name}. "
                    "Older functional levels may store weak LM hashes alongside NTLM hashes, "
                    "which can be cracked in seconds."
                ),
                severity=Severity.HIGH,
                remediation_desc="Raise domain functional level and ensure NoLMHash policy is enabled via GPO.",
                powershell="Set-ADDomainMode -Identity (Get-ADDomain) -DomainMode Windows2008R2Domain",
                nist_800_53=["IA-5", "SC-13"],
            )]
        return []
