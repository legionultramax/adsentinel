"""Password Policy checks — Domain default password policy (PP-001 to PP-010)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import (
    DEFAULT_LOCKOUT_THRESHOLD,
    DEFAULT_MAX_PASSWORD_AGE_DAYS,
    DEFAULT_PASSWORD_HISTORY,
    DEFAULT_PASSWORD_MIN_LENGTH,
    MITRE_BRUTE_FORCE,
    MITRE_CREDENTIALS_IN_ATTRIBUTES,
    MITRE_LSASS_MEMORY,
    MITRE_PASS_THE_HASH,
    MITRE_PASSWORD_SPRAYING,
)
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity


@check
class PP001_MinPasswordLength(BaseCheck):
    id = "PP-001"
    name = "Minimum Password Length"
    description = "Check if minimum password length meets security requirements"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        policy = self.context.password_policy
        if policy.min_length < DEFAULT_PASSWORD_MIN_LENGTH:
            return [self.finding(
                title=f"Minimum password length is {policy.min_length} (recommended: {DEFAULT_PASSWORD_MIN_LENGTH}+)",
                description=(
                    f"The domain password policy requires only {policy.min_length} characters. "
                    f"Short passwords are vulnerable to brute force and password spraying attacks. "
                    f"NIST SP 800-63B recommends a minimum of 14 characters."
                ),
                severity=Severity.HIGH if policy.min_length < 8 else Severity.MEDIUM,
                remediation_desc="Increase minimum password length to at least 14 characters.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -MinPasswordLength {DEFAULT_PASSWORD_MIN_LENGTH}",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                cis_controls=["5.2"],
                nist_800_53=["IA-5"],
                details={"current_length": policy.min_length, "recommended": DEFAULT_PASSWORD_MIN_LENGTH},
            )]
        return []


@check
class PP002_PasswordComplexity(BaseCheck):
    id = "PP-002"
    name = "Password Complexity Requirements"
    description = "Check if password complexity is enabled"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        policy = self.context.password_policy
        if not policy.complexity_enabled:
            return [self.finding(
                title="Password complexity requirements are disabled",
                description=(
                    "Password complexity is not enforced. Without complexity requirements, "
                    "users can set simple passwords that are easily guessed or cracked."
                ),
                severity=Severity.HIGH,
                remediation_desc="Enable password complexity requirements.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -ComplexityEnabled $true",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                cis_controls=["5.2"],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class PP003_AccountLockoutThreshold(BaseCheck):
    id = "PP-003"
    name = "Account Lockout Threshold"
    description = "Check if account lockout threshold is configured"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        policy = self.context.password_policy
        if policy.lockout_threshold == 0:
            return [self.finding(
                title="Account lockout is not configured",
                description=(
                    "No account lockout threshold is set. Attackers can attempt unlimited "
                    "password guesses without any account lockout, enabling brute force and "
                    "password spraying attacks."
                ),
                severity=Severity.HIGH,
                remediation_desc=f"Set account lockout threshold to {DEFAULT_LOCKOUT_THRESHOLD} or fewer attempts.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -LockoutThreshold {DEFAULT_LOCKOUT_THRESHOLD}",
                mitre=[MitreAttack(technique_id=MITRE_PASSWORD_SPRAYING, technique_name="Password Spraying", tactic="Credential Access")],
                cis_controls=["4.10"],
                nist_800_53=["AC-7"],
            )]
        elif policy.lockout_threshold > 10:
            return [self.finding(
                title=f"Account lockout threshold is too high ({policy.lockout_threshold})",
                description=f"The lockout threshold of {policy.lockout_threshold} allows too many failed attempts before lockout.",
                severity=Severity.MEDIUM,
                remediation_desc=f"Reduce lockout threshold to {DEFAULT_LOCKOUT_THRESHOLD} or fewer.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -LockoutThreshold {DEFAULT_LOCKOUT_THRESHOLD}",
                mitre=[MitreAttack(technique_id=MITRE_PASSWORD_SPRAYING, technique_name="Password Spraying", tactic="Credential Access")],
                cis_controls=["4.10"],
                nist_800_53=["AC-7"],
            )]
        return []


@check
class PP004_MaxPasswordAge(BaseCheck):
    id = "PP-004"
    name = "Maximum Password Age"
    description = "Check if maximum password age is configured appropriately"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        policy = self.context.password_policy
        if policy.max_age_days == 0:
            return [self.finding(
                title="Passwords never expire",
                description="No maximum password age is set. Passwords never expire, increasing the window for credential theft.",
                severity=Severity.MEDIUM,
                remediation_desc=f"Set maximum password age to {DEFAULT_MAX_PASSWORD_AGE_DAYS} days or use FGPP for sensitive accounts.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -MaxPasswordAge {DEFAULT_MAX_PASSWORD_AGE_DAYS}.00:00:00",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                nist_800_53=["IA-5"],
            )]
        elif policy.max_age_days > DEFAULT_MAX_PASSWORD_AGE_DAYS:
            return [self.finding(
                title=f"Maximum password age is too long ({policy.max_age_days} days)",
                description=f"Passwords can be up to {policy.max_age_days} days old before expiring.",
                severity=Severity.LOW,
                remediation_desc=f"Reduce maximum password age to {DEFAULT_MAX_PASSWORD_AGE_DAYS} days.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -MaxPasswordAge {DEFAULT_MAX_PASSWORD_AGE_DAYS}.00:00:00",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class PP005_MinPasswordAge(BaseCheck):
    id = "PP-005"
    name = "Minimum Password Age"
    description = "Check if minimum password age prevents rapid cycling"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        policy = self.context.password_policy
        if policy.min_age_days == 0:
            return [self.finding(
                title="Minimum password age is 0 (passwords can be changed immediately)",
                description=(
                    "With no minimum password age, users can cycle through passwords rapidly "
                    "to reuse old passwords, defeating password history requirements."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Set minimum password age to at least 1 day.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -MinPasswordAge 1.00:00:00",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                cis_controls=["5.2"],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class PP006_PasswordHistory(BaseCheck):
    id = "PP-006"
    name = "Password History"
    description = "Check if password history prevents reuse"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        policy = self.context.password_policy
        if policy.history_count < DEFAULT_PASSWORD_HISTORY:
            return [self.finding(
                title=f"Password history remembers only {policy.history_count} passwords (recommended: {DEFAULT_PASSWORD_HISTORY})",
                description=f"With only {policy.history_count} remembered passwords, users can cycle back to old passwords quickly.",
                severity=Severity.MEDIUM if policy.history_count < 12 else Severity.LOW,
                remediation_desc=f"Set password history to remember at least {DEFAULT_PASSWORD_HISTORY} passwords.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -PasswordHistoryCount {DEFAULT_PASSWORD_HISTORY}",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                cis_controls=["5.2"],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class PP007_ReversibleEncryption(BaseCheck):
    id = "PP-007"
    name = "Reversible Encryption"
    description = "Check if reversible password encryption is enabled"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        policy = self.context.password_policy
        if policy.reversible_encryption:
            return [self.finding(
                title="Reversible password encryption is enabled",
                description=(
                    "Storing passwords with reversible encryption is essentially the same as "
                    "storing plaintext passwords. An attacker who gains access to the AD database "
                    "can recover all user passwords."
                ),
                severity=Severity.CRITICAL,
                remediation_desc="Disable reversible encryption and force password resets for all affected accounts.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -ReversibleEncryptionEnabled $false",
                mitre=[MitreAttack(technique_id=MITRE_LSASS_MEMORY, technique_name="LSASS Memory", tactic="Credential Access")],
                cis_controls=["3.11"],
                nist_800_53=["IA-5", "SC-28"],
                stig_rules=["V-36435"],
            )]
        return []


@check
class PP008_LockoutDuration(BaseCheck):
    id = "PP-008"
    name = "Lockout Duration"
    description = "Check if account lockout duration is appropriate"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        policy = self.context.password_policy
        if policy.lockout_threshold > 0 and policy.lockout_duration_minutes == 0:
            return [self.finding(
                title="Account lockout duration is set to 'until admin unlocks'",
                description="Locked accounts require admin intervention, which can be used for denial-of-service by intentionally locking accounts.",
                severity=Severity.LOW,
                remediation_desc="Set lockout duration to 15-30 minutes for automatic unlock.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -LockoutDuration 00:30:00",
                mitre=[MitreAttack(technique_id=MITRE_PASSWORD_SPRAYING, technique_name="Password Spraying", tactic="Credential Access")],
                nist_800_53=["AC-7"],
            )]
        elif policy.lockout_threshold > 0 and policy.lockout_duration_minutes < 15:
            return [self.finding(
                title=f"Account lockout duration is too short ({policy.lockout_duration_minutes} minutes)",
                description="Short lockout durations allow rapid retry of password attacks.",
                severity=Severity.LOW,
                remediation_desc="Increase lockout duration to at least 15 minutes.",
                powershell=f"Set-ADDefaultDomainPasswordPolicy -Identity {self.context.domain_info.dns_name} -LockoutDuration 00:15:00",
                mitre=[MitreAttack(technique_id=MITRE_PASSWORD_SPRAYING, technique_name="Password Spraying", tactic="Credential Access")],
                nist_800_53=["AC-7"],
            )]
        return []


@check
class PP009_StalePasswords(BaseCheck):
    id = "PP-009"
    name = "Stale User Passwords"
    description = "Check for enabled accounts with passwords older than 365 days"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        from adsentinel.utils.time_utils import days_since

        stale_users = []
        for user in self.context.get_enabled_users():
            age = days_since(user.password_last_set)
            if age > 365:
                stale_users.append(user)

        if stale_users:
            return [self.finding(
                title=f"{len(stale_users)} enabled accounts have passwords older than 1 year",
                description="Accounts with very old passwords increase the risk of credential compromise from historical breaches.",
                severity=Severity.MEDIUM if len(stale_users) < 50 else Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in stale_users[:50]],
                affected_count=len(stale_users),
                remediation_desc="Force password reset for accounts with stale passwords.",
                powershell="Get-ADUser -Filter {PasswordLastSet -lt (Get-Date).AddDays(-365) -and Enabled -eq $true} | Set-ADUser -ChangePasswordAtLogon $true",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                nist_800_53=["IA-5"],
            )]
        return []


@check
class PP010_PasswordNeverExpires(BaseCheck):
    id = "PP-010"
    name = "Password Never Expires Flag"
    description = "Check for accounts with 'Password Never Expires' set"
    category = "Password Policy"

    def run(self) -> List[Finding]:
        never_expires = [u for u in self.context.get_enabled_users() if u.password_never_expires]
        if never_expires:
            # Separate admins from regular users for severity
            admin_never_expires = [u for u in never_expires if self.context.is_privileged_user(u)]
            sev = Severity.HIGH if admin_never_expires else Severity.MEDIUM

            return [self.finding(
                title=f"{len(never_expires)} accounts have 'Password Never Expires' ({len(admin_never_expires)} privileged)",
                description=(
                    f"Found {len(never_expires)} enabled accounts with the password never expires flag. "
                    f"{len(admin_never_expires)} of these are privileged accounts, which increases risk."
                ),
                severity=sev,
                affected_objects=[self.affected_user(u) for u in never_expires[:50]],
                affected_count=len(never_expires),
                remediation_desc="Remove 'Password Never Expires' flag. Use FGPP for service accounts that need longer rotation periods.",
                powershell="Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | Set-ADUser -PasswordNeverExpires $false",
                mitre=[MitreAttack(technique_id=MITRE_BRUTE_FORCE, technique_name="Brute Force", tactic="Credential Access")],
                nist_800_53=["IA-5"],
                details={"admin_count": len(admin_never_expires)},
            )]
        return []
