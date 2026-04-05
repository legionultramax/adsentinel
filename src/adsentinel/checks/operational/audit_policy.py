"""Operational/Audit checks (OPS-001 to OPS-010)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity


@check
class OPS001_AuditPolicyNotCollected(BaseCheck):
    id = "OPS-001"
    name = "Audit Policy Configuration"
    description = "Check if audit policy is properly configured"
    category = "Operational Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        if self.context.audit_policy is None:
            return [self.finding(
                title="Unable to collect audit policy (WinRM not available)",
                description="Audit policy could not be verified. Ensure Advanced Audit Policy is configured for security monitoring.",
                severity=Severity.INFO,
                remediation_desc="Enable WinRM for comprehensive audit policy checks.",
                source="WinRM",
            )]

        # Check critical audit categories
        critical_categories = {
            "Logon": "Success and Failure",
            "Account Logon": "Success and Failure",
            "Account Management": "Success and Failure",
            "Directory Service Access": "Success and Failure",
            "Policy Change": "Success and Failure",
        }

        missing = []
        for category, expected in critical_categories.items():
            value = self.context.audit_policy.get(category, "")
            if "No Auditing" in value or not value:
                missing.append(category)

        if missing:
            return [self.finding(
                title=f"{len(missing)} critical audit categories are not configured",
                description=f"Missing audit policies: {', '.join(missing)}. Without proper auditing, security incidents cannot be detected or investigated.",
                severity=Severity.HIGH,
                remediation_desc="Enable auditing for all critical categories via Advanced Audit Policy.",
                powershell="auditpol /set /category:\"Account Logon\" /success:enable /failure:enable",
                mitre=[MitreAttack(technique_id="T1562.002", technique_name="Disable Windows Event Logging", tactic="Defense Evasion")],
                cis_controls=["8.5"],
                nist_800_53=["AU-2", "AU-12"],
                source="WinRM",
                details={"missing_categories": missing},
            )]
        return []


@check
class OPS002_EventLogSize(BaseCheck):
    id = "OPS-002"
    name = "Security Event Log Size"
    description = "Check if security event log is adequately sized"
    category = "Operational Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        security_log = self.context.raw_entries.get("event_log_security")
        if security_log and isinstance(security_log, dict):
            max_size = security_log.get("MaximumSizeInBytes", 0)
            if max_size and max_size < 1073741824:  # 1 GB
                size_mb = max_size / (1024 * 1024)
                return [self.finding(
                    title=f"Security event log size is only {size_mb:.0f}MB (recommended: 1GB+)",
                    description="Small event logs get overwritten quickly, destroying forensic evidence.",
                    severity=Severity.MEDIUM,
                    remediation_desc="Increase Security event log size to at least 1GB.",
                    powershell="wevtutil sl Security /ms:1073741824",
                    cis_controls=["8.3"],
                    nist_800_53=["AU-4"],
                    source="WinRM",
                )]
        return []


@check
class OPS003_PowerShellLogging(BaseCheck):
    id = "OPS-003"
    name = "PowerShell Script Block Logging"
    description = "Check if PowerShell script block logging is enabled"
    category = "Operational Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        ps_logging = self.context.registry_values.get("EnableScriptBlockLogging", "")
        if not ps_logging or ps_logging == "0":
            return [self.finding(
                title="PowerShell Script Block Logging is not enabled",
                description="Without script block logging, PowerShell-based attacks cannot be detected or investigated. Most modern attacks use PowerShell.",
                severity=Severity.HIGH,
                remediation_desc="Enable PowerShell Script Block Logging via GPO.",
                powershell="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1",
                mitre=[MitreAttack(technique_id="T1059.001", technique_name="PowerShell", tactic="Execution")],
                cis_controls=["8.8"],
                nist_800_53=["AU-2"],
                source="WinRM",
            )]
        return []


@check
class OPS004_CommandLineAuditing(BaseCheck):
    id = "OPS-004"
    name = "Command Line Process Auditing"
    description = "Check if command line auditing is enabled in process creation events"
    category = "Operational Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        cmd_audit = self.context.registry_values.get("ProcessCreationIncludeCmdLine_Enabled", "")
        if not cmd_audit or cmd_audit == "0":
            return [self.finding(
                title="Command line process auditing is not enabled",
                description="Process creation events (4688) don't include the command line. This is essential for detecting living-off-the-land attacks.",
                severity=Severity.MEDIUM,
                remediation_desc="Enable command line in process creation events via GPO.",
                powershell="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1",
                cis_controls=["8.8"],
                nist_800_53=["AU-2"],
                source="WinRM",
            )]
        return []


@check
class OPS005_PrintSpoolerOnDC(BaseCheck):
    id = "OPS-005"
    name = "Print Spooler on Domain Controllers"
    description = "Check if Print Spooler service is running on DCs"
    category = "Operational Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        spooler = self.context.service_statuses.get("Spooler", "")
        if spooler and spooler.lower() == "running":
            return [self.finding(
                title="Print Spooler service is running on domain controller",
                description=(
                    "The Print Spooler enables PrintNightmare (CVE-2021-34527) and SpoolSample/PrinterBug "
                    "coercion attacks that can force the DC to authenticate to an attacker-controlled server."
                ),
                severity=Severity.HIGH,
                remediation_desc="Disable the Print Spooler service on all domain controllers.",
                powershell="Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled",
                mitre=[MitreAttack(technique_id="T1187", technique_name="Forced Authentication", tactic="Credential Access")],
                cis_controls=["4.8"],
                nist_800_53=["CM-7"],
                source="WinRM",
            )]
        return []


@check
class OPS006_ScheduledTaskAudit(BaseCheck):
    id = "OPS-006"
    name = "Privileged Service Accounts"
    description = "Check for non-gMSA service accounts in privileged groups"
    category = "Operational Security"

    def run(self) -> List[Finding]:
        svc_admins = [
            u for u in self.context.users
            if u.enabled and u.spn_list and self.context.is_privileged_user(u)
            and not u.sam_account_name.endswith("$")
        ]
        if svc_admins:
            return [self.finding(
                title=f"{len(svc_admins)} service accounts are members of privileged groups",
                description="Service accounts with SPNs in admin groups are Kerberoastable and provide lateral movement paths if compromised.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in svc_admins],
                affected_count=len(svc_admins),
                remediation_desc="Remove service accounts from privileged groups. Convert to gMSA with least-privilege delegation.",
                powershell="Get-ADUser -Filter {ServicePrincipalName -like '*' -and adminCount -eq 1 -and Enabled -eq $true} -Properties ServicePrincipalName",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class OPS007_StaleEnabledAccounts(BaseCheck):
    id = "OPS-007"
    name = "Stale Enabled Accounts"
    description = "Check for enabled accounts inactive for 180+ days"
    category = "Operational Security"

    def run(self) -> List[Finding]:
        from adsentinel.utils.time_utils import days_since
        very_stale = [
            u for u in self.context.users
            if u.enabled and days_since(u.last_logon) > 180
            and u.sam_account_name not in ("krbtgt", "Guest")
        ]
        if very_stale and len(very_stale) > 20:
            return [self.finding(
                title=f"{len(very_stale)} enabled accounts have been inactive for 180+ days",
                description="These accounts significantly increase the attack surface. Stale accounts are prime targets for credential stuffing and brute force.",
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in very_stale[:50]],
                affected_count=len(very_stale),
                remediation_desc="Disable accounts inactive for 180+ days.",
                powershell="Search-ADAccount -AccountInactive -TimeSpan 180.00:00:00 -UsersOnly | Where-Object Enabled | Disable-ADAccount",
                cis_controls=["5.3"],
                nist_800_53=["AC-2"],
            )]
        return []


@check
class OPS008_DescriptionAudit(BaseCheck):
    id = "OPS-008"
    name = "Sensitive Data in Descriptions"
    description = "Check for sensitive information in computer/group description fields"
    category = "Operational Security"

    def run(self) -> List[Finding]:
        from adsentinel.models.finding import AffectedObject
        keywords = ["password", "pwd", "secret", "key:", "token", "credential"]
        suspicious = []
        for group in self.context.groups:
            if group.description:
                if any(kw in group.description.lower() for kw in keywords):
                    suspicious.append(AffectedObject(dn=group.dn, sam_account_name=group.sam_account_name, object_type="group"))
        if suspicious:
            return [self.finding(
                title=f"{len(suspicious)} group descriptions may contain sensitive data",
                description="Group description fields containing passwords or keys are readable by all domain users.",
                severity=Severity.HIGH,
                affected_objects=suspicious[:50],
                affected_count=len(suspicious),
                remediation_desc="Remove sensitive data from description fields.",
                nist_800_53=["SC-28"],
            )]
        return []
