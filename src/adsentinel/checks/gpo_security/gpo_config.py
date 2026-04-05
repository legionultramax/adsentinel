"""GPO Security checks (GPO-001 to GPO-010)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import MITRE_GROUP_POLICY_MODIFICATION
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity


@check
class GPO001_NoGPOs(BaseCheck):
    id = "GPO-001"
    name = "GPO Count"
    description = "Check if GPOs exist in the domain"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        if not self.context.gpos:
            return [self.finding(
                title="No Group Policy Objects found",
                description="No GPOs were discovered. This may indicate a collection issue or a domain with no policy enforcement.",
                severity=Severity.INFO,
                remediation_desc="Verify GPO collection and ensure baseline security policies are deployed.",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO002_DefaultDomainPolicy(BaseCheck):
    id = "GPO-002"
    name = "Default Domain Policy"
    description = "Check if the Default Domain Policy is properly configured"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        default_dp = None
        for gpo in self.context.gpos:
            name = gpo.get("display_name", "").lower()
            if name == "default domain policy":
                default_dp = gpo
                break

        if default_dp and default_dp.get("is_disabled"):
            return [self.finding(
                title="Default Domain Policy is disabled",
                description="The Default Domain Policy is disabled. This GPO controls critical settings including password policy and account lockout.",
                severity=Severity.CRITICAL,
                remediation_desc="Enable the Default Domain Policy immediately.",
                powershell="(Get-GPO -Name 'Default Domain Policy').GpoStatus = 'AllSettingsEnabled'",
                mitre=[MitreAttack(technique_id=MITRE_GROUP_POLICY_MODIFICATION, technique_name="Group Policy Modification", tactic="Defense Evasion")],
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO003_DefaultDCPolicy(BaseCheck):
    id = "GPO-003"
    name = "Default Domain Controllers Policy"
    description = "Check if the Default Domain Controllers Policy is properly configured"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        default_dc = None
        for gpo in self.context.gpos:
            name = gpo.get("display_name", "").lower()
            if name == "default domain controllers policy":
                default_dc = gpo
                break

        if default_dc and default_dc.get("is_disabled"):
            return [self.finding(
                title="Default Domain Controllers Policy is disabled",
                description="The Default Domain Controllers Policy is disabled. This GPO controls DC-specific security settings.",
                severity=Severity.HIGH,
                remediation_desc="Enable the Default Domain Controllers Policy.",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO004_DisabledGPOs(BaseCheck):
    id = "GPO-004"
    name = "Disabled GPOs"
    description = "Check for GPOs that are fully disabled"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        disabled = [g for g in self.context.gpos if g.get("is_disabled")]
        total = len(self.context.gpos)
        if disabled and total > 0 and len(disabled) > 5:
            return [self.finding(
                title=f"{len(disabled)} of {total} GPOs are fully disabled",
                description="Many disabled GPOs may indicate poor GPO lifecycle management. Disabled GPOs can still have ACLs that could be abused if re-enabled by an attacker.",
                severity=Severity.LOW,
                affected_count=len(disabled),
                remediation_desc="Review and remove unneeded disabled GPOs.",
                powershell="Get-GPO -All | Where-Object {$_.GpoStatus -eq 'AllSettingsDisabled'}",
                nist_800_53=["CM-6"],
                details={"disabled_gpos": [g.get("display_name", "") for g in disabled[:20]]},
            )]
        return []


@check
class GPO005_UnlinkedGPOs(BaseCheck):
    id = "GPO-005"
    name = "Unversioned GPOs"
    description = "Check for GPOs with version 0 (never modified)"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        unversioned = [g for g in self.context.gpos if g.get("version", 0) == 0 and not g.get("is_disabled")]
        if unversioned:
            return [self.finding(
                title=f"{len(unversioned)} active GPOs have never been modified (version 0)",
                description="GPOs with version 0 may be empty or misconfigured. They add processing overhead without providing policy enforcement.",
                severity=Severity.LOW,
                affected_count=len(unversioned),
                remediation_desc="Review version-0 GPOs and remove if not needed.",
                powershell="Get-GPO -All | Where-Object {$_.Computer.DSVersion -eq 0 -and $_.User.DSVersion -eq 0}",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO006_GPOCount(BaseCheck):
    id = "GPO-006"
    name = "Excessive GPO Count"
    description = "Check for excessive number of GPOs that may slow logon"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        total = len(self.context.gpos)
        if total > 100:
            return [self.finding(
                title=f"{total} GPOs detected — may cause slow logon and policy processing",
                description="Large numbers of GPOs increase logon times and make security auditing difficult. Consider consolidating policies.",
                severity=Severity.LOW,
                remediation_desc="Audit and consolidate GPOs to reduce count below 100.",
                nist_800_53=["CM-6"],
                details={"gpo_count": total},
            )]
        return []


@check
class GPO007_PartiallyDisabledGPOs(BaseCheck):
    id = "GPO-007"
    name = "Partially Disabled GPOs"
    description = "Check for GPOs with only user or computer settings disabled"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        partial = [
            g for g in self.context.gpos
            if (g.get("user_disabled") or g.get("computer_disabled"))
            and not g.get("is_disabled")
        ]
        if partial and len(partial) > 10:
            return [self.finding(
                title=f"{len(partial)} GPOs have partially disabled settings",
                description="GPOs with partially disabled sections may indicate incomplete policy configurations or migration remnants.",
                severity=Severity.INFO,
                affected_count=len(partial),
                remediation_desc="Review partially disabled GPOs to ensure the configuration is intentional.",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO008_GPOSysvol(BaseCheck):
    id = "GPO-008"
    name = "GPO SYSVOL Path Validation"
    description = "Check for GPOs without SYSVOL paths"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        no_path = [g for g in self.context.gpos if not g.get("file_sys_path")]
        if no_path:
            return [self.finding(
                title=f"{len(no_path)} GPOs have no SYSVOL file system path",
                description="GPOs without a SYSVOL path cannot apply settings. This may indicate corruption or a replication issue.",
                severity=Severity.MEDIUM,
                affected_count=len(no_path),
                remediation_desc="Run gpotool or dcdiag to verify GPO health and SYSVOL replication.",
                powershell="dcdiag /test:sysvolcheck",
                nist_800_53=["CM-6"],
            )]
        return []
