"""Replication Security checks (REP-001 to REP-006)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import MITRE_DCSYNC
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity
from adsentinel.utils.time_utils import days_since


@check
class REP001_DCCount(BaseCheck):
    id = "REP-001"
    name = "Domain Controller Count"
    description = "Check domain controller count and configuration"
    category = "Replication Security"

    def run(self) -> List[Finding]:
        dcs = self.context.domain_info.domain_controllers
        if len(dcs) < 2:
            return [self.finding(
                title="Only 1 domain controller detected — no redundancy",
                description="A single domain controller means no fault tolerance. If it fails, the entire domain is unavailable.",
                severity=Severity.HIGH,
                remediation_desc="Deploy at least 2 domain controllers for redundancy.",
                nist_800_53=["CP-6"],
            )]
        return []


@check
class REP002_RODCUsage(BaseCheck):
    id = "REP-002"
    name = "Read-Only Domain Controllers"
    description = "Check RODC deployment status"
    category = "Replication Security"

    def run(self) -> List[Finding]:
        rodcs = [dc for dc in self.context.domain_info.domain_controllers if dc.is_read_only]
        total_dcs = len(self.context.domain_info.domain_controllers)
        if rodcs and len(rodcs) == total_dcs:
            return [self.finding(
                title="All domain controllers are read-only (RODC)",
                description="All DCs are RODCs. At least one writable DC is required for AD modifications.",
                severity=Severity.HIGH,
                remediation_desc="Ensure at least one writable domain controller exists.",
                nist_800_53=["CP-6"],
            )]
        return []


@check
class REP003_StaleDCPasswords(BaseCheck):
    id = "REP-003"
    name = "DC Computer Account Passwords"
    description = "Check domain controller computer account password age"
    category = "Replication Security"

    def run(self) -> List[Finding]:
        stale_dcs = []
        # Build sets of both short hostnames and FQDNs for matching
        dc_hostnames = set()
        for dc in self.context.domain_info.domain_controllers:
            if dc.hostname:
                dc_hostnames.add(dc.hostname.lower())
                # Also add FQDN form if hostname doesn't contain a dot
                if "." not in dc.hostname and self.context.domain_info.dns_name:
                    dc_hostnames.add(f"{dc.hostname.lower()}.{self.context.domain_info.dns_name.lower()}")
        for comp in self.context.computers:
            if comp.dns_hostname and comp.dns_hostname.lower() in dc_hostnames:
                age = days_since(comp.password_last_set)
                if age > 60:
                    stale_dcs.append(comp)

        if stale_dcs:
            return [self.finding(
                title=f"{len(stale_dcs)} DC computer accounts have passwords older than 60 days",
                description="Domain controller machine passwords should rotate automatically every 30 days. Old passwords may indicate replication or service issues.",
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_computer(c) for c in stale_dcs],
                affected_count=len(stale_dcs),
                remediation_desc="Investigate DC replication health and machine password rotation.",
                powershell="Get-ADDomainController -Filter * | Select-Object Name, @{N='PwdAge';E={(New-TimeSpan $_.PasswordLastSet (Get-Date)).Days}}",
                nist_800_53=["IA-5"],
            )]
        return []


@check
class REP004_DCOSVersions(BaseCheck):
    id = "REP-004"
    name = "DC Operating System Consistency"
    description = "Check for mixed OS versions across domain controllers"
    category = "Replication Security"

    def run(self) -> List[Finding]:
        dcs = self.context.domain_info.domain_controllers
        os_versions = {dc.os_version for dc in dcs if dc.os_version}
        if len(os_versions) > 2:
            return [self.finding(
                title=f"Domain controllers run {len(os_versions)} different OS versions",
                description=f"OS versions: {', '.join(os_versions)}. Mixed DC OS versions can cause compatibility issues.",
                severity=Severity.LOW,
                remediation_desc="Standardize DC operating system versions.",
                details={"os_versions": list(os_versions)},
                nist_800_53=["CM-6"],
            )]
        return []


@check
class REP005_TombstoneLifetime(BaseCheck):
    id = "REP-005"
    name = "Tombstone Lifetime"
    description = "Check AD tombstone lifetime configuration"
    category = "Replication Security"

    def run(self) -> List[Finding]:
        tsl = self.context.domain_info.tombstone_lifetime
        if tsl < 180:
            return [self.finding(
                title=f"Tombstone lifetime is {tsl} days (recommended: 180+)",
                description="Short tombstone lifetime reduces the window for recovering deleted objects and can cause replication issues with offline DCs.",
                severity=Severity.LOW,
                remediation_desc="Increase tombstone lifetime to at least 180 days.",
                powershell="Set-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=com' -Replace @{tombstoneLifetime=180}",
                nist_800_53=["CP-9"],
            )]
        return []
