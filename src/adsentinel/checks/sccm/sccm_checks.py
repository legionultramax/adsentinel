"""SCCM/MECM Security checks (SCCM-001 to SCCM-005)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity


@check
class SCCM001_NAAExposure(BaseCheck):
    id = "SCCM-001"
    name = "SCCM Network Access Account"
    description = "Check for SCCM Network Access Account (NAA) in AD"
    category = "SCCM/MECM Security"

    def run(self) -> List[Finding]:
        # NAA accounts are often named sccm*, naa*, cm_*
        naa_candidates = [
            u for u in self.context.users
            if u.enabled and any(
                u.sam_account_name.lower().startswith(prefix)
                for prefix in ["sccm", "naa", "cm_", "mecm", "configmgr"]
            )
        ]
        if naa_candidates:
            return [self.finding(
                title=f"{len(naa_candidates)} potential SCCM NAA accounts detected",
                description=(
                    "SCCM Network Access Accounts (NAAs) store credentials on all SCCM clients "
                    "in a recoverable format (DPAPI-protected). An attacker with local admin on any "
                    "SCCM client can extract these credentials. If the NAA has excessive privileges, "
                    "this leads to lateral movement or privilege escalation."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_user(u) for u in naa_candidates],
                affected_count=len(naa_candidates),
                remediation_desc="Use Enhanced HTTP instead of NAA. If NAA is required, ensure it has minimal permissions (read-only to distribution points).",
                mitre=[MitreAttack(technique_id="T1003.005", technique_name="Cached Domain Credentials", tactic="Credential Access")],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class SCCM002_SCCMAdminGroup(BaseCheck):
    id = "SCCM-002"
    name = "SCCM Admin Group Membership"
    description = "Check for SCCM admin groups with excessive membership"
    category = "SCCM/MECM Security"

    def run(self) -> List[Finding]:
        sccm_groups = [
            g for g in self.context.groups
            if any(kw in g.sam_account_name.lower() for kw in ["sccm", "configmgr", "mecm"])
            and g.is_security_group
        ]
        large_sccm = [g for g in sccm_groups if len(g.member_dns) > 10]
        if large_sccm:
            return [self.finding(
                title=f"{len(large_sccm)} SCCM admin groups have excessive membership",
                description=(
                    "SCCM Full Administrators can deploy scripts to all managed systems, "
                    "effectively granting them local admin on every SCCM client. "
                    "This group should have minimal membership."
                ),
                severity=Severity.MEDIUM,
                affected_objects=[self.affected_group(g) for g in large_sccm],
                affected_count=len(large_sccm),
                remediation_desc="Review SCCM admin group membership. Apply least-privilege RBAC roles.",
                nist_800_53=["AC-6"],
            )]
        return []


@check
class SCCM003_SCCMServerHardening(BaseCheck):
    id = "SCCM-003"
    name = "SCCM Server Identification"
    description = "Identify SCCM servers for security review"
    category = "SCCM/MECM Security"

    def run(self) -> List[Finding]:
        sccm_servers = [
            c for c in self.context.computers
            if c.enabled and any(
                kw in (c.dns_hostname or "").lower() or kw in c.sam_account_name.lower()
                for kw in ["sccm", "configmgr", "mecm", "sms"]
            )
        ]
        if sccm_servers:
            return [self.finding(
                title=f"{len(sccm_servers)} potential SCCM/MECM servers identified",
                description="SCCM servers are Tier 0 assets — they can execute code on all managed clients. Ensure proper hardening.",
                severity=Severity.INFO,
                affected_objects=[self.affected_computer(c) for c in sccm_servers],
                affected_count=len(sccm_servers),
                remediation_desc="Treat SCCM servers as Tier 0. Restrict admin access. Enable Enhanced HTTP.",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class SCCM004_ClientPushInstall(BaseCheck):
    id = "SCCM-004"
    name = "SCCM Client Push Account"
    description = "Check for SCCM client push installation accounts"
    category = "SCCM/MECM Security"

    def run(self) -> List[Finding]:
        # Client push accounts often have local admin everywhere
        push_candidates = [
            u for u in self.context.users
            if u.enabled and any(
                kw in u.sam_account_name.lower()
                for kw in ["sccmpush", "clientpush", "ccmsetup", "sccminstall"]
            )
        ]
        if push_candidates:
            return [self.finding(
                title=f"{len(push_candidates)} potential SCCM client push accounts found",
                description=(
                    "SCCM client push installation accounts typically have local administrator "
                    "rights on all endpoints. Kerberoasting or compromising these accounts "
                    "grants widespread lateral movement."
                ),
                severity=Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in push_candidates],
                affected_count=len(push_candidates),
                remediation_desc="Use alternative deployment methods (GPO, Intune). If client push is required, rotate the password frequently.",
                mitre=[MitreAttack(technique_id="T1078.002", technique_name="Domain Accounts", tactic="Lateral Movement")],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class SCCM005_PXEAbuse(BaseCheck):
    id = "SCCM-005"
    name = "PXE Boot Security"
    description = "Check for PXE-related service accounts"
    category = "SCCM/MECM Security"

    def run(self) -> List[Finding]:
        pxe_indicators = [
            u for u in self.context.users
            if u.enabled and any(
                kw in u.sam_account_name.lower()
                for kw in ["pxe", "wds", "mdt", "osd"]
            )
        ]
        if pxe_indicators:
            return [self.finding(
                title=f"{len(pxe_indicators)} PXE/deployment service accounts found",
                description=(
                    "PXE boot environments can be abused to extract SCCM NAA credentials or "
                    "task sequence media secrets. Ensure PXE password protection is enabled "
                    "and certificates are used for media authentication."
                ),
                severity=Severity.LOW,
                affected_objects=[self.affected_user(u) for u in pxe_indicators],
                affected_count=len(pxe_indicators),
                remediation_desc="Enable PXE password requirement. Use certificate-based media authentication.",
                nist_800_53=["CM-6"],
            )]
        return []
