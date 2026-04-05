"""Trust Security checks (TR-001 to TR-008)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity


@check
class TR001_BidirectionalTrusts(BaseCheck):
    id = "TR-001"
    name = "Bidirectional Trusts"
    description = "Check for bidirectional trust relationships"
    category = "Trust Security"

    def run(self) -> List[Finding]:
        bidi = [t for t in self.context.trusts if t.trust_direction == 3]
        if bidi:
            return [self.finding(
                title=f"{len(bidi)} bidirectional trust relationships found",
                description="Bidirectional trusts allow authentication in both directions, increasing the attack surface.",
                severity=Severity.MEDIUM,
                affected_objects=[
                    AffectedObject(dn=t.dn, sam_account_name=t.trusted_domain, object_type="trust",
                                   details={"direction": t.direction_name})
                    for t in bidi
                ],
                affected_count=len(bidi),
                remediation_desc="Review if bidirectional trust is required. Consider one-way trusts where possible.",
                nist_800_53=["AC-20"],
            )]
        return []


@check
class TR002_SIDFilteringDisabled(BaseCheck):
    id = "TR-002"
    name = "SID Filtering"
    description = "Check if SID filtering is enabled on trusts"
    category = "Trust Security"

    def run(self) -> List[Finding]:
        no_filter = [t for t in self.context.trusts if not t.sid_filtering_enabled]
        if no_filter:
            return [self.finding(
                title=f"{len(no_filter)} trusts have SID filtering disabled",
                description=(
                    "SID filtering prevents SID history injection attacks across trust boundaries. "
                    "Without it, an admin in a trusted domain can forge SIDs to gain unauthorized access."
                ),
                severity=Severity.HIGH,
                affected_objects=[
                    AffectedObject(dn=t.dn, sam_account_name=t.trusted_domain, object_type="trust")
                    for t in no_filter
                ],
                affected_count=len(no_filter),
                remediation_desc="Enable SID filtering on all external trusts.",
                powershell="netdom trust /d:YOURDOMAIN TRUSTEDDOMAIN /EnableSIDHistory:no",
                mitre=[MitreAttack(technique_id="T1134.005", technique_name="SID-History Injection", tactic="Privilege Escalation")],
                nist_800_53=["AC-20"],
            )]
        return []


@check
class TR003_NoSelectiveAuth(BaseCheck):
    id = "TR-003"
    name = "Selective Authentication"
    description = "Check if selective authentication is used on trusts"
    category = "Trust Security"

    def run(self) -> List[Finding]:
        no_selective = [
            t for t in self.context.trusts
            if not t.selective_auth and not t.is_forest_trust
        ]
        if no_selective:
            return [self.finding(
                title=f"{len(no_selective)} trusts use forest-wide authentication (no selective auth)",
                description="Without selective authentication, all users in trusted domains can authenticate to all resources.",
                severity=Severity.LOW,
                affected_objects=[
                    AffectedObject(dn=t.dn, sam_account_name=t.trusted_domain, object_type="trust")
                    for t in no_selective
                ],
                affected_count=len(no_selective),
                remediation_desc="Enable selective authentication to restrict which users can authenticate across the trust.",
                powershell="Set-ADTrust -Identity 'TRUSTEDDOMAIN' -SelectiveAuthentication $true",
                nist_800_53=["AC-20"],
            )]
        return []


@check
class TR004_ForestTrustTransitive(BaseCheck):
    id = "TR-004"
    name = "Forest Trust Transitivity"
    description = "Check for transitive forest trusts"
    category = "Trust Security"

    def run(self) -> List[Finding]:
        forest_trusts = [t for t in self.context.trusts if t.is_forest_trust]
        if len(forest_trusts) > 1:
            return [self.finding(
                title=f"{len(forest_trusts)} forest trusts detected — check for transitive paths",
                description="Multiple forest trusts may create transitive authentication paths. An attacker in Forest A could potentially reach Forest C through Forest B.",
                severity=Severity.MEDIUM,
                affected_objects=[
                    AffectedObject(dn=t.dn, sam_account_name=t.trusted_domain, object_type="trust")
                    for t in forest_trusts
                ],
                affected_count=len(forest_trusts),
                remediation_desc="Review forest trust topology for unintended transitive paths.",
                nist_800_53=["AC-20"],
            )]
        return []


@check
class TR005_TrustToOldDomain(BaseCheck):
    id = "TR-005"
    name = "Trusts to External Domains"
    description = "Inventory all external trust relationships"
    category = "Trust Security"

    def run(self) -> List[Finding]:
        external = [t for t in self.context.trusts if t.trust_type == 1]  # Downlevel trust
        if external:
            return [self.finding(
                title=f"{len(external)} external (downlevel/NT4) trusts found",
                description="External trusts to downlevel domains use weaker authentication. These should be reviewed and removed if no longer needed.",
                severity=Severity.MEDIUM,
                affected_objects=[
                    AffectedObject(dn=t.dn, sam_account_name=t.trusted_domain, object_type="trust")
                    for t in external
                ],
                affected_count=len(external),
                remediation_desc="Review and remove unnecessary external trusts.",
                nist_800_53=["AC-20"],
            )]
        return []
