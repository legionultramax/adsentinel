"""Base check class and @check decorator — the foundation every check builds on."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Type

from adsentinel.logging_config import get_logger
from adsentinel.models.compliance import ComplianceMapping, MitreAttack
from adsentinel.models.finding import AffectedObject, CheckResult, Finding, Remediation
from adsentinel.models.severity import Severity

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)


class BaseCheck(ABC):
    """Abstract base class for all security checks.

    Every check must define:
        - id: Unique check ID (e.g., "PP-001")
        - name: Human-readable check name
        - category: Check category (e.g., "Password Policy")
        - run(): The check logic that returns a list of Findings
    """

    id: str = ""
    name: str = ""
    description: str = ""
    category: str = ""
    requires_winrm: bool = False

    def __init__(self, context: SharedContext) -> None:
        self.context = context
        self._findings: List[Finding] = []

    @abstractmethod
    def run(self) -> List[Finding]:
        """Execute the check and return findings."""

    def execute(self) -> CheckResult:
        """Execute the check with error handling and timing."""
        if self.requires_winrm and not self.context.has_winrm_data:
            logger.debug("check_skipped_no_winrm", check_id=self.id)
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                category=self.category,
                skipped=True,
                skip_reason="WinRM data not available",
            )

        start = time.monotonic()
        try:
            findings = self.run()
            duration = (time.monotonic() - start) * 1000
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                category=self.category,
                findings=findings,
                duration_ms=round(duration, 2),
            )
        except Exception as e:
            duration = (time.monotonic() - start) * 1000
            logger.error("check_failed", check_id=self.id, error=str(e))
            return CheckResult(
                check_id=self.id,
                check_name=self.name,
                category=self.category,
                error=str(e),
                duration_ms=round(duration, 2),
            )

    # ---- Helper methods for creating findings ----

    def finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        affected_objects: Optional[List[AffectedObject]] = None,
        affected_count: int = 0,
        remediation_desc: str = "",
        powershell: str = "",
        manual_steps: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
        mitre: Optional[List[MitreAttack]] = None,
        cis_controls: Optional[List[str]] = None,
        nist_800_53: Optional[List[str]] = None,
        stig_rules: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
        source: str = "LDAP",
    ) -> Finding:
        """Create a Finding with all metadata populated."""
        return Finding(
            id=self.id,
            title=title,
            description=description,
            severity=severity,
            category=self.category,
            affected_objects=affected_objects or [],
            affected_count=affected_count if affected_count != 0 else len(affected_objects or []),
            remediation=Remediation(
                description=remediation_desc,
                powershell_command=powershell,
                manual_steps=manual_steps or [],
                references=references or [],
            ),
            compliance=ComplianceMapping(
                mitre_attack=mitre or [],
                cis_controls=cis_controls or [],
                nist_800_53=nist_800_53 or [],
                stig_rules=stig_rules or [],
            ),
            details=details or {},
            source=source,
        )

    def affected_user(self, user: Any) -> AffectedObject:
        """Create an AffectedObject from an ADUser."""
        return AffectedObject(
            dn=user.dn,
            sam_account_name=user.sam_account_name,
            object_type="user",
        )

    def affected_group(self, group: Any) -> AffectedObject:
        """Create an AffectedObject from an ADGroup."""
        return AffectedObject(
            dn=group.dn,
            sam_account_name=group.sam_account_name,
            object_type="group",
        )

    def affected_computer(self, computer: Any) -> AffectedObject:
        """Create an AffectedObject from an ADComputer."""
        return AffectedObject(
            dn=computer.dn,
            sam_account_name=computer.sam_account_name,
            object_type="computer",
        )


def check(cls: Type[BaseCheck]) -> Type[BaseCheck]:
    """Decorator that registers a check class in the global CheckRegistry."""
    from adsentinel.checks.registry import CheckRegistry
    CheckRegistry.register(cls)
    return cls
