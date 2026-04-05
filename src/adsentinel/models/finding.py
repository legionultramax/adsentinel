"""Security finding model — the core output of every check."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from adsentinel.models.compliance import ComplianceMapping
from adsentinel.models.severity import Severity


class AffectedObject(BaseModel):
    """An AD object affected by a finding."""

    dn: str = ""
    sam_account_name: str = ""
    object_type: str = ""  # user, group, computer, gpo, template, etc.
    details: Dict[str, Any] = {}


class Remediation(BaseModel):
    """Remediation guidance for a finding."""

    description: str
    powershell_command: str = ""
    manual_steps: List[str] = []
    references: List[str] = []


class Finding(BaseModel):
    """A single security finding produced by a check."""

    id: str  # Unique ID: e.g., "PP-001", "KRB-003"
    title: str
    description: str
    severity: Severity
    category: str  # e.g., "Password Policy", "Kerberos Security"
    affected_objects: List[AffectedObject] = []
    affected_count: int = 0
    remediation: Remediation = Field(default_factory=lambda: Remediation(description=""))
    compliance: ComplianceMapping = Field(default_factory=ComplianceMapping)
    details: Dict[str, Any] = {}
    source: str = "LDAP"  # "LDAP" or "WinRM"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def mitre_ids(self) -> List[str]:
        """Shortcut to get MITRE ATT&CK technique IDs."""
        return [m.technique_id for m in self.compliance.mitre_attack]


class CheckResult(BaseModel):
    """Result of running a single check — may produce zero or more findings."""

    check_id: str
    check_name: str
    category: str
    findings: List[Finding] = []
    error: Optional[str] = None
    duration_ms: float = 0.0
    skipped: bool = False
    skip_reason: str = ""
