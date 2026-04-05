"""Compliance framework mapping models."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class MitreAttack(BaseModel):
    """MITRE ATT&CK technique mapping."""

    technique_id: str  # e.g., "T1558.003"
    technique_name: str  # e.g., "Kerberoasting"
    tactic: str  # e.g., "Credential Access"
    url: str = ""

    def __str__(self) -> str:
        return f"{self.technique_id} - {self.technique_name}"


class ComplianceMapping(BaseModel):
    """Maps a finding to compliance framework controls."""

    mitre_attack: List[MitreAttack] = []
    cis_controls: List[str] = []  # e.g., ["5.2", "5.4"]
    nist_800_53: List[str] = []  # e.g., ["AC-2", "AC-6"]
    stig_rules: List[str] = []  # e.g., ["V-36435"]
    cis_benchmark: Optional[str] = None  # e.g., "CIS Microsoft Windows Server 2019 Benchmark v1.3.0 - 1.1.1"
