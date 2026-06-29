"""WINRM-001 — WinRM coverage gap warning.

When WinRM is unavailable, a significant portion of checks are silently skipped.
This check surfaces that gap as an explicit HIGH finding so it always appears in the
report, making the assessment scope limitations visible to both the analyst and the client.
"""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity


@check
class WINRM001_CoverageGap(BaseCheck):
    id = "WINRM-001"
    name = "WinRM Assessment Coverage Gap"
    description = (
        "Detect when WinRM is unavailable and enumerate all checks that were silently skipped, "
        "ensuring the report reflects actual assessment scope."
    )
    category = "Operational Security"
    requires_winrm = False  # Must always run — that's the whole point

    def run(self) -> List[Finding]:
        if self.context.has_winrm_data:
            return []

        # Enumerate every registered check that requires WinRM
        from adsentinel.checks.registry import CheckRegistry
        skipped = sorted(
            cls.id
            for cls in CheckRegistry.get_all_checks()
            if getattr(cls, "requires_winrm", False)
        )

        if not skipped:
            return []

        skipped_summary = ", ".join(skipped)
        skipped_categories: List[str] = sorted({
            cls.category
            for cls in CheckRegistry.get_all_checks()
            if getattr(cls, "requires_winrm", False)
        })

        return [self.finding(
            title=(
                f"WinRM unavailable — {len(skipped)} checks skipped across "
                f"{len(skipped_categories)} categories"
            ),
            description=(
                "WinRM (Windows Remote Management) was not available during this assessment. "
                "WinRM-gated checks cover the most exploited attack vectors against domain controllers "
                "and cannot be evaluated via LDAP alone.\n\n"
                "Skipped categories: " + ", ".join(skipped_categories) + "\n\n"
                "Skipped check IDs: " + skipped_summary + "\n\n"
                "Critical checks that could not run include:\n"
                "  • AUTH-013: LSA Protection / RunAsPPL (LSASS dump prevention)\n"
                "  • AUTH-008: Credential Guard (VBS-isolated credential storage)\n"
                "  • AUTH-001: NTLMv1 (trivially crackable authentication)\n"
                "  • AUTH-002: WDigest (cleartext passwords in LSASS memory)\n"
                "  • COER-001: Print Spooler on DCs (SpoolSample/PrinterBug coercion)\n"
                "  • COER-002: PetitPotam / EFS-RPC coercion vector\n"
                "  • OPS-003: PowerShell Script Block Logging\n"
                "  • GPO-009: GPP cpassword in SYSVOL (MS14-025 — trivially decryptable)\n"
                "  • DNS-001 through DNS-005: DNS zone and configuration security"
            ),
            severity=Severity.HIGH,
            remediation_desc=(
                "Enable WinRM on the domain controller and re-run the assessment with WinRM access "
                "to obtain complete coverage. "
                "Quick enable: winrm quickconfig -quiet (run as Administrator on the DC). "
                "Ensure the scanning host can reach TCP 5985 (HTTP) or 5986 (HTTPS) on the DC."
            ),
            powershell=(
                "# On the target DC — enable WinRM:\n"
                "winrm quickconfig -quiet\n"
                "# Or via GPO: Computer Configuration > Windows Settings > Security Settings >\n"
                "#   System Services > Windows Remote Management (WS-Management) > Automatic\n\n"
                "# Verify from scanning host:\n"
                "Test-WSMan -ComputerName <DC_HOSTNAME>"
            ),
            manual_steps=[
                "Enable WinRM on all domain controllers.",
                "Ensure firewall rules allow WinRM from the scanning host (TCP 5985/5986).",
                "Re-run adsentinel with --winrm (or without --no-winrm) to complete the assessment.",
                "Treat WinRM-gated findings as unverified — assume worst-case (vulnerable) for reporting.",
            ],
            mitre=[MitreAttack(
                technique_id="T1003.001",
                technique_name="LSASS Memory",
                tactic="Credential Access",
            )],
            nist_800_53=["CA-7", "RA-5"],
            details={
                "skipped_check_count": len(skipped),
                "skipped_categories": skipped_categories,
                "skipped_check_ids": skipped,
            },
        )]
