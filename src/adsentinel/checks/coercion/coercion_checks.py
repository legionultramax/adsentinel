"""Coercion Attack checks (COER-001 to COER-008)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import MITRE_FORCED_AUTH
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity
from adsentinel.utils import safe_int

_MITRE_COERCE = [MitreAttack(
    technique_id=MITRE_FORCED_AUTH,
    technique_name="Forced Authentication",
    tactic="Credential Access",
)]


@check
class COER001_PrintSpooler(BaseCheck):
    id = "COER-001"
    name = "PrinterBug / SpoolSample"
    description = "Check if Print Spooler enables coercion attacks on DCs"
    category = "Coercion Attacks"
    requires_winrm = True

    def run(self) -> List[Finding]:
        spooler = self.context.service_statuses.get("Spooler", "")
        if spooler and spooler.lower() == "running":
            return [self.finding(
                title="Print Spooler running — SpoolSample/PrinterBug coercion possible",
                description=(
                    "The Print Spooler service enables the PrinterBug (SpoolSample) attack. "
                    "An attacker can force the DC to authenticate to an attacker-controlled server "
                    "using MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx, "
                    "enabling NTLM relay to AD CS (ESC8) or unconstrained delegation abuse."
                ),
                severity=Severity.HIGH,
                remediation_desc="Disable the Print Spooler service on all domain controllers.",
                powershell="Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled",
                mitre=_MITRE_COERCE,
                nist_800_53=["CM-7"],
                source="WinRM",
            )]
        return []


@check
class COER002_PetitPotam(BaseCheck):
    id = "COER-002"
    name = "PetitPotam (EFS-RPC)"
    description = "Check if EFS RPC coercion mitigation is in place"
    category = "Coercion Attacks"
    requires_winrm = True

    def run(self) -> List[Finding]:
        # PetitPotam uses MS-EFSRPC. Mitigation is disabling EFS or applying KB5005413
        efs_svc = self.context.service_statuses.get("EFS", "")
        # If no explicit mitigation detected, warn
        if not efs_svc or efs_svc.lower() != "disabled":
            return [self.finding(
                title="PetitPotam (EFS-RPC) coercion may be possible",
                description=(
                    "PetitPotam uses MS-EFSRPC (EfsRpcOpenFileRaw) to coerce DC authentication. "
                    "Combined with NTLM relay to AD CS, this is a full domain compromise path. "
                    "Ensure KB5005413+ patches are applied and consider disabling EFS on DCs."
                ),
                severity=Severity.HIGH,
                remediation_desc="Apply latest Windows updates (KB5005413+). Disable NTLM on DCs or enforce EPA on AD CS.",
                mitre=_MITRE_COERCE,
                nist_800_53=["SI-2", "CM-7"],
                source="WinRM",
            )]
        return []


@check
class COER003_DFSCoerce(BaseCheck):
    id = "COER-003"
    name = "DFSCoerce (MS-DFSNM)"
    description = "Check if DFS Namespace service enables coercion"
    category = "Coercion Attacks"
    requires_winrm = True

    def run(self) -> List[Finding]:
        dfs = self.context.service_statuses.get("Dfs", "")
        if dfs and dfs.lower() == "running":
            return [self.finding(
                title="DFS Namespace service running — DFSCoerce coercion possible",
                description=(
                    "DFSCoerce uses MS-DFSNM NetrDfsRemoveStdRoot to coerce DC authentication. "
                    "Like PetitPotam, this enables NTLM relay attacks."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Apply latest patches. Consider RPC firewall rules for MS-DFSNM.",
                mitre=_MITRE_COERCE,
                nist_800_53=["CM-7"],
                source="WinRM",
            )]
        return []


@check
class COER004_ShadowCredentials(BaseCheck):
    id = "COER-004"
    name = "Shadow Credentials Attack Surface"
    description = "Check for accounts with msDS-KeyCredentialLink set"
    category = "Coercion Attacks"

    def run(self) -> List[Finding]:
        shadow_users = [
            u for u in self.context.users
            if u.enabled and u.ms_ds_key_credential_link
        ]
        shadow_comps = [
            c for c in self.context.computers
            if c.enabled and c.ms_ds_key_credential_link
        ]
        total = len(shadow_users) + len(shadow_comps)
        if total > 0:
            return [self.finding(
                title=f"Shadow Credentials: {total} objects have msDS-KeyCredentialLink populated",
                description=(
                    "msDS-KeyCredentialLink enables PKINIT pre-authentication via WHfB keys. "
                    "If an attacker can write to this attribute (via GenericWrite/GenericAll), "
                    "they can add their own key and authenticate as the target — no password needed."
                ),
                severity=Severity.MEDIUM if total < 10 else Severity.HIGH,
                affected_objects=[self.affected_user(u) for u in shadow_users[:25]] + [self.affected_computer(c) for c in shadow_comps[:25]],
                affected_count=total,
                remediation_desc="Audit who can write msDS-KeyCredentialLink on sensitive accounts. Remove unauthorized entries.",
                mitre=[MitreAttack(technique_id="T1556.007", technique_name="Hybrid Identity", tactic="Credential Access")],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class COER005_WebClient(BaseCheck):
    id = "COER-005"
    name = "WebClient Service"
    description = "Check if WebClient service enables WebDAV coercion"
    category = "Coercion Attacks"
    requires_winrm = True

    def run(self) -> List[Finding]:
        wc = self.context.service_statuses.get("WebClient", "")
        if wc and wc.lower() == "running":
            return [self.finding(
                title="WebClient service running — WebDAV coercion possible",
                description=(
                    "The WebClient service enables HTTP-based authentication coercion via WebDAV. "
                    "This allows attackers to coerce authentication over HTTP (not SMB), "
                    "bypassing SMB signing requirements for relay attacks."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Disable WebClient service on servers and domain controllers.",
                powershell="Stop-Service -Name WebClient -Force; Set-Service -Name WebClient -StartupType Disabled",
                mitre=_MITRE_COERCE,
                nist_800_53=["CM-7"],
                source="WinRM",
            )]
        return []


@check
class COER006_UnconstrainedDelegCoerce(BaseCheck):
    id = "COER-006"
    name = "Unconstrained Delegation + Coercion"
    description = "Check if unconstrained delegation servers can capture TGTs via coercion"
    category = "Coercion Attacks"

    def run(self) -> List[Finding]:
        unconst_comps = [
            c for c in self.context.computers
            if c.enabled and c.trusted_for_delegation
        ]
        dc_hostnames = {
            dc.hostname.lower() for dc in self.context.domain_info.domain_controllers
            if dc.hostname
        }
        # Exclude DCs (they always have unconstrained delegation)
        non_dc_unconst = [
            c for c in unconst_comps
            if c.dns_hostname and c.dns_hostname.lower() not in dc_hostnames
        ]
        if non_dc_unconst:
            return [self.finding(
                title=f"{len(non_dc_unconst)} non-DC computers with unconstrained delegation — TGT capture via coercion",
                description=(
                    "Non-DC servers with unconstrained delegation will cache TGTs from incoming authentications. "
                    "Combined with coercion attacks (PrinterBug, PetitPotam), an attacker can force a DC to "
                    "authenticate and capture its TGT for a full domain compromise."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[self.affected_computer(c) for c in non_dc_unconst],
                affected_count=len(non_dc_unconst),
                remediation_desc="Remove unconstrained delegation from all non-DC servers. Use constrained delegation or RBCD.",
                mitre=[MitreAttack(technique_id="T1558", technique_name="Steal or Forge Kerberos Tickets", tactic="Credential Access")],
                nist_800_53=["AC-6"],
            )]
        return []


@check
class COER007_NTLMRelayMitigation(BaseCheck):
    id = "COER-007"
    name = "NTLM Relay Mitigations"
    description = "Check if key NTLM relay protections are in place"
    category = "Coercion Attacks"
    requires_winrm = True

    def run(self) -> List[Finding]:
        issues = []
        smb = self.context.smb_config
        if smb and not smb.get("RequireSecuritySignature", True):
            issues.append("SMB signing not required")

        ldap_signing = safe_int(self.context.registry_values.get("LDAPServerIntegrity", ""))
        if ldap_signing is not None and ldap_signing < 2:
            issues.append("LDAP signing not required")

        cb = safe_int(self.context.registry_values.get("LdapEnforceChannelBinding", ""))
        if cb is not None and cb < 2:
            issues.append("LDAP channel binding not enforced")

        if issues:
            return [self.finding(
                title=f"NTLM relay protections incomplete: {len(issues)} gaps",
                description=(
                    f"Missing protections: {', '.join(issues)}. "
                    "These gaps enable NTLM relay attacks when combined with coercion techniques."
                ),
                severity=Severity.HIGH,
                remediation_desc="Enable SMB signing, LDAP signing, and LDAP channel binding.",
                nist_800_53=["SC-8"],
                source="WinRM",
                details={"missing_protections": issues},
            )]
        return []


@check
class COER008_RBCDAbuse(BaseCheck):
    id = "COER-008"
    name = "RBCD Abuse Potential"
    description = "Check if MAQ + RBCD enables privilege escalation"
    category = "Coercion Attacks"

    def run(self) -> List[Finding]:
        maq = self.context.domain_info.machine_account_quota
        rbcd_comps = [c for c in self.context.computers if c.ms_ds_allowed_to_act_on_behalf]
        if maq > 0 and rbcd_comps:
            return [self.finding(
                title=f"RBCD abuse path: MAQ={maq} + {len(rbcd_comps)} computers with RBCD configured",
                description=(
                    "With a non-zero Machine Account Quota, any user can create a computer account. "
                    "Combined with write access to msDS-AllowedToActOnBehalfOfOtherIdentity, "
                    "this enables S4U2Self/S4U2Proxy delegation abuse for privilege escalation."
                ),
                severity=Severity.HIGH,
                affected_objects=[self.affected_computer(c) for c in rbcd_comps[:20]],
                affected_count=len(rbcd_comps),
                remediation_desc="Set MAQ to 0. Audit RBCD configurations.",
                mitre=[MitreAttack(technique_id="T1550.003", technique_name="Pass the Ticket", tactic="Lateral Movement")],
                nist_800_53=["AC-6"],
            )]
        return []
