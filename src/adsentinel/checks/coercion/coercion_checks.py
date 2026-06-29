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
        # EFS service status is NOT a reliable PetitPotam mitigation signal.
        # MS-EFSRPC is an RPC endpoint — disabling the EFS *service* does not block
        # EfsRpcOpenFileRaw or other authenticated EFSRPC methods on unpatched DCs.
        # The real mitigations are: KB5005413+ (patches the RPC handler) + EPA on AD CS.
        # We check EFS service only to set severity: Disabled → MEDIUM (one vector reduced),
        # Running/unknown → HIGH (full attack surface exposed).
        efs_svc = self.context.service_statuses.get("EFS", "")
        efs_disabled = efs_svc.lower() == "disabled"

        if efs_disabled:
            title = "PetitPotam partially mitigated — EFS service disabled but RPC endpoint may remain"
            description = (
                "The EFS service is disabled on this DC, which blocks the primary PetitPotam "
                "vector (EfsRpcOpenFileRaw). However, MS-EFSRPC is an RPC endpoint registered "
                "independently of the EFS service on unpatched Windows versions. Other EFSRPC "
                "methods may still be reachable. Confirm KB5005413 or later is installed and "
                "enforce EPA on AD CS to fully neutralise this coercion path."
            )
            severity = Severity.MEDIUM
        else:
            title = "PetitPotam (EFS-RPC) coercion path is open"
            description = (
                "The EFS service is running (or status could not be determined). PetitPotam "
                "abuses MS-EFSRPC to coerce DC authentication without any credentials. Combined "
                "with NTLM relay to AD CS (ESC8), this is a single-step domain compromise: "
                "attacker → coerce DC → relay to CA → issue DC certificate → DCSync. "
                "Apply KB5005413+ and enforce Extended Protection for Authentication (EPA) on "
                "all AD CS HTTP endpoints."
            )
            severity = Severity.HIGH

        return [self.finding(
            title=title,
            description=description,
            severity=severity,
            remediation_desc=(
                "1. Apply KB5005413 or the latest cumulative update on all DCs. "
                "2. Enforce EPA on IIS hosting AD CS (Certificate Authority Web Enrollment, "
                "Certificate Enrollment Web Service). "
                "3. Disable NTLM authentication on DCs if operationally feasible. "
                "4. Disable the EFS service on DCs that do not use file encryption."
            ),
            powershell=(
                "# Check patch status:\n"
                "Get-HotFix | Where-Object {$_.HotFixID -like 'KB50054*'}\n\n"
                "# Check EFS service:\n"
                "Get-Service EFS | Select-Object Name, Status, StartType"
            ),
            mitre=_MITRE_COERCE,
            nist_800_53=["SI-2", "CM-7"],
            details={"efs_service_status": efs_svc or "unknown"},
            source="WinRM",
        )]


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


@check
class COER009_LLMNR(BaseCheck):
    id = "COER-009"
    name = "LLMNR Enabled (Poisoning Vector)"
    description = "Check if LLMNR is disabled via Group Policy"
    category = "Coercion Attacks"
    requires_winrm = True

    def run(self) -> List[Finding]:
        # Key is only present when the policy is explicitly set.
        # Absent = LLMNR is ON (Windows default). Value "0" = disabled (safe). Value "1" = explicitly ON.
        raw = self.context.registry_values.get("LLMNREnabled")

        if raw is not None and raw.strip() == "0":
            return []  # Explicitly disabled via policy — clean

        # Either absent (default-on) or explicitly set to 1
        state = "explicitly enabled via policy" if raw == "1" else "enabled by default (policy key absent)"
        return [self.finding(
            title=f"LLMNR is {state} — name poisoning attacks possible",
            description=(
                "Link-Local Multicast Name Resolution (LLMNR) responds to name queries on the local "
                "subnet when DNS fails. Attackers running Responder or Inveigh can answer these "
                "broadcast queries and capture NTLMv2 hashes from any machine that falls through to "
                "LLMNR — which is every machine by default. The hashes can be cracked offline or "
                "relayed to SMB/LDAP for lateral movement and privilege escalation.\n\n"
                "LLMNR poisoning is the #1 finding in almost every internal penetration test. "
                "The fix is a single Group Policy setting."
            ),
            severity=Severity.HIGH,
            remediation_desc=(
                "Disable LLMNR via Group Policy: "
                "Computer Configuration > Administrative Templates > Network > DNS Client > "
                "Turn OFF Multicast Name Resolution = Enabled. "
                "Apply to all OUs, especially workstations and servers."
            ),
            powershell=(
                "# Verify current state (run on DC):\n"
                "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
                "-Name EnableMulticast -ErrorAction SilentlyContinue\n\n"
                "# Disable directly on one machine (GPO is the right fix for the domain):\n"
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
                "-Name EnableMulticast -Value 0 -Type DWord -Force"
            ),
            manual_steps=[
                "Open Group Policy Management Console (gpmc.msc).",
                "Edit or create a GPO linked to the domain or all OUs.",
                "Navigate to: Computer Configuration > Policies > Administrative Templates > "
                "Network > DNS Client.",
                "Set 'Turn OFF Multicast Name Resolution' to Enabled.",
                "Run gpupdate /force on all machines or wait for refresh.",
                "Verify with: Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient'",
            ],
            mitre=[MitreAttack(
                technique_id="T1557.001",
                technique_name="LLMNR/NBT-NS Poisoning and SMB Relay",
                tactic="Credential Access",
            )],
            cis_controls=["4.8", "9.2"],
            nist_800_53=["CM-7", "SC-20"],
            source="WinRM",
            details={"registry_value": raw, "policy_state": state},
        )]


@check
class COER010_NBTNSPoisoning(BaseCheck):
    id = "COER-010"
    name = "NBT-NS Enabled (Poisoning Vector)"
    description = "Check if NetBIOS Name Service broadcast (NBT-NS) is disabled"
    category = "Coercion Attacks"
    requires_winrm = True

    # NodeType=2 (P-node) disables NetBIOS broadcast — all other values leave it active.
    # NodeType values: 1=B-node (broadcast), 2=P-node (point-to-point, no broadcast),
    #                  4=M-node (mixed), 8=H-node (hybrid, MS default)
    _SAFE_NODE_TYPE = 2

    def run(self) -> List[Finding]:
        raw = self.context.registry_values.get("NetBTNodeType")

        if raw is not None:
            try:
                node_type = int(raw.strip())
                if node_type == self._SAFE_NODE_TYPE:
                    return []  # P-node: no NBT-NS broadcast — clean
            except ValueError:
                pass

        node_desc = (
            f"NodeType={raw} (broadcast-capable)" if raw is not None
            else "NodeType absent (Windows default H-node, broadcast-capable)"
        )
        return [self.finding(
            title=f"NBT-NS is active — {node_desc}",
            description=(
                "NetBIOS Name Service (NBT-NS) is a legacy name resolution protocol that broadcasts "
                "queries over UDP/137 when DNS fails. Like LLMNR, it allows Responder/Inveigh to "
                "intercept name resolution requests and capture NTLMv2 hashes from any machine on "
                "the subnet. NBT-NS and LLMNR together are the most reliable credential capture "
                "vector in internal assessments — both must be disabled.\n\n"
                "Setting NodeType=2 (P-node) prevents the broadcast entirely. "
                "The DHCP option 001 (vendor class 'Microsoft Windows') can push this domain-wide."
            ),
            severity=Severity.HIGH,
            remediation_desc=(
                "Set NodeType=2 (P-node) via DHCP Option 001 (Microsoft vendor class) or registry: "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\NodeType = 2. "
                "Alternatively, disable NetBIOS over TCP/IP per-adapter via GPO startup script."
            ),
            powershell=(
                "# Check current NodeType on all DCs:\n"
                "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters' "
                "-Name NodeType -ErrorAction SilentlyContinue\n\n"
                "# Set P-node (disable NBT-NS broadcast) on local machine:\n"
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters' "
                "-Name NodeType -Value 2 -Type DWord -Force\n\n"
                "# Disable NetBIOS over TCP/IP on all adapters via WMI:\n"
                "$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'\n"
                "$adapters | ForEach-Object { $_.SetTcpipNetbios(2) }"
            ),
            manual_steps=[
                "Configure DHCP Option 046 (NetBIOS over TCP/IP Node Type) to value 0x2 (P-node) "
                "in DHCP server for the Microsoft vendor class.",
                "Or set HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\NodeType=2 via GPO.",
                "Verify: Get-ItemProperty HKLM:\\SYSTEM\\...\\NetBT\\Parameters | Select NodeType",
                "Reboot or restart NetBT-dependent services after the change.",
            ],
            mitre=[MitreAttack(
                technique_id="T1557.001",
                technique_name="LLMNR/NBT-NS Poisoning and SMB Relay",
                tactic="Credential Access",
            )],
            cis_controls=["4.8", "9.2"],
            nist_800_53=["CM-7", "SC-20"],
            source="WinRM",
            details={"registry_value": raw, "node_type_desc": node_desc},
        )]
