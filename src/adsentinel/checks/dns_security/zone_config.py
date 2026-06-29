"""DNS Security checks (DNS-001 to DNS-006).

DNS-006: IPv6 enabled on Domain Controllers (mitm6 attack vector).
"""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity
from adsentinel.utils import safe_int


@check
class DNS001_ZoneTransfer(BaseCheck):
    id = "DNS-001"
    name = "DNS Zone Transfer Restrictions"
    description = "Check if DNS zone transfers are restricted"
    category = "DNS Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        zone_xfer = self.context.registry_values.get("SecureResponses", "")
        # Zone transfers should be restricted to authorized servers
        if self.context.dns_zones and not zone_xfer:
            return [self.finding(
                title="DNS zone transfer restrictions not verified",
                description="Unable to verify DNS zone transfer restrictions. Unrestricted zone transfers expose the entire DNS namespace to attackers.",
                severity=Severity.MEDIUM,
                remediation_desc="Restrict DNS zone transfers to authorized name servers only.",
                powershell="Get-DnsServerZone | Set-DnsServerZoneTransferPolicy -AllowedSecondary 'NameServers'",
                mitre=[MitreAttack(technique_id="T1590.002", technique_name="DNS", tactic="Reconnaissance")],
                nist_800_53=["SC-20"],
                source="WinRM",
            )]
        return []


@check
class DNS002_DynamicUpdates(BaseCheck):
    id = "DNS-002"
    name = "DNS Dynamic Updates"
    description = "Check DNS dynamic update security"
    category = "DNS Security"

    def run(self) -> List[Finding]:
        # AD-integrated zones should use secure-only dynamic updates
        if self.context.dns_zones:
            return [self.finding(
                title=f"{len(self.context.dns_zones)} DNS zones found — verify secure-only dynamic updates",
                description="AD-integrated DNS zones should be configured for 'Secure only' dynamic updates to prevent unauthorized DNS record modification.",
                severity=Severity.INFO,
                remediation_desc="Set all AD-integrated zones to 'Secure only' dynamic updates.",
                powershell="Get-DnsServerZone | Where-Object {$_.DynamicUpdate -ne 'Secure'} | Set-DnsServerZone -DynamicUpdate Secure",
                nist_800_53=["SC-20"],
                details={"zone_count": len(self.context.dns_zones)},
            )]
        return []


@check
class DNS003_WPADRecord(BaseCheck):
    id = "DNS-003"
    name = "WPAD DNS Record"
    description = "Check for WPAD DNS record that could enable NTLM relay"
    category = "DNS Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        # Check if WPAD is in the Global Query Block List
        wpad_blocked = self.context.registry_values.get("GlobalQueryBlockList", "")
        # Flag if: (1) block list exists but WPAD is not in it, OR (2) no block list data at all
        if not wpad_blocked or "wpad" not in wpad_blocked.lower():
            return [self.finding(
                title="WPAD is not in the DNS Global Query Block List",
                description=(
                    "WPAD (Web Proxy Auto-Discovery) is not blocked in DNS. Attackers can register "
                    "a WPAD record to intercept proxy configuration requests and perform NTLM relay attacks."
                ),
                severity=Severity.HIGH,
                remediation_desc="Add WPAD to the DNS Global Query Block List.",
                powershell="Set-DnsServerGlobalQueryBlockList -List 'wpad','isatap' -Enable $true",
                mitre=[MitreAttack(technique_id="T1557.001", technique_name="LLMNR/NBT-NS Poisoning", tactic="Credential Access")],
                nist_800_53=["SC-20"],
                source="WinRM",
            )]
        return []


@check
class DNS004_Scavenging(BaseCheck):
    id = "DNS-004"
    name = "DNS Scavenging"
    description = "Check if DNS scavenging is enabled"
    category = "DNS Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        scavenging = safe_int(self.context.registry_values.get("ScavengingInterval", ""))
        if scavenging is not None and scavenging == 0:
            return [self.finding(
                title="DNS scavenging is not enabled",
                description="Without scavenging, stale DNS records accumulate, creating a larger attack surface for DNS spoofing.",
                severity=Severity.LOW,
                remediation_desc="Enable DNS scavenging with appropriate no-refresh and refresh intervals.",
                powershell="Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00",
                nist_800_53=["CM-6"],
                source="WinRM",
            )]
        return []


@check
class DNS005_DangerousRecords(BaseCheck):
    id = "DNS-005"
    name = "Wildcard DNS Records"
    description = "Check for wildcard DNS records that could redirect traffic"
    category = "DNS Security"

    def run(self) -> List[Finding]:
        # Wildcard records in AD zones can redirect all unmatched queries
        for zone in self.context.dns_zones:
            name = zone.get("name", "")
            if name == "*" or name.startswith("*."):
                return [self.finding(
                    title="Wildcard DNS record found",
                    description="Wildcard DNS records redirect all unmatched queries, potentially enabling traffic interception.",
                    severity=Severity.MEDIUM,
                    remediation_desc="Remove wildcard DNS records unless explicitly required.",
                    nist_800_53=["SC-20"],
                )]
        return []


@check
class DNS006_IPv6EnabledOnDCs(BaseCheck):
    id = "DNS-006"
    name = "IPv6 Enabled on Domain Controllers (mitm6 Vector)"
    description = (
        "IPv6 is enabled by default on all modern Windows servers. When DHCPv6 is not "
        "actively used, attackers can run mitm6 to win DHCPv6 negotiations, redirect DNS "
        "queries, and relay authentication (NTLM/Kerberos) to seize domain resources. "
        "If IPv6 is not needed, disabling it removes this entire attack surface."
    )
    category = "DNS Security"
    requires_winrm = True

    # DisabledComponents bitmask (HKLM\...\Tcpip6\Parameters):
    #   bit 0 (0x01) — disable IPv6 on all non-tunnel interfaces
    #   bit 1 (0x02) — disable IPv6 on all tunnel interfaces
    #   0xFF (255)   — fully disable IPv6 (recommended hardening value)
    # If bit 0 is NOT set, at least one network interface accepts IPv6 traffic.
    _SAFE_MASK = 0x01

    def run(self) -> List[Finding]:
        raw = self.context.registry_values.get("IPv6DisabledComponents")

        if raw is not None:
            val = safe_int(raw)
            if val is not None and (val & self._SAFE_MASK):
                return []  # IPv6 disabled on all non-tunnel interfaces — clean

        val_int = safe_int(raw) if raw is not None else None
        if raw is None:
            state = "IPv6 is enabled by default (DisabledComponents registry key is absent)"
            severity = Severity.HIGH
        elif val_int == 0:
            state = f"IPv6 is fully enabled (DisabledComponents=0, all bits clear)"
            severity = Severity.HIGH
        else:
            state = f"IPv6 is partially enabled (DisabledComponents={raw.strip()}, bit 0 not set)"
            severity = Severity.MEDIUM

        dc_count = len(self.context.domain_info.domain_controllers)
        dc_label = f"{dc_count} domain controller{'s' if dc_count != 1 else ''}"

        return [self.finding(
            title=f"IPv6 enabled on {dc_label} — mitm6 relay attack is possible",
            description=(
                f"{state}. All {dc_label} accept IPv6 traffic. "
                "The mitm6 tool abuses DHCPv6 to become the preferred DNS server for "
                "machines on the network, then relays their authentication to Active "
                "Directory (typically via ntlmrelayx) to create computer accounts, "
                "modify ACLs, or achieve full domain compromise. "
                "CVE impact: no specific CVE — this exploits a Windows design default."
            ),
            severity=severity,
            remediation_desc=(
                "If IPv6 is not required, fully disable it on all DC interfaces by setting "
                "DisabledComponents to 0xFF (255). Apply via GPO to all Domain Controllers OU. "
                "Also add ISATAP and WPAD to the DNS Global Query Block List."
            ),
            powershell=(
                "# Via GPO (preferred — targets all DCs):\n"
                "# Computer Configuration → Policies → Windows Settings → Registry\n"
                "# Key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\n"
                "# Value: DisabledComponents  Type: REG_DWORD  Data: 0xFF\n\n"
                "# Or directly on each DC (requires reboot):\n"
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' "
                "-Name DisabledComponents -Value 0xFF -Type DWord\n\n"
                "# Block ISATAP and WPAD in DNS Global Query Block List:\n"
                "Set-DnsServerGlobalQueryBlockList -List 'wpad','isatap' -Enable $true"
            ),
            mitre=[
                MitreAttack(
                    technique_id="T1557.001",
                    technique_name="LLMNR/NBT-NS Poisoning and SMB Relay",
                    tactic="Credential Access",
                ),
                MitreAttack(
                    technique_id="T1021.002",
                    technique_name="SMB/Windows Admin Shares",
                    tactic="Lateral Movement",
                ),
            ],
            cis_controls=["4.8", "12.2"],
            nist_800_53=["CM-6", "CM-7", "SC-5"],
            details={
                "disabled_components_raw": raw,
                "dc_count": dc_count,
                "attack_tool": "mitm6 (https://github.com/dirkjanm/mitm6)",
                "combined_attack": "mitm6 + ntlmrelayx → LDAP relay → domain compromise",
            },
            source="WinRM",
        )]
