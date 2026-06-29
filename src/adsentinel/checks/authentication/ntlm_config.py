"""Authentication Security checks (AUTH-001 to AUTH-015)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import MITRE_NTLM_RELAY, MITRE_PASS_THE_HASH
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import Finding
from adsentinel.models.severity import Severity
from adsentinel.utils import safe_int


@check
class AUTH001_NTLMv1(BaseCheck):
    id = "AUTH-001"
    name = "NTLMv1 Authentication"
    description = "Check if NTLMv1 is allowed (requires WinRM)"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        lm_level_raw = self.context.registry_values.get("LmCompatibilityLevel", "")
        lm_level = safe_int(lm_level_raw)
        if lm_level is not None and lm_level < 3:
            return [self.finding(
                title=f"NTLMv1 authentication is allowed (LmCompatibilityLevel={lm_level_raw})",
                description=(
                    "NTLMv1 uses weak encryption that can be cracked almost instantly. "
                    "LmCompatibilityLevel should be set to 5 (send NTLMv2 only, refuse LM & NTLMv1)."
                ),
                severity=Severity.CRITICAL,
                remediation_desc="Set LmCompatibilityLevel to 5 via GPO.",
                powershell="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5",
                mitre=[MitreAttack(technique_id=MITRE_NTLM_RELAY, technique_name="LLMNR/NBT-NS Poisoning and SMB Relay", tactic="Credential Access")],
                cis_controls=["3.10"],
                nist_800_53=["IA-5", "SC-13"],
                stig_rules=["V-73487"],
                source="WinRM",
            )]
        return []


@check
class AUTH002_WDigest(BaseCheck):
    id = "AUTH-002"
    name = "WDigest Authentication"
    description = (
        "Check if WDigest stores cleartext passwords in LSASS memory. "
        "Handles two cases: UseLogonCredential=1 (explicitly enabled) and absent key on "
        "pre-2012 R2 DCs where WDigest is on by default even without the registry key."
    )
    category = "Authentication Security"
    requires_winrm = True

    _FIX_PS = (
        "Set-ItemProperty -Path "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "-Name 'UseLogonCredential' -Value 0 -Type DWord"
    )

    @staticmethod
    def _is_pre_2012r2(os_version: str) -> bool:
        """True if the OS version string indicates a Windows Server version older than 2012 R2."""
        v = os_version.lower()
        if any(x in v for x in ("2012 r2", "2016", "2019", "2022", "2025")):
            return False
        return any(x in v for x in ("2003", "2008", "2012"))

    def run(self) -> List[Finding]:
        # Use .get() with no default so we can distinguish absent (None) from explicit "0"
        wdigest = self.context.registry_values.get("UseLogonCredential")

        if wdigest == "1":
            return [self.finding(
                title="WDigest explicitly enabled — cleartext passwords cached in LSASS memory",
                description=(
                    "UseLogonCredential=1 is set in the WDigest registry key. "
                    "This instructs Windows to cache the user's cleartext password in LSASS memory "
                    "on every interactive logon, RDP session, and RunAs operation. "
                    "Tools such as Mimikatz (sekurlsa::wdigest) can extract these in seconds "
                    "from any process with SeDebugPrivilege."
                ),
                severity=Severity.CRITICAL,
                remediation_desc=(
                    "Set UseLogonCredential to 0. All active sessions must re-authenticate before "
                    "the cleartext credential is flushed from LSASS — force logoffs or reboot the DC."
                ),
                powershell=self._FIX_PS,
                mitre=[MitreAttack(technique_id="T1003.001", technique_name="LSASS Memory", tactic="Credential Access")],
                nist_800_53=["IA-5"],
                source="WinRM",
            )]

        if wdigest == "0":
            return []  # Explicitly disabled — clean

        # Key is absent from registry. Behavior is OS-version-dependent:
        # Pre-2012 R2 (including Server 2012 without R2): WDigest on by default.
        # 2012 R2+: WDigest off by default (KB2871997 changed the default).
        legacy_dcs = [
            dc for dc in self.context.domain_info.domain_controllers
            if self._is_pre_2012r2(dc.os_version)
        ]

        if not legacy_dcs:
            return []

        dc_list = ", ".join(
            f"{dc.hostname or dc.dn} ({dc.os_version})"
            for dc in legacy_dcs[:10]
        )
        return [self.finding(
            title=(
                f"{len(legacy_dcs)} pre-2012 R2 DC(s) have WDigest enabled by default "
                "(UseLogonCredential key absent)"
            ),
            description=(
                "The UseLogonCredential registry key is absent on these domain controllers. "
                "On Windows Server versions prior to 2012 R2, the default behavior when the key "
                "is missing is for WDigest to cache cleartext credentials in LSASS memory — "
                "identical to UseLogonCredential=1. Microsoft changed this default in Server 2012 R2 "
                "and backported the fix to older OS versions via KB2871997, but only if that update "
                "is installed AND the key is explicitly set to 0.\n\n"
                "Affected domain controllers (pre-2012 R2):\n" +
                "\n".join(f"  • {dc.hostname or dc.dn} ({dc.os_version})" for dc in legacy_dcs[:10]) +
                ("\n  (and more...)" if len(legacy_dcs) > 10 else "")
            ),
            severity=Severity.HIGH,
            remediation_desc=(
                "1. Install KB2871997 on all pre-2012 R2 DCs if not already applied. "
                "2. Explicitly set UseLogonCredential=0 on every DC regardless of OS version — "
                "an explicit 0 is immune to KB removal and makes the intent unambiguous. "
                "3. Force logoffs or reboot after applying to flush any cached cleartext from LSASS."
            ),
            powershell=self._FIX_PS,
            mitre=[MitreAttack(technique_id="T1003.001", technique_name="LSASS Memory", tactic="Credential Access")],
            nist_800_53=["IA-5"],
            source="WinRM",
            details={
                "legacy_dc_count": len(legacy_dcs),
                "legacy_dcs": [
                    {"hostname": dc.hostname, "os": dc.os_version}
                    for dc in legacy_dcs
                ],
                "registry_key_state": "absent",
            },
        )]


@check
class AUTH003_SMBSigning(BaseCheck):
    id = "AUTH-003"
    name = "SMB Signing"
    description = "Check if SMB signing is required"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        smb = self.context.smb_config
        if smb and not smb.get("RequireSecuritySignature", True):
            return [self.finding(
                title="SMB signing is not required",
                description="Without required SMB signing, attackers can perform SMB relay attacks to impersonate users.",
                severity=Severity.HIGH,
                remediation_desc="Enable required SMB signing on all domain systems via GPO.",
                powershell="Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                mitre=[MitreAttack(technique_id=MITRE_NTLM_RELAY, technique_name="SMB Relay", tactic="Credential Access")],
                cis_controls=["3.10"],
                nist_800_53=["SC-8"],
                source="WinRM",
            )]
        return []


@check
class AUTH004_SMBv1(BaseCheck):
    id = "AUTH-004"
    name = "SMBv1 Protocol"
    description = "Check if SMBv1 is enabled"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        smb = self.context.smb_config
        if smb and smb.get("EnableSMB1Protocol", False):
            return [self.finding(
                title="SMBv1 protocol is enabled",
                description="SMBv1 is vulnerable to EternalBlue and other critical exploits. It should be disabled on all systems.",
                severity=Severity.CRITICAL,
                remediation_desc="Disable SMBv1 on all domain systems.",
                powershell="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                mitre=[MitreAttack(technique_id="T1210", technique_name="Exploitation of Remote Services", tactic="Lateral Movement")],
                cis_controls=["4.8"],
                nist_800_53=["CM-7"],
                source="WinRM",
            )]
        return []


@check
class AUTH005_LDAPSigning(BaseCheck):
    id = "AUTH-005"
    name = "LDAP Signing Requirements"
    description = "Check if LDAP signing is required on domain controllers"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        ldap_signing = safe_int(self.context.registry_values.get("LDAPServerIntegrity", ""))
        if ldap_signing is not None and ldap_signing < 2:
            return [self.finding(
                title="LDAP signing is not required on domain controllers",
                description="Without LDAP signing, attackers can perform LDAP relay attacks or modify LDAP traffic in transit.",
                severity=Severity.HIGH,
                remediation_desc="Set LDAP signing to 'Require signing' via GPO.",
                powershell="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LDAPServerIntegrity' -Value 2",
                mitre=[MitreAttack(technique_id=MITRE_NTLM_RELAY, technique_name="NTLM Relay", tactic="Credential Access")],
                nist_800_53=["SC-8"],
                source="WinRM",
            )]
        return []


@check
class AUTH006_LDAPChannelBinding(BaseCheck):
    id = "AUTH-006"
    name = "LDAP Channel Binding"
    description = "Check if LDAP channel binding is enabled"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        cb = safe_int(self.context.registry_values.get("LdapEnforceChannelBinding", ""))
        if cb is not None and cb < 2:
            return [self.finding(
                title="LDAP channel binding is not enforced",
                description="Without channel binding, LDAP connections are vulnerable to credential relaying attacks.",
                severity=Severity.MEDIUM,
                remediation_desc="Enable LDAP channel binding (set to 2 = Always).",
                powershell="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2",
                nist_800_53=["SC-8"],
                source="WinRM",
            )]
        return []


@check
class AUTH007_NTLMRestrictions(BaseCheck):
    id = "AUTH-007"
    name = "NTLM Restrictions"
    description = "Check if NTLM authentication is restricted"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        restrict_raw = self.context.registry_values.get("RestrictNTLMInDomain", "")
        restrict = safe_int(restrict_raw)
        if restrict is not None and restrict == 0:
            return [self.finding(
                title="NTLM authentication is not restricted in the domain",
                description=(
                    "NTLM authentication is allowed without restrictions. NTLM is vulnerable to relay "
                    "attacks and pass-the-hash. Restricting NTLM forces Kerberos where possible."
                ),
                severity=Severity.MEDIUM,
                remediation_desc="Enable NTLM auditing first, then progressively restrict NTLM.",
                powershell="# Step 1: Audit\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -Name 'AuditNTLMInDomain' -Value 7",
                mitre=[MitreAttack(technique_id=MITRE_PASS_THE_HASH, technique_name="Pass the Hash", tactic="Lateral Movement")],
                nist_800_53=["IA-5"],
                source="WinRM",
            )]
        return []


@check
class AUTH008_CredentialGuard(BaseCheck):
    id = "AUTH-008"
    name = "Credential Guard"
    description = "Check if Credential Guard is enabled on DCs"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        cg_raw = self.context.registry_values.get("LsaCfgFlags", "")
        cg = safe_int(cg_raw)
        if cg is not None and cg == 0:
            return [self.finding(
                title="Credential Guard is not enabled",
                description="Credential Guard uses virtualization-based security to protect NTLM hashes and Kerberos TGTs from theft by tools like Mimikatz.",
                severity=Severity.MEDIUM,
                remediation_desc="Enable Credential Guard via GPO on supported hardware.",
                powershell="# Enable via GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security",
                mitre=[MitreAttack(technique_id="T1003.001", technique_name="LSASS Memory", tactic="Credential Access")],
                cis_controls=["10.5"],
                nist_800_53=["SC-39"],
                source="WinRM",
            )]
        return []


@check
class AUTH009_AnonymousBind(BaseCheck):
    id = "AUTH-009"
    name = "LDAP Anonymous Bind"
    description = (
        "Read dsHeuristics from CN=Directory Service to determine whether anonymous LDAP "
        "bind is explicitly enabled. Position 7 of the dsHeuristics string set to '2' "
        "allows unauthenticated principals to query the directory."
    )
    category = "Authentication Security"

    def run(self) -> List[Finding]:
        # dsHeuristics is collected by DomainInfoCollector from:
        # CN=Directory Service,CN=Windows NT,CN=Services,<config_dn>
        # Key is absent from raw_entries when the object was unreachable.
        # Key is present but empty string when the attribute has no value (anonymous bind blocked by default).
        if "dsHeuristics" not in self.context.raw_entries:
            return [self.finding(
                title="dsHeuristics attribute could not be read — anonymous LDAP bind status unknown",
                description=(
                    "CN=Directory Service could not be queried. The dsHeuristics attribute on this "
                    "object controls whether anonymous LDAP binds are permitted. Its status cannot "
                    "be confirmed without read access to the configuration naming context."
                ),
                severity=Severity.INFO,
                remediation_desc=(
                    "Verify manually: check dsHeuristics on "
                    "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=... "
                    "Position 7 (1-indexed) set to '2' means anonymous bind is enabled."
                ),
                powershell=(
                    "$configDN = (Get-ADRootDSE).configurationNamingContext\n"
                    "Get-ADObject \"CN=Directory Service,CN=Windows NT,CN=Services,$configDN\" "
                    "-Properties dsHeuristics | Select-Object dsHeuristics"
                ),
                nist_800_53=["AC-14", "IA-5"],
            )]

        dsh = self.context.raw_entries["dsHeuristics"]
        # Position 7 (1-indexed) = index 6 (0-indexed): fLDAPBlockAnonOps
        # '2' → anonymous LDAP bind is explicitly enabled
        # Absent, shorter than 7 chars, or any value other than '2' → blocked (secure default)
        anon_char = dsh[6] if len(dsh) > 6 else "0"

        if anon_char != "2":
            return []  # Anonymous bind is blocked — clean

        return [self.finding(
            title="Anonymous LDAP bind is enabled via dsHeuristics (position 7 = '2')",
            description=(
                "The dsHeuristics attribute on CN=Directory Service has character 7 set to '2', "
                "which explicitly enables anonymous LDAP binds. Any unauthenticated host on the "
                "network can bind to the domain controller's LDAP port (389/636) without credentials "
                "and enumerate AD objects — users, groups, computers, SPNs, and password policy — "
                "up to the limits of anonymous read permissions.\n\n"
                "This was originally required for compatibility with legacy LDAP clients that do not "
                "support authentication. It should be disabled in all modern environments.\n\n"
                f"Current dsHeuristics value: '{dsh}' (character 7 = '{anon_char}')"
            ),
            severity=Severity.HIGH,
            remediation_desc=(
                "Set character 7 of dsHeuristics to '0' (or remove the value entirely if all other "
                "positions are also default). Anonymous LDAP bind has been blocked by default since "
                "Windows Server 2003 SP1 — only change this if a specific legacy application requires it."
            ),
            powershell=(
                "# Check current dsHeuristics:\n"
                "$configDN = (Get-ADRootDSE).configurationNamingContext\n"
                "$obj = Get-ADObject \"CN=Directory Service,CN=Windows NT,CN=Services,$configDN\" "
                "-Properties dsHeuristics\n"
                "$obj.dsHeuristics\n\n"
                "# Disable anonymous bind (set position 7 to '0'):\n"
                "# Replace only character 7 in the existing string to preserve other flags:\n"
                "$dsh = $obj.dsHeuristics.ToCharArray()\n"
                "$dsh[6] = '0'\n"
                "Set-ADObject $obj -Replace @{dsHeuristics = [string]::new($dsh)}"
            ),
            mitre=[MitreAttack(technique_id="T1087.002", technique_name="Domain Account Discovery", tactic="Discovery")],
            nist_800_53=["AC-14", "IA-5"],
            details={"dsHeuristics": dsh, "anon_char_pos7": anon_char},
        )]


@check
class AUTH010_SmartcardEnforcement(BaseCheck):
    id = "AUTH-010"
    name = "Smartcard Authentication"
    description = "Check if privileged accounts require smartcard authentication"
    category = "Authentication Security"

    def run(self) -> List[Finding]:
        from adsentinel.constants import UAC_SMARTCARD_REQUIRED
        priv_no_sc = [
            u for u in self.context.users
            if u.enabled and self.context.is_privileged_user(u)
            and not (u.user_account_control & UAC_SMARTCARD_REQUIRED)
        ]
        if priv_no_sc:
            return [self.finding(
                title=f"{len(priv_no_sc)} privileged accounts don't require smartcard authentication",
                description="Privileged accounts using only password authentication are vulnerable to credential theft. Smartcard enforcement adds a hardware factor.",
                severity=Severity.LOW,
                affected_objects=[self.affected_user(u) for u in priv_no_sc[:50]],
                affected_count=len(priv_no_sc),
                remediation_desc="Enforce smartcard authentication for privileged accounts.",
                powershell="Get-ADUser -Filter {adminCount -eq 1 -and SmartcardLogonRequired -eq $false -and Enabled -eq $true} | Set-ADUser -SmartcardLogonRequired $true",
                nist_800_53=["IA-2"],
            )]
        return []


@check
class AUTH011_PasswordNotReqdComputers(BaseCheck):
    id = "AUTH-011"
    name = "Computers with PASSWD_NOTREQD"
    description = "Check for computer accounts with PASSWD_NOTREQD flag"
    category = "Authentication Security"

    def run(self) -> List[Finding]:
        from adsentinel.constants import UAC_PASSWD_NOTREQD
        no_pwd_comps = [
            c for c in self.context.computers
            if c.enabled and (c.user_account_control & UAC_PASSWD_NOTREQD)
        ]
        if no_pwd_comps:
            return [self.finding(
                title=f"{len(no_pwd_comps)} computer accounts have PASSWD_NOTREQD flag",
                description="Computer accounts with PASSWD_NOTREQD can have empty passwords, enabling attackers to authenticate as the machine.",
                severity=Severity.HIGH,
                affected_objects=[self.affected_computer(c) for c in no_pwd_comps[:50]],
                affected_count=len(no_pwd_comps),
                remediation_desc="Remove PASSWD_NOTREQD from computer accounts.",
                powershell="Get-ADComputer -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} | Set-ADComputer -PasswordNotRequired $false",
                nist_800_53=["IA-5"],
            )]
        return []


@check
class AUTH013_LSAProtection(BaseCheck):
    id = "AUTH-013"
    name = "LSA Protection (RunAsPPL)"
    description = "Check if LSASS is running as a Protected Process Light (PPL)"
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        raw = self.context.registry_values.get("RunAsPPL")

        # Key absent entirely — registry value was not found on the DC
        if raw is None:
            return [self.finding(
                title="LSA Protection (RunAsPPL) is not configured",
                description=(
                    "The RunAsPPL registry value is absent, meaning LSASS is not running as a "
                    "Protected Process Light. Any administrator-level process can open LSASS memory "
                    "directly and dump credentials with tools such as Mimikatz sekurlsa::logonpasswords "
                    "or Task Manager. This is the single most common privilege-escalation step after "
                    "an attacker gains local admin on a domain controller."
                ),
                severity=Severity.CRITICAL,
                remediation_desc=(
                    "Enable LSA Protection by setting RunAsPPL=1 in the registry and rebooting. "
                    "On Server 2022+, set RunAsPPL=2 to also write-protect the key itself. "
                    "Verify with 'Get-WinEvent -LogName System | Where-Object Id -eq 12' "
                    "to confirm LSASS started as a protected process."
                ),
                powershell=(
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                    "-Name 'RunAsPPL' -Value 1 -Type DWord\n"
                    "# Server 2022+ — also enables write-protection of the key:\n"
                    "# Set-ItemProperty ... -Value 2"
                ),
                manual_steps=[
                    "Reboot the domain controller after setting RunAsPPL — the protection activates at boot.",
                    "Confirm via Event ID 12 in the System log: 'LSASS.exe was started as a protected process'.",
                    "Install Windows Defender Credential Guard as a complementary hardening layer.",
                ],
                mitre=[MitreAttack(technique_id="T1003.001", technique_name="LSASS Memory", tactic="Credential Access")],
                cis_controls=["10.5"],
                nist_800_53=["SC-39", "SI-3"],
                stig_rules=["V-93459"],
                source="WinRM",
            )]

        ppl_level = safe_int(raw)
        if ppl_level is not None and ppl_level >= 1:
            return []  # Protected — no finding

        # Value is present but explicitly set to 0
        return [self.finding(
            title="LSA Protection (RunAsPPL) is explicitly disabled (RunAsPPL=0)",
            description=(
                "The RunAsPPL registry value is present and set to 0, explicitly disabling LSASS "
                "process protection. This allows any administrator to dump LSASS memory directly. "
                "A value of 0 is more concerning than an absent key because it suggests the "
                "protection was intentionally turned off."
            ),
            severity=Severity.CRITICAL,
            remediation_desc="Change RunAsPPL to 1 (or 2 on Server 2022+) and reboot the domain controller.",
            powershell=(
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                "-Name 'RunAsPPL' -Value 1 -Type DWord"
            ),
            details={"current_value": raw},
            mitre=[MitreAttack(technique_id="T1003.001", technique_name="LSASS Memory", tactic="Credential Access")],
            cis_controls=["10.5"],
            nist_800_53=["SC-39", "SI-3"],
            stig_rules=["V-93459"],
            source="WinRM",
        )]


@check
class AUTH012_StaleComputerPasswords(BaseCheck):
    id = "AUTH-012"
    name = "Stale Computer Passwords"
    description = "Check for computers with passwords older than 90 days"
    category = "Authentication Security"

    def run(self) -> List[Finding]:
        stale = [c for c in self.context.computers if c.enabled and c.is_stale]
        if stale and len(stale) > 10:
            return [self.finding(
                title=f"{len(stale)} computers have stale passwords (90+ days)",
                description="Computers that haven't rotated their machine passwords may be offline, decommissioned, or compromised.",
                severity=Severity.MEDIUM if len(stale) < 50 else Severity.HIGH,
                affected_objects=[self.affected_computer(c) for c in stale[:50]],
                affected_count=len(stale),
                remediation_desc="Disable or remove stale computer accounts.",
                powershell="Get-ADComputer -Filter {PasswordLastSet -lt (Get-Date).AddDays(-90) -and Enabled -eq $true} | Disable-ADAccount",
                nist_800_53=["AC-2"],
            )]
        return []


@check
class AUTH014_RDPNLANotEnforced(BaseCheck):
    id = "AUTH-014"
    name = "RDP Network Level Authentication Not Enforced"
    description = (
        "Check that RDP requires Network Level Authentication (NLA) before presenting "
        "the Windows login screen. Without NLA, unauthenticated attackers interact with "
        "the full RDP session stack, enabling pre-auth exploitation and credential harvesting."
    )
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        raw = self.context.registry_values.get("RDPNLARequired")

        if raw is not None:
            val = safe_int(raw)
            if val == 1:
                return []  # NLA enforced — clean

        # Both absent (not configured via GPO) and explicitly 0 are dangerous.
        # Absent: the per-connection setting may still enable NLA, but Group Policy
        # enforcement is missing — any GPO change or local override can disable it.
        state = (
            "not configured via Group Policy (per-connection default may vary)"
            if raw is None
            else f"explicitly disabled (UserAuthenticationRequired={raw.strip()})"
        )
        severity = Severity.CRITICAL if raw is not None and safe_int(raw) == 0 else Severity.HIGH

        return [self.finding(
            title=f"RDP Network Level Authentication is {state}",
            description=(
                "Network Level Authentication (NLA) requires users to authenticate before a full "
                "RDP session is established — the Windows login screen is never shown to unauthenticated "
                "connections. Without NLA enforcement:\n\n"
                "• Pre-authentication vulnerabilities (BlueKeep CVE-2019-0708, DejaBlue CVE-2019-1181/1182) "
                "are exploitable against the full RDP stack.\n"
                "• Attackers can reach the credential entry screen and spray passwords or observe "
                "the hostname/domain without presenting any credentials.\n"
                "• RDP credential prompt is exposed on the network — vulnerable to SMB relay if "
                "NTLMv2 downgrade is also present.\n\n"
                "NLA should be enforced via Group Policy "
                "(Computer Configuration → Administrative Templates → Windows Components → "
                "Remote Desktop Services → Remote Desktop Session Host → Security: "
                "'Require user authentication for remote connections by using NLA')."
            ),
            severity=severity,
            remediation_desc=(
                "Enforce NLA via Group Policy: set 'Require user authentication for remote connections "
                "by using Network Level Authentication' to Enabled on all servers and workstations. "
                "For DCs specifically, apply via the Default Domain Controllers Policy or a dedicated GPO."
            ),
            powershell=(
                "# Check current NLA setting on this host:\n"
                "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                "-Name UserAuthenticationRequired | Select-Object UserAuthenticationRequired\n\n"
                "# Enforce via registry (complement with GPO for durability):\n"
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                "-Name 'UserAuthenticationRequired' -Value 1 -Type DWord\n\n"
                "# Verify GPO setting across domain DCs:\n"
                "Invoke-Command -ComputerName (Get-ADDomainController -Filter *).HostName -ScriptBlock {\n"
                "    (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'"
                " -Name UserAuthenticationRequired -EA SilentlyContinue).UserAuthenticationRequired\n"
                "}"
            ),
            manual_steps=[
                "Open Group Policy Management Console (gpmc.msc).",
                "Edit the Default Domain Controllers Policy (or a dedicated DC hardening GPO).",
                "Navigate to: Computer Configuration → Policies → Administrative Templates → "
                "Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security.",
                "Enable 'Require user authentication for remote connections by using Network Level Authentication'.",
                "Run gpupdate /force on all DCs and verify with: "
                "Get-ItemProperty HKLM:\\...\\RDP-Tcp -Name UserAuthenticationRequired",
            ],
            mitre=[MitreAttack(
                technique_id="T1021.001",
                technique_name="Remote Services: Remote Desktop Protocol",
                tactic="Lateral Movement",
            )],
            cis_controls=["4.5", "12.8"],
            nist_800_53=["AC-17", "IA-2", "CM-6"],
            stig_rules=["V-93561"],
            source="WinRM",
            details={"registry_value": raw if raw is not None else "absent"},
        )]


@check
class AUTH015_RDPRestrictedAdminEnabled(BaseCheck):
    id = "AUTH-015"
    name = "RDP Restricted Admin Mode Enabled (Pass-the-Hash Vector)"
    description = (
        "Check whether RDP Restricted Admin mode is enabled on domain controllers. "
        "When enabled, users can RDP using an NTLM hash instead of a plaintext password — "
        "a significant lateral movement amplifier for any attacker holding stolen hashes."
    )
    category = "Authentication Security"
    requires_winrm = True

    def run(self) -> List[Finding]:
        raw = self.context.registry_values.get("RDPRestrictedAdminDisabled")

        # DisableRestrictedAdmin=1 → Restricted Admin is DISABLED → safe
        if raw is not None:
            val = safe_int(raw)
            if val == 1:
                return []

        # DisableRestrictedAdmin=0 or absent → Restricted Admin is ENABLED (default pre-2019)
        # Both are dangerous — absent means the OS default (enabled) applies.
        state = (
            "enabled by default (DisableRestrictedAdmin key absent)"
            if raw is None
            else f"explicitly enabled (DisableRestrictedAdmin={raw.strip()})"
        )

        return [self.finding(
            title=f"RDP Restricted Admin mode is {state} — Pass-the-Hash via RDP is possible",
            description=(
                "RDP Restricted Admin mode allows connecting to a remote host using only an "
                "NTLM hash or Kerberos ticket — no plaintext password required. "
                "While designed to protect credentials on untrusted servers, it is routinely "
                "abused as a pass-the-hash (PtH) lateral movement technique:\n\n"
                "• Mimikatz: sekurlsa::pth /user:Administrator /domain:corp /ntlm:<hash> /run:mstsc\n"
                "• impacket: rdp_check.py or xfreerdp /restricted-admin\n\n"
                "Any attacker who obtains an NTLM hash for a domain admin account (via DCSync, "
                "LSASS dump, NTLM capture, or ADCS) can immediately RDP into every DC and server "
                "where that account has access — without ever cracking the password.\n\n"
                "DisableRestrictedAdmin=1 under HKLM\\System\\CurrentControlSet\\Control\\Lsa "
                "disables this mode and forces full-credential authentication for RDP."
            ),
            severity=Severity.HIGH,
            remediation_desc=(
                "Set DisableRestrictedAdmin=1 to prevent hash-based RDP authentication. "
                "Deploy via GPO for domain-wide enforcement. "
                "Note: if you currently rely on Restricted Admin for legitimate admin scripts, "
                "migrate those to Credential SSP or Kerberos-delegated sessions first."
            ),
            powershell=(
                "# Check current state:\n"
                "Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' "
                "-Name DisableRestrictedAdmin -ErrorAction SilentlyContinue\n\n"
                "# Disable Restricted Admin mode (blocks PtH via RDP):\n"
                "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' "
                "-Name 'DisableRestrictedAdmin' -Value 1 -Type DWord\n\n"
                "# Verify across all DCs:\n"
                "Invoke-Command -ComputerName (Get-ADDomainController -Filter *).HostName -ScriptBlock {\n"
                "    (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' "
                "-Name DisableRestrictedAdmin -EA SilentlyContinue).DisableRestrictedAdmin\n"
                "}"
            ),
            manual_steps=[
                "Open Group Policy Management Console.",
                "Edit the Default Domain Controllers Policy or a dedicated server hardening GPO.",
                "Navigate to: Computer Configuration → Preferences → Windows Settings → Registry.",
                "Add a registry item: HKLM\\System\\CurrentControlSet\\Control\\Lsa, "
                "Value: DisableRestrictedAdmin, Type: REG_DWORD, Data: 1.",
                "Run gpupdate /force and confirm the value is set to 1 on all DCs.",
                "After enforcement, test that admin RDP sessions still work using full credentials.",
            ],
            mitre=[MitreAttack(
                technique_id="T1550.002",
                technique_name="Use Alternate Authentication Material: Pass the Hash",
                tactic="Lateral Movement",
            ), MitreAttack(
                technique_id="T1021.001",
                technique_name="Remote Services: Remote Desktop Protocol",
                tactic="Lateral Movement",
            )],
            cis_controls=["4.5"],
            nist_800_53=["AC-17", "IA-2", "CM-6"],
            source="WinRM",
            details={"registry_value": raw if raw is not None else "absent"},
        )]
