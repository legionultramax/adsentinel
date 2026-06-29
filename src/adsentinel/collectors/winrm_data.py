"""WinRM data collector — registry values, services, audit policy, SMB config, SYSVOL GPP scan,
and SYSVOL user-rights-assignment scan.

All WinRM-gated checks depend on this collector to have populated SharedContext fields.
Collection is batched into as few PowerShell round-trips as possible.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from adsentinel.collectors.base import BaseCollector
from adsentinel.logging_config import get_logger

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)

# ── Batched PowerShell: all registry keys we need in one round-trip ──────────
_REGISTRY_BATCH_PS = r"""
$keys = @(
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                                       N='LmCompatibilityLevel';                K='LmCompatibilityLevel'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest';                  N='UseLogonCredential';                  K='UseLogonCredential'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters';                          N='LDAPServerIntegrity';                 K='LDAPServerIntegrity'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters';                          N='LdapEnforceChannelBinding';           K='LdapEnforceChannelBinding'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters';                      N='RestrictNTLMInDomain';                K='RestrictNTLMInDomain'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                                       N='LsaCfgFlags';                         K='LsaCfgFlags'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                                       N='RunAsPPL';                            K='RunAsPPL'},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';          N='EnableScriptBlockLogging';            K='EnableScriptBlockLogging'},
    @{P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';            N='ProcessCreationIncludeCmdLine_Enabled'; K='ProcessCreationIncludeCmdLine_Enabled'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel';                N='StrongCertificateBindingEnforcement'; K='StrongCertificateBindingEnforcement'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; N='Enabled'; K='TLS10ServerEnabled'},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient';                           N='EnableMulticast';                     K='LLMNREnabled'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters';                        N='NodeType';                            K='NetBTNodeType'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';      N='UserAuthenticationRequired';          K='RDPNLARequired'},
    @{P='HKLM:\System\CurrentControlSet\Control\Lsa';                                      N='DisableRestrictedAdmin';              K='RDPRestrictedAdminDisabled'},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters';                      N='DisabledComponents';                  K='IPv6DisabledComponents'}
)
$out = @{}
foreach ($k in $keys) {
    $prop = Get-ItemProperty -Path $k.P -Name $k.N -ErrorAction SilentlyContinue
    $out[$k.K] = if ($null -ne $prop) { "$($prop.($k.N))" } else { $null }
}
$out | ConvertTo-Json -Compress
"""

# ── Services batch ────────────────────────────────────────────────────────────
_SERVICES_BATCH_PS = r"""
$names = @('Spooler','EFS','Dfs','WebClient','WinRM','W3SVC','RpcEptMapper','LanmanServer')
$out = @{}
foreach ($n in $names) {
    $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
    $out[$n] = if ($svc) { $svc.Status.ToString() } else { 'NotFound' }
}
$out | ConvertTo-Json -Compress
"""

# ── SYSVOL GPP cpassword scan (MS14-025) ─────────────────────────────────────
# cpassword values are AES-256 encrypted with a key Microsoft published in 2012.
# Finding them proves credentials are stored in group policy and recoverable.
# ── SYSVOL local-admin assignment scan (Restricted Groups + GPP Groups.xml) ──
# Two mechanisms grant local Administrators membership via GPO:
#   1. Restricted Groups (GptTmpl.inf) — *S-1-5-32-544__Members line
#   2. Group Policy Preferences — Groups.xml with action=ADD/UPDATE targeting Administrators
# Both are collected and stored as unified records for the GPO-011 check.
_LOCAL_ADMIN_SCAN_PS_TEMPLATE = r"""
$sysvolRoot = '\\{domain}\SYSVOL'
$guidRegex  = [regex]'\{{([0-9A-Fa-f]{{8}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{12}})\}}'
$results    = [System.Collections.Generic.List[object]]::new()
try {{
    # ── 1. Restricted Groups: GptTmpl.inf ────────────────────────────────────
    Get-ChildItem -Path $sysvolRoot -Recurse -Filter 'GptTmpl.inf' -ErrorAction SilentlyContinue |
        ForEach-Object {{
            $filePath = $_.FullName
            try {{
                $content = Get-Content -Path $filePath -Raw -Encoding Unicode -ErrorAction Stop
            }} catch {{
                try {{ $content = Get-Content -Path $filePath -Raw -ErrorAction Stop }}
                catch {{ return }}
            }}
            $match = [regex]::Match($content, '(?i)\*?S-1-5-32-544__Members\s*=\s*([^\r\n]+)')
            if ($match.Success) {{
                $guidHit = $guidRegex.Match($filePath)
                $gpoGuid = if ($guidHit.Success) {{ $guidHit.Groups[1].Value }} else {{ 'Unknown' }}
                $results.Add([PSCustomObject]@{{
                    FilePath   = $filePath
                    GPOGuid    = $gpoGuid
                    Source     = 'RestrictedGroups'
                    RawMembers = $match.Groups[1].Value.Trim()
                }})
            }}
        }}
    # ── 2. GPP Groups.xml ────────────────────────────────────────────────────
    Get-ChildItem -Path $sysvolRoot -Recurse -Filter 'Groups.xml' -ErrorAction SilentlyContinue |
        ForEach-Object {{
            $filePath = $_.FullName
            try {{ [xml]$xml = Get-Content -Path $filePath -Raw -ErrorAction Stop }}
            catch {{ return }}
            $adminGroups = $xml.Groups.Group | Where-Object {{
                $_.name -match 'Administrators' -or
                ($_.Properties -and $_.Properties.groupName -match 'Administrators')
            }}
            foreach ($grp in $adminGroups) {{
                $parts = [System.Collections.Generic.List[string]]::new()
                foreach ($m in $grp.Properties.Members.Member) {{
                    if ($m -and $m.action -in @('ADD','UPDATE')) {{
                        $parts.Add("$($m.name)|$($m.sid)|$($m.action)")
                    }}
                }}
                if ($parts.Count -gt 0) {{
                    $guidHit = $guidRegex.Match($filePath)
                    $gpoGuid = if ($guidHit.Success) {{ $guidHit.Groups[1].Value }} else {{ 'Unknown' }}
                    $results.Add([PSCustomObject]@{{
                        FilePath   = $filePath
                        GPOGuid    = $gpoGuid
                        Source     = 'GPPGroups'
                        RawMembers = $parts -join ';'
                    }})
                }}
            }}
        }}
}} catch {{ }}
@($results) | ConvertTo-Json -Depth 2 -Compress
"""

# ── SYSVOL GptTmpl.inf user-rights-assignment scan ───────────────────────────
# SeRemoteInteractiveLogonRight controls who can initiate an RDP session.
# Overly broad grants (Everyone, Authenticated Users) on DCs are a critical
# lateral movement path — any domain account becomes a DC RDP foothold.
_USER_RIGHTS_SCAN_PS_TEMPLATE = r"""
$sysvolRoot = '\\{domain}\SYSVOL'
$guidRegex  = [regex]'\{{([0-9A-Fa-f]{{8}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{12}})\}}'
$results    = [System.Collections.Generic.List[object]]::new()
try {{
    Get-ChildItem -Path $sysvolRoot -Recurse -Filter 'GptTmpl.inf' -ErrorAction SilentlyContinue |
        ForEach-Object {{
            $filePath = $_.FullName
            try {{
                $content = Get-Content -Path $filePath -Raw -Encoding Unicode -ErrorAction Stop
            }} catch {{
                try {{ $content = Get-Content -Path $filePath -Raw -ErrorAction Stop }}
                catch {{ return }}
            }}
            $match = [regex]::Match($content, 'SeRemoteInteractiveLogonRight\s*=\s*([^\r\n]+)')
            if ($match.Success) {{
                $guidHit = $guidRegex.Match($filePath)
                $gpoGuid = if ($guidHit.Success) {{ $guidHit.Groups[1].Value }} else {{ 'Unknown' }}
                $results.Add([PSCustomObject]@{{
                    FilePath = $filePath
                    GPOGuid  = $gpoGuid
                    RawValue = $match.Groups[1].Value.Trim()
                }})
            }}
        }}
}} catch {{ }}
@($results) | ConvertTo-Json -Depth 2 -Compress
"""

# ── SYSVOL GPP cpassword scan (MS14-025) ─────────────────────────────────────
# cpassword values are AES-256 encrypted with a key Microsoft published in 2012.
# Finding them proves credentials are stored in group policy and recoverable.
_GPP_SCAN_PS_TEMPLATE = r"""
$sysvolRoot = '\\{domain}\SYSVOL'
$targets    = @('Groups.xml','ScheduledTasks.xml','Services.xml','DataSources.xml','Printers.xml','Drives.xml')
$cpRegex    = [regex]'cpassword="([^"]+)"'
$guidRegex  = [regex]'\{{([0-9A-Fa-f]{{8}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{12}})\}}'
$results    = [System.Collections.Generic.List[object]]::new()
try {{
    Get-ChildItem -Path $sysvolRoot -Recurse -ErrorAction SilentlyContinue |
        Where-Object {{ $targets -contains $_.Name }} |
        ForEach-Object {{
            $filePath = $_.FullName
            $content  = [System.IO.File]::ReadAllText($filePath)
            $cpHits   = $cpRegex.Matches($content)
            if ($cpHits.Count -gt 0) {{
                $guidHit = $guidRegex.Match($filePath)
                $gpoGuid = if ($guidHit.Success) {{ $guidHit.Groups[1].Value }} else {{ 'Unknown' }}
                $userHit = [regex]::Match($content, 'userName="([^"]+)"')
                $nameHit = [regex]::Match($content, '(?<![a-z])name="([^"]+)"')
                foreach ($cp in $cpHits) {{
                    $results.Add([PSCustomObject]@{{
                        FilePath  = $filePath
                        FileName  = $_.Name
                        GPOGuid   = $gpoGuid
                        CPassword = $cp.Groups[1].Value
                        UserName  = if ($userHit.Success) {{ $userHit.Groups[1].Value }} else {{ '' }}
                        ItemName  = if ($nameHit.Success) {{ $nameHit.Groups[1].Value }} else {{ '' }}
                    }})
                }}
            }}
        }}
}} catch {{ }}
@($results) | ConvertTo-Json -Depth 2 -Compress
"""


class WinRMDataCollector(BaseCollector):
    """Collects all WinRM-sourced data in batched PowerShell calls.

    Populates:
        context.registry_values  — keyed registry values from DC
        context.service_statuses — service run states
        context.audit_policy     — audit policy from auditpol
        context.smb_config       — SMB server config
        context.raw_entries["gpp_passwords"]       — GPP cpassword findings from SYSVOL
        context.raw_entries["gpo_rdp_rights"]      — SeRemoteInteractiveLogonRight entries from GptTmpl.inf
        context.raw_entries["gpo_local_admin"]     — Restricted Groups + GPP local Administrators grants
    """

    name = "winrm_data"
    description = "Registry values, services, audit policy, SMB config, and SYSVOL GPP scan"
    requires_winrm = True

    def collect(self, context: SharedContext) -> None:
        assert self.winrm is not None

        self._collect_registry(context)
        self._collect_services(context)
        self._collect_audit_policy(context)
        self._collect_smb(context)
        self._collect_event_log(context)
        self._collect_gpp_passwords(context)
        self._collect_rdp_rights(context)
        self._collect_local_admin_assignments(context)

        context._winrm_data_collected = True
        logger.info(
            "winrm_data_collected",
            registry_keys=len(context.registry_values),
            services=len(context.service_statuses),
            gpp_findings=len(context.raw_entries.get("gpp_passwords", [])),
            rdp_rights_findings=len(context.raw_entries.get("gpo_rdp_rights", [])),
            local_admin_findings=len(context.raw_entries.get("gpo_local_admin", [])),
        )

    # ── private helpers ───────────────────────────────────────────────────────

    def _collect_registry(self, context: SharedContext) -> None:
        raw = self.winrm.run_powershell(_REGISTRY_BATCH_PS)
        if not raw:
            logger.warning("winrm_registry_batch_failed")
            return
        try:
            data: Dict[str, Any] = json.loads(raw)
            for key, value in data.items():
                if value is not None:
                    context.registry_values[key] = str(value)
        except (json.JSONDecodeError, AttributeError) as exc:
            logger.warning("winrm_registry_parse_error", error=str(exc))

    def _collect_services(self, context: SharedContext) -> None:
        raw = self.winrm.run_powershell(_SERVICES_BATCH_PS)
        if not raw:
            logger.warning("winrm_services_batch_failed")
            return
        try:
            data: Dict[str, str] = json.loads(raw)
            context.service_statuses.update(data)
        except (json.JSONDecodeError, AttributeError) as exc:
            logger.warning("winrm_services_parse_error", error=str(exc))

    def _collect_audit_policy(self, context: SharedContext) -> None:
        policy = self.winrm.get_audit_policy()
        if policy:
            context.audit_policy = policy

    def _collect_smb(self, context: SharedContext) -> None:
        smb = self.winrm.get_smb_config()
        if smb:
            context.smb_config = smb

    def _collect_event_log(self, context: SharedContext) -> None:
        log_cfg = self.winrm.get_event_log_config("Security")
        if log_cfg:
            context.raw_entries["event_log_security"] = log_cfg

    def _collect_gpp_passwords(self, context: SharedContext) -> None:
        domain = self.ldap.config.domain
        safe_domain = domain.replace("'", "''")
        script = _GPP_SCAN_PS_TEMPLATE.format(domain=safe_domain)
        raw = self.winrm.run_powershell(script)
        if not raw:
            context.raw_entries["gpp_passwords"] = []
            return
        try:
            data = json.loads(raw)
            if data is None:
                data = []
            elif isinstance(data, dict):
                data = [data]
            context.raw_entries["gpp_passwords"] = data
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("winrm_gpp_parse_error", error=str(exc))
            context.raw_entries["gpp_passwords"] = []

    def _collect_local_admin_assignments(self, context: SharedContext) -> None:
        domain = self.ldap.config.domain
        safe_domain = domain.replace("'", "''")
        script = _LOCAL_ADMIN_SCAN_PS_TEMPLATE.format(domain=safe_domain)
        raw = self.winrm.run_powershell(script)
        if not raw:
            context.raw_entries["gpo_local_admin"] = []
            return
        try:
            data = json.loads(raw)
            if data is None:
                data = []
            elif isinstance(data, dict):
                data = [data]
            context.raw_entries["gpo_local_admin"] = data
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("winrm_local_admin_parse_error", error=str(exc))
            context.raw_entries["gpo_local_admin"] = []

    def _collect_rdp_rights(self, context: SharedContext) -> None:
        domain = self.ldap.config.domain
        safe_domain = domain.replace("'", "''")
        script = _USER_RIGHTS_SCAN_PS_TEMPLATE.format(domain=safe_domain)
        raw = self.winrm.run_powershell(script)
        if not raw:
            context.raw_entries["gpo_rdp_rights"] = []
            return
        try:
            data = json.loads(raw)
            if data is None:
                data = []
            elif isinstance(data, dict):
                data = [data]
            context.raw_entries["gpo_rdp_rights"] = data
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("winrm_rdp_rights_parse_error", error=str(exc))
            context.raw_entries["gpo_rdp_rights"] = []
