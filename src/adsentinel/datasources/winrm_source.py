"""WinRM data source for registry and service checks.

Provides read-only PowerShell command execution via WinRM.
Only uses Get-* commands — never modifies the target system.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from adsentinel.config import ScanConfig
from adsentinel.datasources.base import DataSource
from adsentinel.exceptions import WinRMError
from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


class WinRMSource(DataSource):
    """WinRM data source for PowerShell-based checks."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._session: Optional[Any] = None
        self._available = True

    @staticmethod
    def _sanitize_ps_string(value: str) -> str:
        """Sanitize a value for safe use inside PowerShell single-quoted strings.

        In PS single-quoted strings, the only special char is a single quote
        itself, which is escaped by doubling it.
        """
        return value.replace("'", "''")

    def connect(self) -> None:
        """Establish WinRM connection."""
        if not self.config.use_winrm:
            self._available = False
            logger.info("winrm_disabled", reason="--no-winrm flag set")
            return

        try:
            import winrm

            protocol = "https" if self.config.winrm_ssl else "http"
            endpoint = f"{protocol}://{self.config.server}:{self.config.winrm_port}/wsman"

            username = self.config.get_winrm_username()
            password = self.config.get_winrm_password()

            # Transport priority: kerberos (explicit) → negotiate (SSPI) → ntlm (fallback)
            # negotiate requires pywinrm[negotiate]; ntlm requires pywinrm[ntlm] or requests-ntlm
            if self.config.auth_method.value == "kerberos":
                transports = ["kerberos"]
            else:
                transports = ["negotiate", "ntlm"]

            last_exc: Exception = Exception("no transport attempted")
            for transport in transports:
                try:
                    session = winrm.Session(
                        endpoint,
                        auth=(username, password),
                        transport=transport,
                        server_cert_validation="validate" if self.config.winrm_ssl else "ignore",
                        read_timeout_sec=self.config.timeout + 10,
                        operation_timeout_sec=self.config.timeout,
                    )
                    result = session.run_ps("$env:COMPUTERNAME")
                    if result.status_code != 0:
                        raise WinRMError("test", f"Connection test failed: {result.std_err.decode()}")
                    self._session = session
                    logger.info("winrm_connected", server=self.config.server, port=self.config.winrm_port, transport=transport)
                    break
                except ImportError:
                    logger.debug("winrm_transport_unavailable", transport=transport, reason="missing package")
                    continue
                except Exception as exc:
                    last_exc = exc
                    logger.debug("winrm_transport_failed", transport=transport, error=str(exc))
                    continue
            else:
                raise last_exc

        except ImportError:
            self._available = False
            logger.warning("winrm_unavailable", reason="pywinrm not installed")
        except Exception as e:
            self._available = False
            logger.warning("winrm_unavailable", reason=str(e))

    def disconnect(self) -> None:
        """Close WinRM session."""
        self._session = None
        logger.info("winrm_disconnected")

    def is_connected(self) -> bool:
        """Check if WinRM is available."""
        return self._available and self._session is not None

    def run_powershell(self, command: str) -> Optional[str]:
        """Execute a PowerShell command and return stdout.

        Returns None if WinRM is unavailable (graceful degradation).
        """
        if not self.is_connected():
            return None

        try:
            result = self._session.run_ps(command)
            if result.status_code == 0:
                return result.std_out.decode("utf-8", errors="replace").strip()
            else:
                stderr = result.std_err.decode("utf-8", errors="replace").strip()
                logger.warning("winrm_command_error", command=command[:80], error=stderr)
                return None
        except Exception as e:
            logger.warning("winrm_command_failed", command=command[:80], error=str(e))
            return None

    def run_powershell_json(self, command: str) -> Optional[Any]:
        """Execute a PowerShell command that outputs JSON and parse it."""
        json_command = f"{command} | ConvertTo-Json -Depth 5"
        output = self.run_powershell(json_command)
        if output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                logger.warning("winrm_json_parse_error", command=command[:80])
        return None

    def get_registry_value(self, path: str, name: str) -> Optional[str]:
        """Read a registry value from the remote system."""
        safe_path = self._sanitize_ps_string(path)
        safe_name = self._sanitize_ps_string(name)
        command = f"Get-ItemProperty -Path '{safe_path}' -Name '{safe_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty '{safe_name}'"
        return self.run_powershell(command)

    def get_service_status(self, service_name: str) -> Optional[str]:
        """Get the status of a Windows service."""
        safe_name = self._sanitize_ps_string(service_name)
        command = f"Get-Service -Name '{safe_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"
        return self.run_powershell(command)

    def get_audit_policy(self) -> Optional[Dict[str, str]]:
        """Get the current audit policy settings."""
        output = self.run_powershell("auditpol /get /category:* /r")
        if not output:
            return None

        policies = {}
        lines = output.strip().split("\n")
        for line in lines[1:]:  # Skip header
            parts = line.split(",")
            if len(parts) >= 4:
                subcategory = parts[2].strip()
                setting = parts[3].strip()
                policies[subcategory] = setting
        return policies

    def get_smb_config(self) -> Optional[Dict[str, Any]]:
        """Get SMB server configuration."""
        return self.run_powershell_json(
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EncryptData"
        )

    def get_event_log_config(self, log_name: str) -> Optional[Dict[str, Any]]:
        """Get event log configuration."""
        safe_name = self._sanitize_ps_string(log_name)
        return self.run_powershell_json(
            f"Get-WinEvent -ListLog '{safe_name}' -ErrorAction SilentlyContinue | Select-Object LogName, MaximumSizeInBytes, IsEnabled"
        )
