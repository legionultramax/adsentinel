"""WinRM data source for registry and service checks.

Provides read-only PowerShell command execution via WinRM.
Only uses Get-* commands — never modifies the target system.

Connection strategy (in priority order):
1. subprocess Invoke-Command — uses current Windows SSPI/Kerberos identity.
   Same approach as Argus-AD. Works on domain-joined machines with no extra config.
2. pywinrm ntlm — explicit credentials, requires NTLM enabled on DC WinRM listener.
3. pywinrm negotiate — requires requests_negotiate_sspi package.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Dict, List, Optional

from adsentinel.config import ScanConfig
from adsentinel.datasources.base import DataSource
from adsentinel.exceptions import WinRMError
from adsentinel.logging_config import get_logger

logger = get_logger(__name__)

_SUBPROCESS_MODE = "subprocess"
_PYWINRM_MODE = "pywinrm"


class WinRMSource(DataSource):
    """WinRM data source for PowerShell-based checks."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._session: Optional[Any] = None
        self._available = True
        self._mode: Optional[str] = None  # subprocess or pywinrm

    @staticmethod
    def _sanitize_ps_string(value: str) -> str:
        """Sanitize a value for safe use inside PowerShell single-quoted strings."""
        return value.replace("'", "''")

    def connect(self) -> None:
        """Establish WinRM connection.

        Tries subprocess Invoke-Command first (Windows SSPI — works on domain-joined
        machines without explicit credentials). Falls back to pywinrm with explicit
        credentials if subprocess fails.
        """
        if not self.config.use_winrm:
            self._available = False
            logger.info("winrm_disabled", reason="--no-winrm flag set")
            return

        # ── Strategy 1: subprocess PowerShell Invoke-Command (Argus-AD approach) ──
        # Uses current Windows identity (Kerberos TGT) — no credential passing needed.
        # Only works on Windows with PowerShell available and a valid domain session.
        if sys.platform == "win32" and self._try_subprocess_connect():
            return

        # ── Strategy 2: pywinrm with explicit credentials ──
        self._try_pywinrm_connect()

    def _try_subprocess_connect(self) -> bool:
        """Test Invoke-Command connectivity using current Windows identity."""
        try:
            result = subprocess.run(
                [
                    "powershell", "-NonInteractive", "-NoProfile", "-Command",
                    f"Invoke-Command -ComputerName '{self._sanitize_ps_string(self.config.server)}'"
                    f" -ScriptBlock {{ $env:COMPUTERNAME }} -ErrorAction Stop",
                ],
                capture_output=True, text=True,
                timeout=self.config.timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                self._mode = _SUBPROCESS_MODE
                self._available = True
                logger.info("winrm_connected", server=self.config.server, transport="subprocess_invoke_command")
                return True
            logger.debug("winrm_subprocess_failed", stdout=result.stdout[:200], stderr=result.stderr[:200])
        except Exception as exc:
            logger.debug("winrm_subprocess_error", error=str(exc))
        return False

    def _try_pywinrm_connect(self) -> None:
        """Connect via pywinrm with explicit credentials."""
        try:
            import winrm

            protocol = "https" if self.config.winrm_ssl else "http"
            endpoint = f"{protocol}://{self.config.server}:{self.config.winrm_port}/wsman"
            username = self.config.get_winrm_username()
            password = self.config.get_winrm_password()

            transports = ["kerberos"] if self.config.auth_method.value == "kerberos" else ["ntlm", "negotiate"]

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
                    self._mode = _PYWINRM_MODE
                    logger.info("winrm_connected", server=self.config.server, transport=transport)
                    return
                except ImportError:
                    logger.debug("winrm_transport_unavailable", transport=transport, reason="missing package")
                except Exception as exc:
                    last_exc = exc
                    logger.debug("winrm_transport_failed", transport=transport, error=str(exc))

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
        if self._mode == _SUBPROCESS_MODE:
            return self._available
        return self._available and self._session is not None

    def run_powershell(self, command: str) -> Optional[str]:
        """Execute a PowerShell command on the remote host and return stdout."""
        if not self.is_connected():
            return None

        if self._mode == _SUBPROCESS_MODE:
            return self._run_subprocess_ps(command)
        return self._run_pywinrm_ps(command)

    def _run_subprocess_ps(self, command: str) -> Optional[str]:
        """Run command via Invoke-Command using current Windows identity."""
        try:
            # Wrap command in Invoke-Command for remote execution
            remote_cmd = (
                f"Invoke-Command -ComputerName '{self._sanitize_ps_string(self.config.server)}'"
                f" -ScriptBlock {{ {command} }} -ErrorAction SilentlyContinue"
            )
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", remote_cmd],
                capture_output=True, text=True,
                timeout=self.config.timeout + 10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            logger.warning("winrm_subprocess_command_error", command=command[:80], stderr=result.stderr[:200])
            return None
        except subprocess.TimeoutExpired:
            logger.warning("winrm_subprocess_timeout", command=command[:80])
            return None
        except Exception as e:
            logger.warning("winrm_subprocess_command_failed", command=command[:80], error=str(e))
            return None

    def _run_pywinrm_ps(self, command: str) -> Optional[str]:
        """Run command via pywinrm session."""
        try:
            result = self._session.run_ps(command)
            if result.status_code == 0:
                return result.std_out.decode("utf-8", errors="replace").strip()
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
