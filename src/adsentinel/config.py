"""Configuration system using Pydantic BaseSettings.

Credentials are loaded from environment variables or credential files — NEVER from CLI args
visible in process listings. The priority order is:
1. Environment variables (ADSENTINEL_*)
2. Credential YAML file (--credential-file)
3. CLI arguments (non-sensitive only)
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings


class AuthMethod(str, Enum):
    """Supported authentication methods."""

    SIMPLE = "simple"
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    CERTIFICATE = "certificate"


class ScanConfig(BaseSettings):
    """Main configuration for ADSentinel scans.

    Sensitive values (password, hashes) are read from env vars or credential files,
    never exposed in process listings.
    """

    # Connection
    server: str = Field(default="", description="Domain Controller IP or hostname")
    domain: str = Field(default="", description="AD domain name (e.g., corp.com)")
    port: int = Field(default=389, description="LDAP port")
    use_ssl: bool = Field(default=False, description="Use LDAPS (port 636)")
    timeout: int = Field(default=30, description="Connection timeout in seconds")

    # Authentication
    username: str = Field(default="", description="Username (user@domain or DOMAIN\\user)")
    password: SecretStr = Field(default=SecretStr(""), description="Password (prefer env var ADSENTINEL_PASSWORD)")
    auth_method: AuthMethod = Field(default=AuthMethod.SIMPLE, description="Authentication method")
    credential_file: Optional[str] = Field(default=None, description="Path to YAML credential file")
    client_cert: Optional[str] = Field(default=None, description="Path to client certificate for cert auth")
    client_key: Optional[str] = Field(default=None, description="Path to client private key")

    # WinRM
    use_winrm: bool = Field(default=True, description="Enable WinRM-based checks")
    winrm_port: int = Field(default=5985, description="WinRM port")
    winrm_ssl: bool = Field(default=False, description="Use WinRM over HTTPS")

    # Scan scope
    categories: List[str] = Field(default_factory=list, description="Check categories to run (empty = all)")
    check_ids: List[str] = Field(default_factory=list, description="Specific check IDs to run")
    exclude_categories: List[str] = Field(default_factory=list, description="Categories to exclude")

    # Performance
    max_concurrent: int = Field(default=10, description="Max concurrent LDAP queries")
    page_size: int = Field(default=1000, description="LDAP paged search size")

    # Output
    html_output: Optional[str] = Field(default=None, description="HTML report output path")
    json_output: Optional[str] = Field(default=None, description="JSON report output path")
    csv_output: Optional[str] = Field(default=None, description="CSV report output path")
    pdf_output: Optional[str] = Field(default=None, description="PDF executive summary output path")
    sarif_output: Optional[str] = Field(default=None, description="SARIF output path")
    bloodhound_output: Optional[str] = Field(default=None, description="BloodHound JSON output path")

    # Differential scanning
    baseline_input: Optional[str] = Field(default=None, description="Previous baseline for comparison")
    baseline_output: Optional[str] = Field(default=None, description="Save current scan as baseline")

    # Logging
    verbose: bool = Field(default=False, description="Enable verbose logging")

    model_config = {
        "env_prefix": "ADSENTINEL_",
        "env_file": ".env",
        "case_sensitive": False,
    }

    @field_validator("port", mode="before")
    @classmethod
    def resolve_port(cls, v: int, info: object) -> int:
        return v

    @model_validator(mode="after")
    def apply_ssl_defaults(self) -> "ScanConfig":
        """Set default port for SSL and WinRM SSL."""
        if self.use_ssl and self.port == 389:
            self.port = 636
        if self.winrm_ssl and self.winrm_port == 5985:
            self.winrm_port = 5986
        return self

    @model_validator(mode="after")
    def load_credential_file(self) -> "ScanConfig":
        """Load credentials from YAML file if specified."""
        if self.credential_file:
            path = Path(self.credential_file)
            if path.exists():
                with open(path) as f:
                    creds = yaml.safe_load(f)
                if creds:
                    if "username" in creds and not self.username:
                        self.username = creds["username"]
                    if "password" in creds and not self.password.get_secret_value():
                        self.password = SecretStr(creds["password"])
                    if "server" in creds and not self.server:
                        self.server = creds["server"]
                    if "domain" in creds and not self.domain:
                        self.domain = creds["domain"]
        return self

    @property
    def base_dn(self) -> str:
        """Convert domain name to LDAP base DN."""
        if not self.domain:
            return ""
        parts = self.domain.split(".")
        return ",".join(f"DC={p}" for p in parts)

    @property
    def config_dn(self) -> str:
        """Configuration naming context."""
        return f"CN=Configuration,{self.base_dn}"

    @property
    def schema_dn(self) -> str:
        """Schema naming context."""
        return f"CN=Schema,{self.config_dn}"
