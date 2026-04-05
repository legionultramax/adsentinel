"""Tests for configuration system."""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from adsentinel.config import AuthMethod, ScanConfig


class TestAuthMethod:
    def test_enum_values(self):
        assert AuthMethod.SIMPLE == "simple"
        assert AuthMethod.NTLM == "ntlm"
        assert AuthMethod.KERBEROS == "kerberos"
        assert AuthMethod.CERTIFICATE == "certificate"


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        assert config.port == 389
        assert config.use_ssl is False
        assert config.auth_method == AuthMethod.SIMPLE
        assert config.use_winrm is True
        assert config.max_concurrent == 10
        assert config.page_size == 1000
        assert config.timeout == 30

    def test_base_dn(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        assert config.base_dn == "DC=corp,DC=com"

    def test_base_dn_nested(self):
        config = ScanConfig(server="dc01", domain="sub.corp.com")
        assert config.base_dn == "DC=sub,DC=corp,DC=com"

    def test_config_dn(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        assert config.config_dn == "CN=Configuration,DC=corp,DC=com"

    def test_schema_dn(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        assert config.schema_dn == "CN=Schema,CN=Configuration,DC=corp,DC=com"

    def test_ssl_auto_port(self):
        config = ScanConfig(server="dc01", domain="corp.com", use_ssl=True)
        assert config.port == 636

    def test_ssl_explicit_port(self):
        config = ScanConfig(server="dc01", domain="corp.com", use_ssl=True, port=3269)
        assert config.port == 3269

    def test_winrm_ssl_auto_port(self):
        config = ScanConfig(server="dc01", domain="corp.com", winrm_ssl=True)
        assert config.winrm_port == 5986

    def test_empty_domain_base_dn(self):
        config = ScanConfig(server="dc01", domain="")
        assert config.base_dn == ""

    def test_credential_file(self):
        creds = {"username": "scanner@corp.com", "password": "Secret123"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(creds, f)
            f.flush()
            config = ScanConfig(
                server="dc01",
                domain="corp.com",
                credential_file=f.name,
            )
        assert config.username == "scanner@corp.com"
        assert config.password.get_secret_value() == "Secret123"

    def test_credential_file_does_not_override_explicit(self):
        creds = {"username": "file_user@corp.com", "password": "FilePass"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(creds, f)
            f.flush()
            config = ScanConfig(
                server="dc01",
                domain="corp.com",
                username="cli_user@corp.com",
                credential_file=f.name,
            )
        # CLI username takes precedence
        assert config.username == "cli_user@corp.com"

    def test_categories_list(self):
        config = ScanConfig(
            server="dc01", domain="corp.com",
            categories=["Password Policy", "Kerberos Security"],
        )
        assert len(config.categories) == 2

    def test_password_is_secret(self):
        from pydantic import SecretStr
        config = ScanConfig(server="dc01", domain="corp.com", password=SecretStr("secret"))
        # Password should not appear in string representation
        config_str = str(config.model_dump())
        assert "secret" not in config_str or "SecretStr" in config_str
