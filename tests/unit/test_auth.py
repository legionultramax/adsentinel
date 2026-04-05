"""Tests for authentication manager."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from adsentinel.auth.manager import AuthManager
from adsentinel.config import AuthMethod, ScanConfig
from adsentinel.exceptions import AuthenticationError


class TestAuthManager:
    def test_init(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        am = AuthManager(config)
        assert am.config == config

    def test_get_connection_info(self):
        config = ScanConfig(
            server="dc01.corp.com",
            domain="corp.com",
            username="scanner@corp.com",
        )
        am = AuthManager(config)
        info = am.get_connection_info()
        assert info["server"] == "dc01.corp.com"
        assert info["domain"] == "corp.com"
        assert info["username"] == "scanner@corp.com"
        assert info["auth_method"] == "simple"

    @patch("adsentinel.auth.manager.ldap3")
    def test_simple_bind_no_password_raises(self, mock_ldap3):
        config = ScanConfig(
            server="dc01", domain="corp.com",
            username="user@corp.com",
            password=SecretStr(""),
            auth_method=AuthMethod.SIMPLE,
        )
        am = AuthManager(config)
        with pytest.raises(AuthenticationError, match="Password required"):
            am.create_connection()

    @patch("adsentinel.auth.manager.ldap3")
    def test_ntlm_bind_no_password_raises(self, mock_ldap3):
        config = ScanConfig(
            server="dc01", domain="corp.com",
            username="user@corp.com",
            password=SecretStr(""),
            auth_method=AuthMethod.NTLM,
        )
        am = AuthManager(config)
        with pytest.raises(AuthenticationError, match="Password required"):
            am.create_connection()

    @patch("adsentinel.auth.manager.ldap3")
    def test_certificate_requires_ssl(self, mock_ldap3):
        config = ScanConfig(
            server="dc01", domain="corp.com",
            auth_method=AuthMethod.CERTIFICATE,
            use_ssl=False,
        )
        am = AuthManager(config)
        with pytest.raises(AuthenticationError, match="LDAPS"):
            am.create_connection()

    @patch("adsentinel.auth.manager.ldap3")
    def test_certificate_requires_cert_path(self, mock_ldap3):
        config = ScanConfig(
            server="dc01", domain="corp.com",
            auth_method=AuthMethod.CERTIFICATE,
            use_ssl=True,
            client_cert=None,
        )
        am = AuthManager(config)
        with pytest.raises(AuthenticationError, match="certificate path"):
            am.create_connection()

    @patch("adsentinel.auth.manager.ldap3")
    def test_simple_bind_success(self, mock_ldap3):
        config = ScanConfig(
            server="dc01", domain="corp.com",
            username="user@corp.com",
            password=SecretStr("Pass123"),
            auth_method=AuthMethod.SIMPLE,
        )
        mock_conn = MagicMock()
        mock_conn.bind.return_value = True
        mock_ldap3.Connection.return_value = mock_conn
        mock_ldap3.Server.return_value = MagicMock()

        am = AuthManager(config)
        conn = am.create_connection()
        assert conn == mock_conn

    @patch("adsentinel.auth.manager.ldap3")
    def test_simple_bind_failure(self, mock_ldap3):
        config = ScanConfig(
            server="dc01", domain="corp.com",
            username="user@corp.com",
            password=SecretStr("WrongPass"),
            auth_method=AuthMethod.SIMPLE,
        )
        mock_conn = MagicMock()
        mock_conn.bind.return_value = False
        mock_conn.result = {"description": "invalidCredentials"}
        mock_ldap3.Connection.return_value = mock_conn
        mock_ldap3.Server.return_value = MagicMock()

        am = AuthManager(config)
        with pytest.raises(AuthenticationError, match="SIMPLE bind failed"):
            am.create_connection()

    @patch("adsentinel.auth.manager.ldap3")
    def test_ntlm_username_conversion_upn(self, mock_ldap3):
        config = ScanConfig(
            server="dc01", domain="corp.com",
            username="user@corp.com",
            password=SecretStr("Pass123"),
            auth_method=AuthMethod.NTLM,
        )
        mock_conn = MagicMock()
        mock_conn.bind.return_value = True
        mock_ldap3.Connection.return_value = mock_conn
        mock_ldap3.Server.return_value = MagicMock()

        am = AuthManager(config)
        am.create_connection()

        # Verify DOMAIN\user format was used
        call_args = mock_ldap3.Connection.call_args
        assert "CORP\\" in call_args.kwargs.get("user", call_args[1].get("user", ""))
