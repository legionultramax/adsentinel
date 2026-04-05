"""Tests for CLI commands including preflight."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from adsentinel.cli import cli


class TestCLIRoot:
    def test_no_args_shows_banner(self):
        runner = CliRunner()
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        assert "adsentinel" in result.output.lower() or "Version" in result.output

    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "ADSentinel" in result.output

    def test_version_command(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "ADSentinel" in result.output
        assert "Elite" in result.output


class TestChecksCommand:
    @patch("adsentinel.engine.plugin_loader.discover_checks")
    @patch("adsentinel.checks.registry.CheckRegistry.get_all_checks")
    @patch("adsentinel.checks.registry.CheckRegistry.summary")
    def test_checks_list(self, mock_summary, mock_get_all, mock_discover):
        mock_check = MagicMock()
        mock_check.id = "PP-001"
        mock_check.name = "Test Check"
        mock_check.category = "Password Policy"
        mock_get_all.return_value = [mock_check]
        mock_summary.return_value = {"Password Policy": 1}

        runner = CliRunner()
        result = runner.invoke(cli, ["checks", "--list"])
        assert result.exit_code == 0
        assert "PP-001" in result.output

    @patch("adsentinel.engine.plugin_loader.discover_checks")
    @patch("adsentinel.checks.registry.CheckRegistry.get_all_checks")
    @patch("adsentinel.checks.registry.CheckRegistry.summary")
    def test_checks_filter_category(self, mock_summary, mock_get_all, mock_discover):
        mock_check = MagicMock()
        mock_check.id = "KRB-001"
        mock_check.name = "Kerberoasting"
        mock_check.category = "Kerberos Security"
        mock_get_all.return_value = [mock_check]
        mock_summary.return_value = {"Kerberos Security": 1}

        runner = CliRunner()
        result = runner.invoke(cli, ["checks", "--list", "--category", "Kerberos Security"])
        assert result.exit_code == 0


class TestPreflightCommand:
    @patch("adsentinel.datasources.winrm_source.WinRMSource")
    @patch("adsentinel.datasources.ldap_source.LDAPSource.connect")
    @patch("adsentinel.datasources.ldap_source.LDAPSource.search")
    @patch("adsentinel.datasources.ldap_source.LDAPSource.get_root_dse")
    @patch("adsentinel.datasources.ldap_source.LDAPSource.get_attribute")
    @patch("adsentinel.datasources.ldap_source.LDAPSource.disconnect")
    @patch("socket.create_connection")
    @patch("socket.gethostbyname")
    def test_preflight_all_pass(self, mock_dns, mock_tcp, mock_ldap_disconnect,
                                 mock_ldap_getattr, mock_ldap_rootdse,
                                 mock_ldap_search, mock_ldap_connect, mock_winrm_cls):
        mock_dns.return_value = "10.0.0.1"
        mock_sock = MagicMock()
        mock_tcp.return_value = mock_sock

        mock_ldap_search.return_value = [{"dn": "DC=corp,DC=com", "attributes": {"distinguishedName": "DC=corp,DC=com"}}]
        mock_ldap_rootdse.return_value = {"dn": "", "attributes": {"namingContexts": ["DC=corp,DC=com"]}}
        mock_ldap_getattr.return_value = "testuser"

        runner = CliRunner()
        result = runner.invoke(cli, [
            "preflight",
            "--server", "dc01.corp.com",
            "--domain", "corp.com",
            "--username", "scanner@corp.com",
            "--no-winrm",
        ], env={"ADSENTINEL_PASSWORD": "TestPass123"})

        assert "READY" in result.output or result.exit_code == 0

    @patch("socket.gethostbyname")
    def test_preflight_dns_fails(self, mock_dns):
        import socket
        mock_dns.side_effect = socket.gaierror("Name resolution failed")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "preflight",
            "--server", "nonexistent.invalid",
            "--domain", "corp.com",
            "--username", "scanner@corp.com",
            "--no-winrm",
        ], env={"ADSENTINEL_PASSWORD": "TestPass123"})

        assert result.exit_code != 0 or "Cannot resolve" in result.output

    @patch("socket.create_connection")
    @patch("socket.gethostbyname")
    def test_preflight_tcp_fails(self, mock_dns, mock_tcp):
        import socket
        mock_dns.return_value = "10.0.0.1"
        mock_tcp.side_effect = socket.timeout("Connection timed out")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "preflight",
            "--server", "dc01.corp.com",
            "--domain", "corp.com",
            "--username", "scanner@corp.com",
            "--no-winrm",
        ], env={"ADSENTINEL_PASSWORD": "TestPass123"})

        assert "Cannot connect" in result.output or "NOT READY" in result.output

    @patch("socket.create_connection")
    @patch("socket.gethostbyname")
    def test_preflight_with_ip_address(self, mock_dns, mock_tcp):
        import socket
        mock_dns.side_effect = socket.gaierror("Not a hostname")
        mock_tcp.side_effect = socket.timeout("Refused")

        runner = CliRunner()
        result = runner.invoke(cli, [
            "preflight",
            "--server", "10.0.0.1",
            "--domain", "corp.com",
            "--username", "scanner@corp.com",
            "--no-winrm",
        ], env={"ADSENTINEL_PASSWORD": "TestPass123"})

        assert "10.0.0.1" in result.output
