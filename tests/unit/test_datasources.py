"""Tests for data sources (LDAP, WinRM)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from adsentinel.config import ScanConfig
from adsentinel.datasources.ldap_source import LDAPSource
from adsentinel.datasources.winrm_source import WinRMSource
from adsentinel.exceptions import ConnectionError


class TestLDAPSource:
    def test_init(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        assert ldap._conn is None
        assert ldap._cache == {}

    def test_not_connected_initially(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        assert not ldap.is_connected()

    def test_connection_property_raises_when_not_connected(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        with pytest.raises(ConnectionError):
            _ = ldap.connection

    def test_base_dn(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        assert ldap.base_dn == "DC=corp,DC=com"

    def test_config_dn(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        assert ldap.config_dn == "CN=Configuration,DC=corp,DC=com"

    def test_schema_dn(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        assert ldap.schema_dn == "CN=Schema,CN=Configuration,DC=corp,DC=com"

    def test_clear_cache(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        ldap._cache["test_key"] = [{"dn": "test"}]
        ldap.clear_cache()
        assert ldap._cache == {}

    def test_get_attribute(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        entry = {"attributes": {"sAMAccountName": ["testuser"]}}
        assert ldap.get_attribute(entry, "sAMAccountName") == "testuser"

    def test_get_attribute_default(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        entry = {"attributes": {}}
        assert ldap.get_attribute(entry, "missing", "default") == "default"

    def test_get_attribute_list(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        entry = {"attributes": {"memberOf": ["CN=DA", "CN=EA"]}}
        result = ldap.get_attribute_list(entry, "memberOf")
        assert len(result) == 2

    def test_get_attribute_list_single(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        entry = {"attributes": {"name": "single_value"}}
        result = ldap.get_attribute_list(entry, "name")
        assert result == ["single_value"]

    def test_get_attribute_list_missing(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        entry = {"attributes": {}}
        assert ldap.get_attribute_list(entry, "missing") == []

    def test_normalize_attributes_bytes(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        attrs = {"objectSid": b"\x01\x05\x00"}
        result = ldap._normalize_attributes(attrs)
        assert result["objectSid"] == b"\x01\x05\x00"

    def test_normalize_attributes_list(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        attrs = {"memberOf": ["CN=Group1", "CN=Group2"]}
        result = ldap._normalize_attributes(attrs)
        assert len(result["memberOf"]) == 2

    def test_normalize_attributes_none(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        attrs = {"empty": None}
        result = ldap._normalize_attributes(attrs)
        assert result["empty"] is None

    def test_disconnect_when_not_connected(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)
        # Should not raise
        ldap.disconnect()

    def test_search_single_returns_none_on_empty(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)

        # Mock the search method
        with patch.object(ldap, "search", return_value=[]):
            result = ldap.search_single(search_filter="(cn=nonexistent)")
            assert result is None

    def test_search_single_returns_first(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        ldap = LDAPSource(config)

        entry = {"dn": "CN=test", "attributes": {"cn": "test"}}
        with patch.object(ldap, "search", return_value=[entry]):
            result = ldap.search_single(search_filter="(cn=test)")
            assert result == entry


class TestWinRMSource:
    def test_init(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        winrm = WinRMSource(config)
        assert winrm._session is None
        assert winrm._available is True

    def test_not_connected_initially(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        winrm = WinRMSource(config)
        assert not winrm.is_connected()

    def test_disabled_by_config(self):
        config = ScanConfig(server="dc01", domain="corp.com", use_winrm=False)
        winrm = WinRMSource(config)
        winrm.connect()
        assert not winrm._available

    def test_run_powershell_returns_none_when_not_connected(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        winrm = WinRMSource(config)
        assert winrm.run_powershell("Get-Process") is None

    def test_run_powershell_json_returns_none_when_not_connected(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        winrm = WinRMSource(config)
        assert winrm.run_powershell_json("Get-Service") is None

    def test_disconnect(self):
        config = ScanConfig(server="dc01", domain="corp.com")
        winrm = WinRMSource(config)
        winrm.disconnect()
        assert winrm._session is None
