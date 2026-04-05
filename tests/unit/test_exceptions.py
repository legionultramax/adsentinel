"""Tests for custom exception hierarchy."""

from adsentinel.exceptions import (
    ADSentinelError,
    AuthenticationError,
    CheckExecutionError,
    CollectorError,
    ConfigurationError,
    ConnectionError,
    LDAPQueryError,
    ReportGenerationError,
    WinRMError,
)


class TestExceptions:
    def test_base_exception(self):
        e = ADSentinelError("test")
        assert str(e) == "test"
        assert isinstance(e, Exception)

    def test_authentication_error(self):
        e = AuthenticationError("bad creds")
        assert isinstance(e, ADSentinelError)

    def test_connection_error(self):
        e = ConnectionError("refused")
        assert isinstance(e, ADSentinelError)

    def test_configuration_error(self):
        e = ConfigurationError("missing field")
        assert isinstance(e, ADSentinelError)

    def test_check_execution_error(self):
        e = CheckExecutionError("PP-001", "division by zero")
        assert "PP-001" in str(e)
        assert e.check_id == "PP-001"

    def test_collector_error(self):
        e = CollectorError("UserCollector", "timeout")
        assert "UserCollector" in str(e)
        assert e.collector_name == "UserCollector"

    def test_report_generation_error(self):
        e = ReportGenerationError("template missing")
        assert isinstance(e, ADSentinelError)

    def test_ldap_query_error(self):
        e = LDAPQueryError("(objectClass=user)", "timeout")
        assert "objectClass=user" in str(e)
        assert e.filter_str == "(objectClass=user)"

    def test_winrm_error(self):
        e = WinRMError("Get-Process", "access denied")
        assert e.command == "Get-Process"
        assert "access denied" in str(e)
