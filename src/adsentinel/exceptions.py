"""Custom exception hierarchy for ADSentinel."""


class ADSentinelError(Exception):
    """Base exception for all ADSentinel errors."""


class AuthenticationError(ADSentinelError):
    """Failed to authenticate to the target domain."""


class ConnectionError(ADSentinelError):
    """Failed to connect to the domain controller."""


class ConfigurationError(ADSentinelError):
    """Invalid or missing configuration."""


class CheckExecutionError(ADSentinelError):
    """A security check failed during execution."""

    def __init__(self, check_id: str, message: str) -> None:
        self.check_id = check_id
        super().__init__(f"[{check_id}] {message}")


class CollectorError(ADSentinelError):
    """A data collector failed during execution."""

    def __init__(self, collector_name: str, message: str) -> None:
        self.collector_name = collector_name
        super().__init__(f"Collector '{collector_name}': {message}")


class ReportGenerationError(ADSentinelError):
    """Failed to generate a report."""


class LDAPQueryError(ADSentinelError):
    """An LDAP query failed."""

    def __init__(self, filter_str: str, message: str) -> None:
        self.filter_str = filter_str
        super().__init__(f"LDAP query failed ({filter_str}): {message}")


class WinRMError(ADSentinelError):
    """A WinRM command failed."""

    def __init__(self, command: str, message: str) -> None:
        self.command = command
        super().__init__(f"WinRM error: {message}")
