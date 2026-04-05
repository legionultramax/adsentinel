"""Authentication manager — dispatches to the appropriate auth strategy."""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Optional, Tuple

import ldap3

from adsentinel.config import AuthMethod, ScanConfig
from adsentinel.exceptions import AuthenticationError
from adsentinel.logging_config import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class AuthManager:
    """Factory that creates LDAP connections using the configured auth method."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def create_connection(self) -> ldap3.Connection:
        """Create and bind an LDAP connection using the configured auth method."""
        server = self._create_server()

        method = self.config.auth_method
        logger.info("authenticating", method=method.value, server=self.config.server)

        if method == AuthMethod.SIMPLE:
            return self._bind_simple(server)
        elif method == AuthMethod.NTLM:
            return self._bind_ntlm(server)
        elif method == AuthMethod.KERBEROS:
            return self._bind_kerberos(server)
        elif method == AuthMethod.CERTIFICATE:
            return self._bind_certificate(server)
        else:
            raise AuthenticationError(f"Unsupported auth method: {method}")

    def _create_server(self) -> ldap3.Server:
        """Create an LDAP server object."""
        use_ssl = self.config.use_ssl
        port = self.config.port

        return ldap3.Server(
            self.config.server,
            port=port,
            use_ssl=use_ssl,
            get_info=ldap3.ALL,
            connect_timeout=self.config.timeout,
        )

    def _bind_simple(self, server: ldap3.Server) -> ldap3.Connection:
        """SIMPLE bind with username and password."""
        password = self.config.password.get_secret_value()
        if not password:
            raise AuthenticationError("Password required for SIMPLE authentication")

        conn = ldap3.Connection(
            server,
            user=self.config.username,
            password=password,
            authentication=ldap3.SIMPLE,
            auto_bind=False,
            raise_exceptions=True,
            read_only=True,
        )

        if not conn.bind():
            raise AuthenticationError(
                f"SIMPLE bind failed: {conn.result.get('description', 'Unknown error')}"
            )

        logger.info("authenticated", method="SIMPLE", user=self.config.username)
        return conn

    def _bind_ntlm(self, server: ldap3.Server) -> ldap3.Connection:
        """NTLM bind with DOMAIN\\user format."""
        password = self.config.password.get_secret_value()
        if not password:
            raise AuthenticationError("Password required for NTLM authentication")

        # Ensure DOMAIN\user format
        username = self.config.username
        if "@" in username:
            # Convert user@domain to DOMAIN\user
            user_part, domain_part = username.split("@", 1)
            netbios = domain_part.split(".")[0].upper()
            username = f"{netbios}\\{user_part}"
        elif "\\" not in username:
            netbios = self.config.domain.split(".")[0].upper()
            username = f"{netbios}\\{username}"

        conn = ldap3.Connection(
            server,
            user=username,
            password=password,
            authentication=ldap3.NTLM,
            auto_bind=False,
            raise_exceptions=True,
            read_only=True,
        )

        if not conn.bind():
            raise AuthenticationError(
                f"NTLM bind failed: {conn.result.get('description', 'Unknown error')}"
            )

        logger.info("authenticated", method="NTLM", user=username)
        return conn

    def _bind_kerberos(self, server: ldap3.Server) -> ldap3.Connection:
        """Kerberos/GSSAPI bind using SASL."""
        try:
            conn = ldap3.Connection(
                server,
                authentication=ldap3.SASL,
                sasl_mechanism=ldap3.KERBEROS,
                auto_bind=False,
                raise_exceptions=True,
                read_only=True,
            )

            if not conn.bind():
                raise AuthenticationError(
                    f"Kerberos bind failed: {conn.result.get('description', 'Unknown error')}"
                )

            logger.info("authenticated", method="KERBEROS")
            return conn

        except ImportError:
            raise AuthenticationError(
                "Kerberos authentication requires 'gssapi' (Linux/macOS) or "
                "'winkerberos' (Windows). Install with: pip install adsentinel[kerberos]"
            )

    def _bind_certificate(self, server: ldap3.Server) -> ldap3.Connection:
        """Certificate-based authentication over LDAPS."""
        if not self.config.use_ssl:
            raise AuthenticationError("Certificate authentication requires LDAPS (--ssl)")
        if not self.config.client_cert:
            raise AuthenticationError("Client certificate path required (--client-cert)")

        tls = ldap3.Tls(
            local_certificate_file=self.config.client_cert,
            local_private_key_file=self.config.client_key,
            validate=ldap3.REQUIRED,
        )

        server = ldap3.Server(
            self.config.server,
            port=self.config.port,
            use_ssl=True,
            tls=tls,
            get_info=ldap3.ALL,
            connect_timeout=self.config.timeout,
        )

        conn = ldap3.Connection(
            server,
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.EXTERNAL,
            auto_bind=False,
            raise_exceptions=True,
            read_only=True,
        )

        if not conn.bind():
            raise AuthenticationError(
                f"Certificate bind failed: {conn.result.get('description', 'Unknown error')}"
            )

        logger.info("authenticated", method="CERTIFICATE")
        return conn

    def get_connection_info(self) -> Dict[str, str]:
        """Return connection metadata for reporting."""
        return {
            "server": self.config.server,
            "domain": self.config.domain,
            "port": str(self.config.port),
            "ssl": str(self.config.use_ssl),
            "auth_method": self.config.auth_method.value,
            "username": self.config.username,
        }
