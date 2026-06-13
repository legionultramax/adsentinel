"""LDAP data source — connection management, paged searches, and query caching.

Enhanced with retry logic, automatic reconnection, and partial result tracking for resilience.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import time

import ldap3
from ldap3 import ALL_ATTRIBUTES, SUBTREE

from adsentinel.auth.manager import AuthManager
from adsentinel.config import ScanConfig
from adsentinel.datasources.base import DataSource
from adsentinel.exceptions import ConnectionError, LDAPQueryError
from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


class LDAPSource(DataSource):
    """LDAP/LDAPS data source with paged search, caching, and resilience."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._conn: Optional[ldap3.Connection] = None
        self._server_info: Optional[ldap3.ServerInfo] = None
        self._cache: Dict[str, List[Dict[str, Any]]] = {}
        self._auth_manager = AuthManager(config)
        self._retry_count = 3
        self._retry_delay = 2  # seconds, with backoff

    def connect(self, retries: Optional[int] = None) -> None:
        """Establish LDAP connection with retries."""
        retry_count = retries or self._retry_count
        last_error = None

        for attempt in range(1, retry_count + 1):
            try:
                self._conn = self._auth_manager.create_connection()
                self._server_info = self._conn.server.info
                logger.info(
                    "ldap_connected",
                    server=self.config.server,
                    port=self.config.port,
                    ssl=self.config.use_ssl,
                    attempt=attempt,
                )
                return
            except Exception as e:
                last_error = e
                if attempt < retry_count:
                    delay = self._retry_delay * (2 ** (attempt - 1))
                    logger.warning(
                        "ldap_connect_retry",
                        attempt=attempt,
                        max_retries=retry_count,
                        delay=delay,
                        error=str(e),
                    )
                    time.sleep(delay)
                else:
                    logger.error("ldap_connect_failed", error=str(e))

        raise ConnectionError(f"Failed to connect to {self.config.server}:{self.config.port} after {retry_count} attempts: {last_error}")

    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass
            self._conn = None
            logger.info("ldap_disconnected")

    def is_connected(self) -> bool:
        """Check if LDAP connection is active."""
        return self._conn is not None and self._conn.bound

    def _ensure_connection(self) -> None:
        """Reconnect if connection dropped."""
        if not self.is_connected():
            logger.warning("ldap_reconnecting")
            self.connect()

    @property
    def connection(self) -> ldap3.Connection:
        """Get the active LDAP connection with auto-reconnect."""
        self._ensure_connection()
        if not self.is_connected():
            raise ConnectionError("LDAP connection not established. Call connect() first.")
        return self._conn  # type: ignore

    @property
    def server_info(self) -> Optional[Any]:
        """Get server info from the LDAP connection."""
        return self._server_info

    @property
    def base_dn(self) -> str:
        """Get the base DN from config."""
        return self.config.base_dn

    def search(
        self,
        search_base: Optional[str] = None,
        search_filter: str = "(objectClass=*)",
        attributes: Optional[List[str]] = None,
        search_scope: int = SUBTREE,
        size_limit: int = 0,
        use_cache: bool = True,
    ) -> List[Dict[str, Any]]:
        """Execute a paged LDAP search with modern ldap3 compatibility."""
        base = search_base or self.base_dn
        attrs = attributes or [ALL_ATTRIBUTES]

        cache_key = f"{base}|{search_filter}|{attrs}|{search_scope}"
        if use_cache and cache_key in self._cache:
            logger.debug("cache_hit", filter=search_filter)
            return self._cache[cache_key]

        try:
            self._ensure_connection()

            # Modern paged search (fixed for current ldap3 versions)
            entry_generator = self.connection.extend.standard.paged_search(
                search_base=base,
                search_filter=search_filter,
                attributes=attrs,
                search_scope=search_scope,
                paged_size=self.config.page_size,
                generator=True,
            )

            results = []
            count = 0

            for entry in entry_generator:
                if entry.get("type") != "searchResEntry":
                    continue

                entry_dict = {
                    "dn": entry.get("dn", ""),
                    "attributes": self._normalize_attributes(entry.get("attributes", {})),
                }
                results.append(entry_dict)
                count += 1

                if size_limit and count >= size_limit:
                    break

            logger.info(
                "ldap_search_complete",
                filter=search_filter,
                results=len(results),
            )

            if use_cache:
                self._cache[cache_key] = results

            return results

        except ldap3.core.exceptions.LDAPException as e:
            logger.error("ldap_search_error", filter=search_filter, error=str(e))
            raise LDAPQueryError(search_filter, str(e))
        except Exception as e:
            logger.error("ldap_search_unexpected", filter=search_filter, error=str(e))
            raise

    def search_single(
        self,
        search_base: Optional[str] = None,
        search_filter: str = "(objectClass=*)",
        attributes: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Search and return a single entry, or None."""
        results = self.search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes,
            size_limit=1,
        )
        return results[0] if results else None

    def get_root_dse(self) -> Dict[str, Any]:
        """Read the RootDSE entry for server metadata."""
        try:
            self._ensure_connection()
            self.connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=[ALL_ATTRIBUTES],
            )
            if self.connection.entries:
                entry = self.connection.entries[0]
                return {
                    "dn": str(entry.entry_dn),
                    "attributes": self._normalize_attributes(entry.entry_attributes_as_dict),
                }
        except Exception as e:
            logger.warning("rootdse_failed", error=str(e))
        return {"dn": "", "attributes": {}}

    def get_attribute(self, entry: Dict[str, Any], attr_name: str, default: Any = None) -> Any:
        """Safely get an attribute value from an LDAP entry dict."""
        attrs = entry.get("attributes", {})
        val = attrs.get(attr_name, default)
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val

    def get_attribute_list(self, entry: Dict[str, Any], attr_name: str) -> List[Any]:
        """Get an attribute value as a list."""
        attrs = entry.get("attributes", {})
        val = attrs.get(attr_name, [])
        if not isinstance(val, list):
            return [val] if val else []
        return val

    def clear_cache(self) -> None:
        """Clear the query result cache."""
        self._cache.clear()

    def _normalize_attributes(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize LDAP attribute values for consistent handling."""
        normalized = {}
        for key, value in attrs.items():
            if isinstance(value, bytes):
                normalized[key] = value
            elif isinstance(value, list):
                normalized[key] = [
                    v if isinstance(v, (bytes, int, bool)) else str(v) for v in value
                ]
            elif value is not None:
                normalized[key] = value
            else:
                normalized[key] = None
        return normalized