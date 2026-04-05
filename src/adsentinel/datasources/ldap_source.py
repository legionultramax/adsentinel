"""LDAP data source — connection management, paged searches, and query caching.

This is the primary data source for ADSentinel. Every collector depends on it.
Supports connection pooling, automatic reconnection, paged searches, and
optional query result caching.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import ldap3
from ldap3 import ALL_ATTRIBUTES, SUBTREE

from adsentinel.auth.manager import AuthManager
from adsentinel.config import ScanConfig
from adsentinel.datasources.base import DataSource
from adsentinel.exceptions import ConnectionError, LDAPQueryError
from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


class LDAPSource(DataSource):
    """LDAP/LDAPS data source with paged search and caching."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._conn: Optional[ldap3.Connection] = None
        self._server_info: Optional[ldap3.ServerInfo] = None
        self._cache: Dict[str, List[Dict[str, Any]]] = {}
        self._auth_manager = AuthManager(config)

    def connect(self) -> None:
        """Establish LDAP connection."""
        try:
            self._conn = self._auth_manager.create_connection()
            self._server_info = self._conn.server.info
            logger.info(
                "ldap_connected",
                server=self.config.server,
                port=self.config.port,
                ssl=self.config.use_ssl,
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.config.server}:{self.config.port}: {e}")

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

    @property
    def connection(self) -> ldap3.Connection:
        """Get the active LDAP connection."""
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

    @property
    def config_dn(self) -> str:
        """Get the configuration DN."""
        return self.config.config_dn

    @property
    def schema_dn(self) -> str:
        """Get the schema DN."""
        return self.config.schema_dn

    def search(
        self,
        search_base: Optional[str] = None,
        search_filter: str = "(objectClass=*)",
        attributes: Optional[List[str]] = None,
        search_scope: int = SUBTREE,
        size_limit: int = 0,
        use_cache: bool = True,
    ) -> List[Dict[str, Any]]:
        """Execute a paged LDAP search and return results as dicts.

        Args:
            search_base: Base DN to search from (defaults to domain base DN)
            search_filter: LDAP filter string
            attributes: Attributes to return (None = all)
            search_scope: SUBTREE, LEVEL, or BASE
            size_limit: Max results (0 = unlimited)
            use_cache: Whether to cache/return cached results

        Returns:
            List of dicts, each representing an LDAP entry
        """
        base = search_base or self.base_dn
        attrs = attributes or [ALL_ATTRIBUTES]

        # Check cache
        cache_key = f"{base}|{search_filter}|{attrs}|{search_scope}"
        if use_cache and cache_key in self._cache:
            logger.debug("cache_hit", filter=search_filter)
            return self._cache[cache_key]

        try:
            # Use paged search for large result sets
            entry_generator = self.connection.extend.standard.paged_search(
                search_base=base,
                search_filter=search_filter,
                attributes=attrs,
                search_scope=search_scope,
                paged_size=self.config.page_size,
                paged_cookie=None,
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

            logger.debug("ldap_search", filter=search_filter, results=len(results))

            # Cache results
            if use_cache:
                self._cache[cache_key] = results

            return results

        except ldap3.core.exceptions.LDAPException as e:
            raise LDAPQueryError(search_filter, str(e))

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
                # Keep binary data as-is (for SIDs, security descriptors, etc.)
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
