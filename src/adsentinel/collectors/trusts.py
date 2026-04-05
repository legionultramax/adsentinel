"""Collector for domain trust relationships."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from adsentinel.collectors.base import BaseCollector
from adsentinel.logging_config import get_logger
from adsentinel.models.domain import ADTrust
from adsentinel.utils.ldap_filter import eq
from adsentinel.utils.time_utils import generalized_time_to_datetime

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)


class TrustCollector(BaseCollector):
    """Collects domain and forest trust relationships."""

    name = "trusts"
    description = "Domain/forest trust relationships and configuration"

    def collect(self, context: SharedContext) -> None:
        entries = self.ldap.search(
            search_base=f"CN=System,{self.ldap.base_dn}",
            search_filter=eq("objectClass", "trustedDomain"),
            attributes=[
                "distinguishedName", "trustPartner", "trustDirection",
                "trustType", "trustAttributes", "securityIdentifier",
                "whenCreated",
            ],
        )

        trusts = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            trust = ADTrust(
                dn=entry.get("dn", ""),
                trusted_domain=self._get_str(attrs, "trustPartner"),
                trust_direction=self._get_int(attrs, "trustDirection"),
                trust_type=self._get_int(attrs, "trustType"),
                trust_attributes=self._get_int(attrs, "trustAttributes"),
                sid_filtering_enabled=bool(self._get_int(attrs, "trustAttributes") & 0x4),
                selective_auth=bool(self._get_int(attrs, "trustAttributes") & 0x20),
                when_created=generalized_time_to_datetime(self._get_str(attrs, "whenCreated")),
            )
            trusts.append(trust)

        context.trusts = trusts
        logger.info("collected_trusts", count=len(trusts))

    def _get_str(self, attrs: dict, key: str) -> str:
        val = attrs.get(key, "")
        return str(val[0]) if isinstance(val, list) and val else str(val) if val else ""

    def _get_int(self, attrs: dict, key: str) -> int:
        val = attrs.get(key, 0)
        if isinstance(val, list):
            val = val[0] if val else 0
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0
