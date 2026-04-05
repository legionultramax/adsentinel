"""Collector for AD-integrated DNS zones."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from adsentinel.collectors.base import BaseCollector
from adsentinel.logging_config import get_logger
from adsentinel.utils.ldap_filter import eq

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)


class DNSCollector(BaseCollector):
    """Collects AD-integrated DNS zone configuration."""

    name = "dns"
    description = "AD-integrated DNS zones and security settings"

    def collect(self, context: SharedContext) -> None:
        entries = self.ldap.search(
            search_base=f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.ldap.base_dn}",
            search_filter=eq("objectClass", "dnsZone"),
            attributes=[
                "distinguishedName", "name", "dNSProperty",
            ],
        )

        zones = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            zone = {
                "dn": entry.get("dn", ""),
                "name": self._get_str(attrs, "name"),
            }
            zones.append(zone)

        context.dns_zones = zones
        logger.info("collected_dns_zones", count=len(zones))

    def _get_str(self, attrs: dict, key: str) -> str:
        val = attrs.get(key, "")
        return str(val[0]) if isinstance(val, list) and val else str(val) if val else ""
