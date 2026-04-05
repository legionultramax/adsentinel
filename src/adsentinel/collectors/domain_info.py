"""Collector for domain-level metadata — functional level, FSMO, DCs, Recycle Bin."""

from __future__ import annotations

from typing import TYPE_CHECKING

from adsentinel.collectors.base import BaseCollector
from adsentinel.constants import FUNCTIONAL_LEVELS
from adsentinel.logging_config import get_logger
from adsentinel.models.domain import DomainController, DomainInfo
from adsentinel.utils.ldap_filter import and_filter, eq

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)


class DomainInfoCollector(BaseCollector):
    """Collects domain-level configuration and metadata."""

    name = "domain_info"
    description = "Domain configuration, functional level, DCs, and features"

    def collect(self, context: SharedContext) -> None:
        """Collect domain info and store in context."""
        info = DomainInfo()

        # Get domain base info from config
        info.base_dn = self.ldap.base_dn
        info.config_dn = self.ldap.config_dn
        info.schema_dn = self.ldap.schema_dn
        info.dns_name = self.ldap.config.domain

        # Read domain object
        domain_entry = self.ldap.search_single(
            search_base=self.ldap.base_dn,
            search_filter="(objectClass=domain)",
            attributes=[
                "distinguishedName", "objectSid", "msDS-Behavior-Version",
                "ms-DS-MachineAccountQuota", "name",
            ],
        )

        if domain_entry:
            attrs = domain_entry.get("attributes", {})
            fl = attrs.get("msDS-Behavior-Version", 0)
            if isinstance(fl, list):
                fl = fl[0] if fl else 0
            info.domain_functional_level = int(fl)
            info.domain_functional_level_name = FUNCTIONAL_LEVELS.get(int(fl), f"Unknown ({fl})")

            maq = attrs.get("ms-DS-MachineAccountQuota", 10)
            if isinstance(maq, list):
                maq = maq[0] if maq else 10
            info.machine_account_quota = int(maq)

            sid_raw = attrs.get("objectSid")
            if sid_raw and isinstance(sid_raw, bytes):
                from adsentinel.utils.sid import parse_binary_sid
                info.domain_sid = parse_binary_sid(sid_raw)

        # Check AD Recycle Bin
        recycle_bin_entry = self.ldap.search_single(
            search_base=f"CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{self.ldap.config_dn}",
            search_filter="(objectClass=*)",
            attributes=["msDS-EnabledFeatureBL"],
        )
        if recycle_bin_entry:
            bl = recycle_bin_entry.get("attributes", {}).get("msDS-EnabledFeatureBL", [])
            info.ad_recycle_bin_enabled = len(bl) > 0 if isinstance(bl, list) else bool(bl)

        # Enumerate Domain Controllers
        dc_filter = and_filter([
            eq("objectCategory", "computer"),
            eq("userAccountControl:1.2.840.113556.1.4.803:", "8192"),
        ])

        dc_entries = self.ldap.search(
            search_filter=dc_filter,
            attributes=[
                "distinguishedName", "dNSHostName", "operatingSystem",
                "operatingSystemVersion", "msDS-isRODC", "serverReferenceBL",
            ],
        )

        for dc_entry in dc_entries:
            attrs = dc_entry.get("attributes", {})
            dc = DomainController(
                hostname=self._get_str(attrs, "dNSHostName"),
                dn=dc_entry.get("dn", ""),
                os_version=self._get_str(attrs, "operatingSystem"),
                is_read_only=self._get_bool(attrs, "msDS-isRODC"),
            )
            info.domain_controllers.append(dc)

        # Forest functional level from RootDSE
        root_dse = self.ldap.get_root_dse()
        if root_dse:
            root_attrs = root_dse.get("attributes", {})
            ffl = root_attrs.get("forestFunctionality", 0)
            if isinstance(ffl, list):
                ffl = ffl[0] if ffl else 0
            info.forest_functional_level = int(ffl)
            info.forest_functional_level_name = FUNCTIONAL_LEVELS.get(int(ffl), f"Unknown ({ffl})")

            forest_dn = root_attrs.get("rootDomainNamingContext", "")
            if isinstance(forest_dn, list):
                forest_dn = forest_dn[0] if forest_dn else ""
            info.forest_name = str(forest_dn)

        context.domain_info = info
        logger.info(
            "collected_domain_info",
            domain=info.dns_name,
            functional_level=info.domain_functional_level_name,
            dc_count=len(info.domain_controllers),
        )

    def _get_str(self, attrs: dict, key: str) -> str:
        val = attrs.get(key, "")
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""

    def _get_bool(self, attrs: dict, key: str) -> bool:
        val = attrs.get(key, False)
        if isinstance(val, list):
            val = val[0] if val else False
        return bool(val)
