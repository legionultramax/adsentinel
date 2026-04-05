"""Collector for Group Policy Objects."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from adsentinel.collectors.base import BaseCollector
from adsentinel.logging_config import get_logger
from adsentinel.utils.ldap_filter import eq

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)


class GPOCollector(BaseCollector):
    """Collects Group Policy Objects and their configurations."""

    name = "gpos"
    description = "Group Policy Objects, links, and security settings"

    def collect(self, context: SharedContext) -> None:
        entries = self.ldap.search(
            search_filter=eq("objectClass", "groupPolicyContainer"),
            attributes=[
                "distinguishedName", "displayName", "gPCFileSysPath",
                "flags", "versionNumber", "whenCreated", "whenChanged",
                "gPCMachineExtensionNames", "gPCUserExtensionNames",
            ],
        )

        gpos = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            flags = self._get_int(attrs, "flags")
            gpo = {
                "dn": entry.get("dn", ""),
                "display_name": self._get_str(attrs, "displayName"),
                "file_sys_path": self._get_str(attrs, "gPCFileSysPath"),
                "flags": flags,
                "version": self._get_int(attrs, "versionNumber"),
                "is_disabled": flags == 3,
                "user_disabled": bool(flags & 1),
                "computer_disabled": bool(flags & 2),
            }
            gpos.append(gpo)

        context.gpos = gpos
        logger.info("collected_gpos", count=len(gpos))

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
