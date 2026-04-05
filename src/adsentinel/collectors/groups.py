"""Collector for group objects and membership resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from adsentinel.collectors.base import BaseCollector
from adsentinel.constants import (
    RID_DOMAIN_ADMINS,
    RID_ENTERPRISE_ADMINS,
    RID_SCHEMA_ADMINS,
    PRIVILEGED_GROUP_RIDS,
)
from adsentinel.logging_config import get_logger
from adsentinel.models.domain import ADGroup
from adsentinel.utils.ldap_filter import and_filter, eq
from adsentinel.utils.sid import get_rid, parse_binary_sid
from adsentinel.utils.time_utils import generalized_time_to_datetime

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)

GROUP_ATTRIBUTES = [
    "distinguishedName", "sAMAccountName", "objectSid", "groupType",
    "member", "memberOf", "adminCount", "description", "whenCreated",
]


class GroupCollector(BaseCollector):
    """Collects all security groups and resolves membership."""

    name = "groups"
    description = "Security groups, membership, and privileged group identification"

    def collect(self, context: SharedContext) -> None:
        """Collect groups and resolve privileged membership."""
        group_filter = eq("objectCategory", "group")

        entries = self.ldap.search(
            search_filter=group_filter,
            attributes=GROUP_ATTRIBUTES,
        )

        groups = []
        groups_by_dn: Dict[str, ADGroup] = {}

        for entry in entries:
            group = self._parse_group(entry)
            if group:
                groups.append(group)
                groups_by_dn[group.dn] = group

        context.groups = groups

        # Identify privileged groups and build membership map
        domain_sid = context.domain_info.domain_sid
        for group in groups:
            rid = get_rid(group.sid) if group.sid else None
            if rid in PRIVILEGED_GROUP_RIDS:
                context.privileged_groups[group.dn] = group.member_dns

        # Also add well-known builtin groups
        for group in groups:
            name_lower = group.sam_account_name.lower()
            if name_lower in ("account operators", "server operators", "backup operators",
                              "print operators", "dnsadmins", "administrators"):
                if group.dn not in context.privileged_groups:
                    context.privileged_groups[group.dn] = group.member_dns

        # Build recursive user->group membership
        self._resolve_recursive_membership(context, groups_by_dn)

        logger.info(
            "collected_groups",
            count=len(groups),
            privileged_groups=len(context.privileged_groups),
        )

    def _resolve_recursive_membership(
        self,
        context: SharedContext,
        groups_by_dn: Dict[str, ADGroup],
    ) -> None:
        """Build recursive group membership for each user."""
        for user in context.users:
            all_groups: Set[str] = set()
            self._expand_groups(user.member_of, groups_by_dn, all_groups, set())
            context.user_group_membership[user.dn] = list(all_groups)

            # Mark Protected Users membership
            for group_dn in all_groups:
                group = groups_by_dn.get(group_dn)
                if group and group.sam_account_name.lower() == "protected users":
                    user.is_protected_user = True
                    break

    def _expand_groups(
        self,
        group_dns: List[str],
        groups_by_dn: Dict[str, ADGroup],
        result: Set[str],
        visited: Set[str],
    ) -> None:
        """Recursively expand group membership (handles circular references)."""
        for dn in group_dns:
            if dn in visited:
                continue
            visited.add(dn)
            result.add(dn)

            group = groups_by_dn.get(dn)
            if group and group.member_of:
                self._expand_groups(group.member_of, groups_by_dn, result, visited)

    def _parse_group(self, entry: Dict[str, Any]) -> Optional[ADGroup]:
        """Parse an LDAP entry into an ADGroup model."""
        attrs = entry.get("attributes", {})

        group = ADGroup(
            dn=entry.get("dn", ""),
            sam_account_name=self._get_str(attrs, "sAMAccountName"),
            group_type=self._get_int(attrs, "groupType"),
            member_dns=self._get_list(attrs, "member"),
            member_of=self._get_list(attrs, "memberOf"),
            admin_count=self._get_int(attrs, "adminCount"),
            description=self._get_str(attrs, "description"),
            when_created=generalized_time_to_datetime(self._get_str(attrs, "whenCreated")),
        )

        sid_raw = attrs.get("objectSid")
        if sid_raw:
            if isinstance(sid_raw, list):
                sid_raw = sid_raw[0] if sid_raw else None
            if isinstance(sid_raw, bytes):
                group.sid = parse_binary_sid(sid_raw)

        return group

    def _get_str(self, attrs: dict, key: str) -> str:
        val = attrs.get(key, "")
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""

    def _get_int(self, attrs: dict, key: str) -> int:
        val = attrs.get(key, 0)
        if isinstance(val, list):
            val = val[0] if val else 0
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    def _get_list(self, attrs: dict, key: str) -> List[str]:
        val = attrs.get(key, [])
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)] if val else []
