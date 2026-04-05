"""Collector for user objects with all security-relevant attributes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from adsentinel.collectors.base import BaseCollector
from adsentinel.constants import (
    UAC_ACCOUNTDISABLE,
    UAC_DONT_EXPIRE_PASSWD,
    UAC_DONT_REQ_PREAUTH,
    UAC_NOT_DELEGATED,
    UAC_PASSWD_NOTREQD,
    UAC_TRUSTED_FOR_DELEGATION,
    UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
    UAC_USE_DES_KEY_ONLY,
)
from adsentinel.logging_config import get_logger
from adsentinel.models.domain import ADUser
from adsentinel.utils.ldap_filter import and_filter, eq
from adsentinel.utils.sid import parse_binary_sid
from adsentinel.utils.time_utils import filetime_to_datetime, generalized_time_to_datetime

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)

USER_ATTRIBUTES = [
    "distinguishedName", "sAMAccountName", "userPrincipalName", "displayName",
    "userAccountControl", "servicePrincipalName", "adminCount", "memberOf",
    "pwdLastSet", "lastLogonTimestamp", "whenCreated", "objectSid",
    "msDS-AllowedToDelegateTo", "msDS-KeyCredentialLink", "description",
]


class UserCollector(BaseCollector):
    """Collects all user objects with security-relevant attributes."""

    name = "users"
    description = "User accounts with delegation, SPN, and UAC attributes"

    def collect(self, context: SharedContext) -> None:
        """Collect user data."""
        user_filter = and_filter([
            eq("objectCategory", "person"),
            eq("objectClass", "user"),
        ])

        entries = self.ldap.search(
            search_filter=user_filter,
            attributes=USER_ATTRIBUTES,
        )

        users = []
        for entry in entries:
            user = self._parse_user(entry)
            if user:
                users.append(user)

        context.users = users
        logger.info("collected_users", count=len(users))

    def _parse_user(self, entry: Dict[str, Any]) -> Optional[ADUser]:
        """Parse an LDAP entry into an ADUser model."""
        attrs = entry.get("attributes", {})
        uac = self._get_int(attrs, "userAccountControl")

        user = ADUser(
            dn=entry.get("dn", ""),
            sam_account_name=self._get_str(attrs, "sAMAccountName"),
            upn=self._get_str(attrs, "userPrincipalName"),
            display_name=self._get_str(attrs, "displayName"),
            enabled=not bool(uac & UAC_ACCOUNTDISABLE),
            user_account_control=uac,
            spn_list=self._get_list(attrs, "servicePrincipalName"),
            admin_count=self._get_int(attrs, "adminCount"),
            member_of=self._get_list(attrs, "memberOf"),
            password_last_set=self._parse_timestamp(attrs, "pwdLastSet"),
            last_logon=self._parse_timestamp(attrs, "lastLogonTimestamp"),
            when_created=self._parse_generalized_time(attrs, "whenCreated"),
            password_never_expires=bool(uac & UAC_DONT_EXPIRE_PASSWD),
            password_not_required=bool(uac & UAC_PASSWD_NOTREQD),
            dont_require_preauth=bool(uac & UAC_DONT_REQ_PREAUTH),
            use_des_key_only=bool(uac & UAC_USE_DES_KEY_ONLY),
            trusted_for_delegation=bool(uac & UAC_TRUSTED_FOR_DELEGATION),
            trusted_to_auth_for_delegation=bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
            sensitive_and_not_delegated=bool(uac & UAC_NOT_DELEGATED),
            allowed_to_delegate_to=self._get_list(attrs, "msDS-AllowedToDelegateTo"),
            ms_ds_key_credential_link=self._get_list(attrs, "msDS-KeyCredentialLink"),
            description=self._get_str(attrs, "description"),
        )

        # Parse SID
        sid_raw = attrs.get("objectSid")
        if sid_raw:
            if isinstance(sid_raw, list):
                sid_raw = sid_raw[0] if sid_raw else None
            if isinstance(sid_raw, bytes):
                user.sid = parse_binary_sid(sid_raw)

        return user

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

    def _parse_timestamp(self, attrs: dict, key: str) -> Optional[Any]:
        val = attrs.get(key, None)
        if isinstance(val, list):
            val = val[0] if val else None
        if val is not None:
            return filetime_to_datetime(val)
        return None

    def _parse_generalized_time(self, attrs: dict, key: str) -> Optional[Any]:
        val = attrs.get(key, None)
        if isinstance(val, list):
            val = val[0] if val else None
        if val is not None:
            return generalized_time_to_datetime(str(val))
        return None
