"""Collector for computer objects with LAPS and delegation attributes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from adsentinel.collectors.base import BaseCollector
from adsentinel.constants import (
    UAC_ACCOUNTDISABLE,
    UAC_TRUSTED_FOR_DELEGATION,
    UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
)
from adsentinel.logging_config import get_logger
from adsentinel.models.domain import ADComputer
from adsentinel.utils.ldap_filter import eq
from adsentinel.utils.sddl import parse_security_descriptor
from adsentinel.utils.sid import parse_binary_sid
from adsentinel.utils.time_utils import filetime_to_datetime, generalized_time_to_datetime

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)

COMPUTER_ATTRIBUTES = [
    "distinguishedName", "sAMAccountName", "dNSHostName", "operatingSystem",
    "userAccountControl", "servicePrincipalName", "lastLogonTimestamp",
    "pwdLastSet", "objectSid", "memberOf", "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink",
    "ms-Mcs-AdmPwdExpirationTime",  # LAPS v1
    "msLAPS-PasswordExpirationTime",  # LAPS v2
]


class ComputerCollector(BaseCollector):
    """Collects computer objects with LAPS and delegation status."""

    name = "computers"
    description = "Computer accounts, LAPS coverage, and delegation settings"

    def collect(self, context: SharedContext) -> None:
        """Collect computer data."""
        entries = self.ldap.search(
            search_filter=eq("objectCategory", "computer"),
            attributes=COMPUTER_ATTRIBUTES,
        )

        computers = []
        for entry in entries:
            computer = self._parse_computer(entry)
            if computer:
                computers.append(computer)

        context.computers = computers
        logger.info(
            "collected_computers",
            count=len(computers),
            with_laps=sum(1 for c in computers if c.has_laps),
        )

    def _parse_computer(self, entry: Dict[str, Any]) -> Optional[ADComputer]:
        """Parse an LDAP entry into an ADComputer model."""
        attrs = entry.get("attributes", {})
        uac = self._get_int(attrs, "userAccountControl")

        # Check LAPS (v1 and v2)
        laps_expiry = None
        laps_v1 = attrs.get("ms-Mcs-AdmPwdExpirationTime")
        laps_v2 = attrs.get("msLAPS-PasswordExpirationTime")
        if laps_v2:
            # LAPS v2 uses GeneralizedTime format, not FILETIME
            raw = laps_v2[0] if isinstance(laps_v2, list) else laps_v2
            if raw:
                laps_expiry = generalized_time_to_datetime(str(raw))
                # Fall back to FILETIME if GeneralizedTime parsing fails (some implementations)
                if laps_expiry is None:
                    try:
                        laps_expiry = filetime_to_datetime(raw)
                    except (ValueError, TypeError):
                        pass
        elif laps_v1:
            # LAPS v1 uses Windows FILETIME
            raw = laps_v1[0] if isinstance(laps_v1, list) else laps_v1
            if raw:
                try:
                    laps_expiry = filetime_to_datetime(raw)
                except (ValueError, TypeError):
                    pass

        # RBCD - msDS-AllowedToActOnBehalfOfOtherIdentity (binary security descriptor)
        rbcd_raw_val = attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        rbcd_raw: list = []
        if rbcd_raw_val:
            raw_bytes = rbcd_raw_val[0] if isinstance(rbcd_raw_val, list) else rbcd_raw_val
            if isinstance(raw_bytes, bytes):
                sd = parse_security_descriptor(raw_bytes)
                if sd and sd.get("aces"):
                    rbcd_raw = [ace.get("trustee_sid", "") for ace in sd["aces"] if ace.get("trustee_sid")]
            elif isinstance(raw_bytes, str) and raw_bytes:
                rbcd_raw = [raw_bytes]

        computer = ADComputer(
            dn=entry.get("dn", ""),
            sam_account_name=self._get_str(attrs, "sAMAccountName"),
            dns_hostname=self._get_str(attrs, "dNSHostName"),
            os_version=self._get_str(attrs, "operatingSystem"),
            enabled=not bool(uac & UAC_ACCOUNTDISABLE),
            user_account_control=uac,
            spn_list=self._get_list(attrs, "servicePrincipalName"),
            trusted_for_delegation=bool(uac & UAC_TRUSTED_FOR_DELEGATION),
            trusted_to_auth_for_delegation=bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
            allowed_to_delegate_to=self._get_list(attrs, "msDS-AllowedToDelegateTo"),
            last_logon=self._parse_timestamp(attrs, "lastLogonTimestamp"),
            password_last_set=self._parse_timestamp(attrs, "pwdLastSet"),
            ms_ds_key_credential_link=self._get_list(attrs, "msDS-KeyCredentialLink"),
            laps_password_expiry=laps_expiry,
            member_of=self._get_list(attrs, "memberOf"),
            ms_ds_allowed_to_act_on_behalf=rbcd_raw,
        )

        sid_raw = attrs.get("objectSid")
        if sid_raw:
            if isinstance(sid_raw, list):
                sid_raw = sid_raw[0] if sid_raw else None
            if isinstance(sid_raw, bytes):
                computer.sid = parse_binary_sid(sid_raw)

        return computer

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
