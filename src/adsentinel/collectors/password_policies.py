"""Collector for domain password policy and fine-grained password policies."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from adsentinel.collectors.base import BaseCollector
from adsentinel.logging_config import get_logger
from adsentinel.models.domain import FineGrainedPolicy, PasswordPolicy
from adsentinel.utils.ldap_filter import eq
from adsentinel.utils.time_utils import ad_duration_to_days, ad_duration_to_minutes

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)


class PasswordPolicyCollector(BaseCollector):
    """Collects domain password policy and fine-grained password policies."""

    name = "password_policies"
    description = "Domain password policy and fine-grained password policies (FGPP)"

    def collect(self, context: SharedContext) -> None:
        """Collect password policies."""
        # Default Domain Password Policy
        domain_entry = self.ldap.search_single(
            search_base=self.ldap.base_dn,
            search_filter="(objectClass=domain)",
            attributes=[
                "minPwdLength", "pwdProperties", "pwdHistoryLength",
                "maxPwdAge", "minPwdAge", "lockoutThreshold",
                "lockoutDuration", "lockoutObservationWindow",
            ],
        )

        if domain_entry:
            attrs = domain_entry.get("attributes", {})
            context.password_policy = PasswordPolicy(
                min_length=self._get_int(attrs, "minPwdLength"),
                complexity_enabled=bool(self._get_int(attrs, "pwdProperties") & 1),
                history_count=self._get_int(attrs, "pwdHistoryLength"),
                max_age_days=round(ad_duration_to_days(self._get_int(attrs, "maxPwdAge")), 1),
                min_age_days=round(ad_duration_to_days(self._get_int(attrs, "minPwdAge")), 1),
                lockout_threshold=self._get_int(attrs, "lockoutThreshold"),
                lockout_duration_minutes=round(ad_duration_to_minutes(self._get_int(attrs, "lockoutDuration")), 1),
                lockout_observation_minutes=round(ad_duration_to_minutes(self._get_int(attrs, "lockoutObservationWindow")), 1),
                reversible_encryption=bool(self._get_int(attrs, "pwdProperties") & 16),
            )

        # Fine-Grained Password Policies
        fgpp_filter = eq("objectClass", "msDS-PasswordSettings")
        fgpp_entries = self.ldap.search(
            search_base=f"CN=Password Settings Container,CN=System,{self.ldap.base_dn}",
            search_filter=fgpp_filter,
            attributes=[
                "distinguishedName", "name", "msDS-PasswordSettingsPrecedence",
                "msDS-MinimumPasswordLength", "msDS-PasswordComplexityEnabled",
                "msDS-PasswordHistoryLength", "msDS-MaximumPasswordAge",
                "msDS-MinimumPasswordAge", "msDS-LockoutThreshold",
                "msDS-LockoutDuration", "msDS-PSOAppliesTo",
                "msDS-PasswordReversibleEncryptionEnabled",
            ],
        )

        fgpps = []
        for entry in fgpp_entries:
            attrs = entry.get("attributes", {})
            fgpp = FineGrainedPolicy(
                dn=entry.get("dn", ""),
                name=self._get_str(attrs, "name"),
                precedence=self._get_int(attrs, "msDS-PasswordSettingsPrecedence"),
                min_length=self._get_int(attrs, "msDS-MinimumPasswordLength"),
                complexity_enabled=self._get_bool(attrs, "msDS-PasswordComplexityEnabled"),
                history_count=self._get_int(attrs, "msDS-PasswordHistoryLength"),
                max_age_days=round(ad_duration_to_days(self._get_int(attrs, "msDS-MaximumPasswordAge")), 1),
                min_age_days=round(ad_duration_to_days(self._get_int(attrs, "msDS-MinimumPasswordAge")), 1),
                lockout_threshold=self._get_int(attrs, "msDS-LockoutThreshold"),
                lockout_duration_minutes=round(ad_duration_to_minutes(self._get_int(attrs, "msDS-LockoutDuration")), 1),
                applies_to=self._get_list(attrs, "msDS-PSOAppliesTo"),
                reversible_encryption=self._get_bool(attrs, "msDS-PasswordReversibleEncryptionEnabled"),
            )
            fgpps.append(fgpp)

        context.fine_grained_policies = fgpps
        logger.info(
            "collected_password_policies",
            min_length=context.password_policy.min_length,
            complexity=context.password_policy.complexity_enabled,
            fgpp_count=len(fgpps),
        )

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

    def _get_bool(self, attrs: dict, key: str) -> bool:
        val = attrs.get(key, False)
        if isinstance(val, list):
            val = val[0] if val else False
        return bool(val)

    def _get_list(self, attrs: dict, key: str) -> List[str]:
        val = attrs.get(key, [])
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)] if val else []
