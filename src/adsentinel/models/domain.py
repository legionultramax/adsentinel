"""Domain and identity models for collected AD data."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class DomainInfo(BaseModel):
    """Domain-level metadata collected from AD."""

    dns_name: str = ""
    netbios_name: str = ""
    domain_sid: str = ""
    base_dn: str = ""
    config_dn: str = ""
    schema_dn: str = ""
    forest_name: str = ""
    domain_functional_level: int = 0
    forest_functional_level: int = 0
    domain_functional_level_name: str = ""
    forest_functional_level_name: str = ""
    domain_controllers: List[DomainController] = []
    fsmo_roles: Dict[str, str] = {}
    tombstone_lifetime: int = 180
    ad_recycle_bin_enabled: bool = False
    machine_account_quota: int = 10


class DomainController(BaseModel):
    """Domain Controller information."""

    hostname: str = ""
    dn: str = ""
    ip_address: str = ""
    os_version: str = ""
    is_global_catalog: bool = False
    is_read_only: bool = False
    site_name: str = ""


class ADUser(BaseModel):
    """Active Directory user object with security-relevant attributes."""

    dn: str = ""
    sam_account_name: str = ""
    upn: str = ""
    display_name: str = ""
    enabled: bool = True
    user_account_control: int = 0
    spn_list: List[str] = []
    admin_count: int = 0
    member_of: List[str] = []
    password_last_set: Optional[datetime] = None
    last_logon: Optional[datetime] = None
    when_created: Optional[datetime] = None
    password_never_expires: bool = False
    password_not_required: bool = False
    dont_require_preauth: bool = False
    use_des_key_only: bool = False
    trusted_for_delegation: bool = False
    trusted_to_auth_for_delegation: bool = False
    sensitive_and_not_delegated: bool = False
    is_protected_user: bool = False
    sid: str = ""
    ms_ds_key_credential_link: List[str] = []
    allowed_to_delegate_to: List[str] = []
    description: str = ""
    sid_history: List[str] = []
    account_expires: Optional[datetime] = None

    @property
    def is_kerberoastable(self) -> bool:
        return self.enabled and len(self.spn_list) > 0

    @property
    def is_asrep_roastable(self) -> bool:
        return self.enabled and self.dont_require_preauth

    @property
    def is_stale(self) -> bool:
        """Account hasn't logged in for 90+ days."""
        if not self.last_logon:
            return True
        from datetime import datetime, timezone
        delta = datetime.now(timezone.utc) - self.last_logon
        return delta.days > 90

    @property
    def has_weak_encryption(self) -> bool:
        return self.use_des_key_only


class ADGroup(BaseModel):
    """Active Directory group object."""

    dn: str = ""
    sam_account_name: str = ""
    sid: str = ""
    group_type: int = 0
    member_dns: List[str] = []
    member_of: List[str] = []
    admin_count: int = 0
    description: str = ""
    when_created: Optional[datetime] = None

    @property
    def is_security_group(self) -> bool:
        return bool(self.group_type & 0x80000000)


class ADComputer(BaseModel):
    """Active Directory computer object."""

    dn: str = ""
    sam_account_name: str = ""
    dns_hostname: str = ""
    os_version: str = ""
    enabled: bool = True
    user_account_control: int = 0
    spn_list: List[str] = []
    trusted_for_delegation: bool = False
    trusted_to_auth_for_delegation: bool = False
    allowed_to_delegate_to: List[str] = []
    last_logon: Optional[datetime] = None
    password_last_set: Optional[datetime] = None
    ms_ds_key_credential_link: List[str] = []
    laps_password_expiry: Optional[datetime] = None
    sid: str = ""
    member_of: List[str] = []
    ms_ds_allowed_to_act_on_behalf: List[str] = []

    @property
    def has_laps(self) -> bool:
        return self.laps_password_expiry is not None

    @property
    def is_stale(self) -> bool:
        if not self.last_logon:
            return True
        from datetime import datetime, timezone
        delta = datetime.now(timezone.utc) - self.last_logon
        return delta.days > 90


class ADTrust(BaseModel):
    """Active Directory trust relationship."""

    dn: str = ""
    trusted_domain: str = ""
    trust_direction: int = 0  # 1=inbound, 2=outbound, 3=bidirectional
    trust_type: int = 0
    trust_attributes: int = 0
    sid_filtering_enabled: bool = True
    selective_auth: bool = False
    when_created: Optional[datetime] = None

    @property
    def direction_name(self) -> str:
        return {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(self.trust_direction, "Unknown")

    @property
    def is_forest_trust(self) -> bool:
        return bool(self.trust_attributes & 0x8)


class PasswordPolicy(BaseModel):
    """Domain password policy."""

    min_length: int = 0
    complexity_enabled: bool = False
    history_count: int = 0
    max_age_days: int = 0
    min_age_days: int = 0
    lockout_threshold: int = 0
    lockout_duration_minutes: int = 0
    lockout_observation_minutes: int = 0
    reversible_encryption: bool = False


class FineGrainedPolicy(BaseModel):
    """Fine-Grained Password Policy (FGPP)."""

    dn: str = ""
    name: str = ""
    precedence: int = 0
    min_length: int = 0
    complexity_enabled: bool = False
    history_count: int = 0
    max_age_days: int = 0
    min_age_days: int = 0
    lockout_threshold: int = 0
    lockout_duration_minutes: int = 0
    applies_to: List[str] = []
    reversible_encryption: bool = False
