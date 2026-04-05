"""SharedContext — central data store populated by collectors and consumed by checks."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from adsentinel.models.domain import (
    ADComputer,
    ADGroup,
    ADTrust,
    ADUser,
    DomainInfo,
    FineGrainedPolicy,
    PasswordPolicy,
)


class SharedContext:
    """Central data store for all collected AD data.

    Collectors populate this with domain objects, and checks
    read from it to perform their analysis. This prevents
    duplicate LDAP queries across checks.
    """

    def __init__(self) -> None:
        # Domain-level info
        self.domain_info: DomainInfo = DomainInfo()
        self.password_policy: PasswordPolicy = PasswordPolicy()
        self.fine_grained_policies: List[FineGrainedPolicy] = []

        # AD Objects
        self.users: List[ADUser] = []
        self.groups: List[ADGroup] = []
        self.computers: List[ADComputer] = []
        self.trusts: List[ADTrust] = []

        # Privileged group membership (group DN -> list of member DNs)
        self.privileged_groups: Dict[str, List[str]] = {}

        # Group membership cache (user DN -> list of group DNs, recursive)
        self.user_group_membership: Dict[str, List[str]] = {}

        # GPO data
        self.gpos: List[Dict[str, Any]] = []

        # Certificate Services
        self.certificate_templates: List[Dict[str, Any]] = []
        self.certificate_authorities: List[Dict[str, Any]] = []
        self.enrollment_services: List[Dict[str, Any]] = []

        # ACL/Security Descriptors (DN -> parsed ACL)
        self.acls: Dict[str, Any] = {}

        # DNS zones
        self.dns_zones: List[Dict[str, Any]] = []

        # WinRM-collected data
        self.audit_policy: Optional[Dict[str, str]] = None
        self.smb_config: Optional[Dict[str, Any]] = None
        self.registry_values: Dict[str, str] = {}
        self.service_statuses: Dict[str, str] = {}

        # Raw LDAP entries for checks that need direct access
        self.raw_entries: Dict[str, List[Dict[str, Any]]] = {}

        # Metadata
        self.collection_errors: List[str] = []
        self._winrm_data_collected: bool = False

    @property
    def has_winrm_data(self) -> bool:
        """True if WinRM data was successfully collected."""
        return self._winrm_data_collected or bool(self.registry_values) or self.audit_policy is not None

    def get_users_by_dn(self) -> Dict[str, ADUser]:
        """Get users indexed by DN for fast lookups."""
        return {u.dn: u for u in self.users}

    def get_groups_by_dn(self) -> Dict[str, ADGroup]:
        """Get groups indexed by DN for fast lookups."""
        return {g.dn: g for g in self.groups}

    def get_enabled_users(self) -> List[ADUser]:
        """Get only enabled user accounts."""
        return [u for u in self.users if u.enabled]

    def get_admin_users(self) -> List[ADUser]:
        """Get users with adminCount=1."""
        return [u for u in self.users if u.admin_count == 1]

    def get_kerberoastable_users(self) -> List[ADUser]:
        """Get enabled users with SPNs (Kerberoastable)."""
        return [u for u in self.users if u.is_kerberoastable]

    def get_asrep_roastable_users(self) -> List[ADUser]:
        """Get users vulnerable to AS-REP roasting."""
        return [u for u in self.users if u.is_asrep_roastable]

    def get_stale_users(self) -> List[ADUser]:
        """Get users who haven't logged in for 90+ days."""
        return [u for u in self.users if u.enabled and u.is_stale]

    def get_computers_without_laps(self) -> List[ADComputer]:
        """Get enabled computers without LAPS."""
        return [c for c in self.computers if c.enabled and not c.has_laps]

    def get_unconstrained_delegation(self) -> List[ADUser]:
        """Get accounts with unconstrained delegation (excluding DCs)."""
        return [
            u for u in self.users
            if u.enabled and u.trusted_for_delegation
        ]

    def is_privileged_user(self, user: ADUser) -> bool:
        """Check if a user is a member of any privileged group."""
        user_groups = self.user_group_membership.get(user.dn, [])
        for priv_dn in self.privileged_groups:
            if priv_dn in user_groups:
                return True
        return False
