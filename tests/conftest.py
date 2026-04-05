"""Shared test fixtures — provides mock SharedContext and AD objects."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

import pytest
import structlog


@pytest.fixture(autouse=True)
def _configure_structlog_for_tests():
    """Reconfigure structlog for each test to avoid closed-file errors."""
    structlog.reset_defaults()
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(30),  # WARNING+
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )


from adsentinel.engine.context import SharedContext
from adsentinel.models.domain import (
    ADComputer,
    ADGroup,
    ADUser,
    DomainController,
    DomainInfo,
    FineGrainedPolicy,
    PasswordPolicy,
)


@pytest.fixture
def domain_info() -> DomainInfo:
    """Default domain info for testing."""
    return DomainInfo(
        dns_name="corp.com",
        netbios_name="CORP",
        domain_sid="S-1-5-21-1234567890-1234567890-1234567890",
        base_dn="DC=corp,DC=com",
        config_dn="CN=Configuration,DC=corp,DC=com",
        schema_dn="CN=Schema,CN=Configuration,DC=corp,DC=com",
        forest_name="corp.com",
        domain_functional_level=7,
        forest_functional_level=7,
        domain_functional_level_name="Windows Server 2016",
        forest_functional_level_name="Windows Server 2016",
        domain_controllers=[
            DomainController(
                hostname="DC01.corp.com",
                dn="CN=DC01,OU=Domain Controllers,DC=corp,DC=com",
                os_version="Windows Server 2019",
            ),
        ],
        ad_recycle_bin_enabled=True,
        machine_account_quota=10,
    )


@pytest.fixture
def password_policy() -> PasswordPolicy:
    """Default (weak) password policy for testing."""
    return PasswordPolicy(
        min_length=7,
        complexity_enabled=False,
        history_count=5,
        max_age_days=0,
        min_age_days=0,
        lockout_threshold=0,
        lockout_duration_minutes=0,
        lockout_observation_minutes=0,
        reversible_encryption=False,
    )


@pytest.fixture
def strong_password_policy() -> PasswordPolicy:
    """Strong password policy that passes all checks."""
    return PasswordPolicy(
        min_length=14,
        complexity_enabled=True,
        history_count=24,
        max_age_days=90,
        min_age_days=1,
        lockout_threshold=5,
        lockout_duration_minutes=30,
        lockout_observation_minutes=30,
        reversible_encryption=False,
    )


def make_user(
    name: str,
    dn_prefix: str = "CN=Users",
    enabled: bool = True,
    spns: list | None = None,
    admin_count: int = 0,
    password_last_set: datetime | None = None,
    last_logon: datetime | None = None,
    password_never_expires: bool = False,
    password_not_required: bool = False,
    dont_require_preauth: bool = False,
    use_des_key_only: bool = False,
    trusted_for_delegation: bool = False,
    trusted_to_auth_for_delegation: bool = False,
    sensitive_and_not_delegated: bool = False,
    allowed_to_delegate_to: list | None = None,
    description: str = "",
    member_of: list | None = None,
    sid_rid: int = 1001,
    key_credential_link: list | None = None,
) -> ADUser:
    """Factory for creating test ADUser objects."""
    now = datetime.now(timezone.utc)
    return ADUser(
        dn=f"CN={name},{dn_prefix},DC=corp,DC=com",
        sam_account_name=name,
        upn=f"{name}@corp.com",
        display_name=name,
        enabled=enabled,
        spn_list=spns or [],
        admin_count=admin_count,
        member_of=member_of or [],
        password_last_set=password_last_set or (now - timedelta(days=30)),
        last_logon=last_logon or (now - timedelta(days=1)),
        when_created=now - timedelta(days=365),
        password_never_expires=password_never_expires,
        password_not_required=password_not_required,
        dont_require_preauth=dont_require_preauth,
        use_des_key_only=use_des_key_only,
        trusted_for_delegation=trusted_for_delegation,
        trusted_to_auth_for_delegation=trusted_to_auth_for_delegation,
        sensitive_and_not_delegated=sensitive_and_not_delegated,
        allowed_to_delegate_to=allowed_to_delegate_to or [],
        description=description,
        sid=f"S-1-5-21-1234567890-1234567890-1234567890-{sid_rid}",
        ms_ds_key_credential_link=key_credential_link or [],
        is_protected_user=False,
    )


def make_group(
    name: str,
    sid_rid: int = 2001,
    members: list | None = None,
    member_of: list | None = None,
    admin_count: int = 0,
) -> ADGroup:
    """Factory for creating test ADGroup objects."""
    return ADGroup(
        dn=f"CN={name},CN=Users,DC=corp,DC=com",
        sam_account_name=name,
        sid=f"S-1-5-21-1234567890-1234567890-1234567890-{sid_rid}",
        group_type=-2147483646,  # Global security group
        member_dns=members or [],
        member_of=member_of or [],
        admin_count=admin_count,
    )


def make_computer(
    name: str,
    enabled: bool = True,
    trusted_for_delegation: bool = False,
    laps_expiry: datetime | None = None,
    os_version: str = "Windows 10 Enterprise",
    member_of: list | None = None,
    key_credential_link: list | None = None,
    rbcd: list | None = None,
) -> ADComputer:
    """Factory for creating test ADComputer objects."""
    now = datetime.now(timezone.utc)
    return ADComputer(
        dn=f"CN={name},CN=Computers,DC=corp,DC=com",
        sam_account_name=f"{name}$",
        dns_hostname=f"{name}.corp.com",
        os_version=os_version,
        enabled=enabled,
        trusted_for_delegation=trusted_for_delegation,
        last_logon=now - timedelta(days=1),
        password_last_set=now - timedelta(days=15),
        laps_password_expiry=laps_expiry,
        sid=f"S-1-5-21-1234567890-1234567890-1234567890-{hash(name) % 10000 + 3000}",
        member_of=member_of or [],
        ms_ds_key_credential_link=key_credential_link or [],
        ms_ds_allowed_to_act_on_behalf=rbcd or [],
    )


@pytest.fixture
def context(domain_info, password_policy) -> SharedContext:
    """Shared context with basic data for testing checks."""
    ctx = SharedContext()
    ctx.domain_info = domain_info
    ctx.password_policy = password_policy

    # Create some test users
    da_group_dn = "CN=Domain Admins,CN=Users,DC=corp,DC=com"
    ea_group_dn = "CN=Enterprise Admins,CN=Users,DC=corp,DC=com"

    admin_user = make_user("admin", admin_count=1, member_of=[da_group_dn], sid_rid=500)
    normal_user = make_user("jsmith", sid_rid=1101)
    stale_admin = make_user(
        "old_admin", admin_count=1, member_of=[da_group_dn],
        last_logon=datetime.now(timezone.utc) - timedelta(days=180),
        sid_rid=1102,
    )
    kerberoastable = make_user("svc_sql", spns=["MSSQLSvc/db01.corp.com:1433"], sid_rid=1103)
    kerberoastable_admin = make_user(
        "svc_admin", spns=["HTTP/app01.corp.com"], admin_count=1,
        member_of=[da_group_dn], sid_rid=1104,
    )
    asrep_user = make_user("asrep_user", dont_require_preauth=True, sid_rid=1105)
    unconstrained_user = make_user("svc_unconstrained", trusted_for_delegation=True, sid_rid=1106)
    des_user = make_user("old_svc", use_des_key_only=True, sid_rid=1107)
    no_pwd_user = make_user("empty_user", password_not_required=True, sid_rid=1108)
    never_set_pwd = make_user("new_user", password_last_set=None, sid_rid=1109)
    pwd_in_desc = make_user("lazy_user", description="Password: Summer2024!", sid_rid=1110)
    never_expires = make_user("svc_never", password_never_expires=True, sid_rid=1111)
    t4d_user = make_user("svc_t4d", trusted_to_auth_for_delegation=True, sid_rid=1112)
    shadow_cred_user = make_user("shadow_user", key_credential_link=["B:828:..."], sid_rid=1113)
    krbtgt = make_user(
        "krbtgt", enabled=False, sid_rid=502,
        password_last_set=datetime.now(timezone.utc) - timedelta(days=400),
    )

    ctx.users = [
        admin_user, normal_user, stale_admin, kerberoastable,
        kerberoastable_admin, asrep_user, unconstrained_user,
        des_user, no_pwd_user, never_set_pwd, pwd_in_desc,
        never_expires, t4d_user, shadow_cred_user, krbtgt,
    ]

    # Create groups
    da_group = make_group("Domain Admins", sid_rid=512, members=[
        admin_user.dn, stale_admin.dn, kerberoastable_admin.dn,
    ])
    ea_group = make_group("Enterprise Admins", sid_rid=519, members=[admin_user.dn, stale_admin.dn])
    sa_group = make_group("Schema Admins", sid_rid=518, members=[admin_user.dn])
    protected_users = make_group("Protected Users", sid_rid=525, members=[])
    backup_ops = make_group("Backup Operators", sid_rid=551, members=[normal_user.dn])
    account_ops = make_group("Account Operators", sid_rid=548, members=[])

    ctx.groups = [da_group, ea_group, sa_group, protected_users, backup_ops, account_ops]

    # Build privileged groups
    ctx.privileged_groups = {
        da_group.dn: da_group.member_dns,
        ea_group.dn: ea_group.member_dns,
        sa_group.dn: sa_group.member_dns,
    }

    # Build user group membership
    for user in ctx.users:
        ctx.user_group_membership[user.dn] = user.member_of

    # Create computers
    now = datetime.now(timezone.utc)
    ctx.computers = [
        make_computer("WS001", laps_expiry=now + timedelta(days=30)),
        make_computer("WS002"),  # No LAPS
        make_computer("WS003"),  # No LAPS
        make_computer("SRV001", trusted_for_delegation=True),
        make_computer("SRV002", rbcd=["O:SYD:..."]),
    ]

    return ctx
