"""Unit tests for utility modules."""

import struct
from datetime import datetime, timezone

from adsentinel.utils.sid import parse_binary_sid, get_rid, get_domain_sid, build_sid
from adsentinel.utils.time_utils import (
    filetime_to_datetime,
    generalized_time_to_datetime,
    ad_duration_to_days,
    ad_duration_to_minutes,
    days_since,
)
from adsentinel.utils.ldap_filter import (
    escape_filter_value,
    eq,
    and_filter,
    or_filter,
    not_filter,
    present,
    build_user_filter,
)
from adsentinel.utils.well_known import (
    resolve_sid_name,
    is_privileged_group,
    get_eku_name,
)


class TestSIDParsing:
    def test_parse_known_sid(self):
        # Build a binary SID for S-1-5-21-1234567890-1234567890-1234567890-500
        revision = 1
        sub_count = 5
        authority = (5).to_bytes(6, byteorder="big")
        sub_auths = [21, 1234567890, 1234567890, 1234567890, 500]
        raw = bytes([revision, sub_count]) + authority
        for sa in sub_auths:
            raw += struct.pack("<I", sa)

        result = parse_binary_sid(raw)
        assert result == "S-1-5-21-1234567890-1234567890-1234567890-500"

    def test_parse_empty_sid(self):
        assert parse_binary_sid(b"") == ""
        assert parse_binary_sid(b"\x00") == ""

    def test_get_rid(self):
        assert get_rid("S-1-5-21-111-222-333-500") == 500
        assert get_rid("S-1-5-21-111-222-333-512") == 512
        assert get_rid("S-1-0-0") == 0
        assert get_rid("S-1") is None

    def test_get_domain_sid(self):
        assert get_domain_sid("S-1-5-21-111-222-333-500") == "S-1-5-21-111-222-333"

    def test_build_sid(self):
        assert build_sid("S-1-5-21-111-222-333", 512) == "S-1-5-21-111-222-333-512"


class TestTimeUtils:
    def test_filetime_to_datetime(self):
        # Known value: 132500000000000000 = ~2020-12-06
        ft = 132500000000000000
        result = filetime_to_datetime(ft)
        assert result is not None
        assert result.year == 2020

    def test_filetime_zero(self):
        assert filetime_to_datetime(0) is None

    def test_filetime_never_expires(self):
        assert filetime_to_datetime(0x7FFFFFFFFFFFFFFF) is None

    def test_generalized_time(self):
        result = generalized_time_to_datetime("20240101120000.0Z")
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.hour == 12

    def test_generalized_time_empty(self):
        assert generalized_time_to_datetime("") is None
        assert generalized_time_to_datetime(None) is None

    def test_ad_duration_to_days(self):
        # -864000000000 = 1 day in 100ns intervals
        assert ad_duration_to_days(-864000000000) == 1.0
        assert ad_duration_to_days(0) == 0.0

    def test_ad_duration_to_minutes(self):
        # -6000000000 = 10 minutes
        assert ad_duration_to_minutes(-6000000000) == 10.0

    def test_days_since(self):
        yesterday = datetime.now(timezone.utc) - __import__("datetime").timedelta(days=1)
        assert days_since(yesterday) == 1

    def test_days_since_none(self):
        assert days_since(None) == -1


class TestLDAPFilter:
    def test_escape_special_chars(self):
        assert escape_filter_value("test*value") == "test\\2avalue"
        assert escape_filter_value("test(value)") == "test\\28value\\29"
        assert escape_filter_value("test\\value") == "test\\5cvalue"

    def test_eq_filter(self):
        assert eq("cn", "admin") == "(cn=admin)"

    def test_eq_with_special_chars(self):
        assert eq("cn", "test*") == "(cn=test\\2a)"

    def test_and_filter(self):
        result = and_filter(["(a=1)", "(b=2)"])
        assert result == "(&(a=1)(b=2))"

    def test_and_filter_single(self):
        result = and_filter(["(a=1)"])
        assert result == "(a=1)"

    def test_or_filter(self):
        result = or_filter(["(a=1)", "(b=2)"])
        assert result == "(|(a=1)(b=2))"

    def test_not_filter(self):
        assert not_filter("(a=1)") == "(!(a=1))"

    def test_present(self):
        assert present("servicePrincipalName") == "(servicePrincipalName=*)"

    def test_build_user_filter_basic(self):
        f = build_user_filter()
        assert "objectCategory=person" in f
        assert "objectClass=user" in f

    def test_build_user_filter_with_spn(self):
        f = build_user_filter(with_spn=True)
        assert "servicePrincipalName=*" in f


class TestWellKnown:
    def test_resolve_known_sid(self):
        assert resolve_sid_name("S-1-5-32-544") == "BUILTIN\\Administrators"
        assert resolve_sid_name("S-1-1-0") == "Everyone"

    def test_resolve_unknown_sid(self):
        assert resolve_sid_name("S-1-5-21-xxx") == "S-1-5-21-xxx"

    def test_is_privileged_group(self):
        assert is_privileged_group("Domain Admins")
        assert is_privileged_group("DOMAIN ADMINS")  # Case insensitive
        assert not is_privileged_group("Domain Users")

    def test_get_eku_name(self):
        assert get_eku_name("1.3.6.1.5.5.7.3.2") == "Client Authentication"
        assert "Unknown" in get_eku_name("1.2.3.4.5.6")
