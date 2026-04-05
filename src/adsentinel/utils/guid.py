"""GUID utilities for AD schema rights and extended rights."""

from __future__ import annotations

from adsentinel.utils.well_known import SCHEMA_GUID_NAMES

# Extended rights GUIDs commonly used in ACL attacks
EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "00000000-0000-0000-0000-000000000000": "All Extended Rights",
}

# Property set GUIDs
PROPERTY_SETS = {
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
}

# Validated writes
VALIDATED_WRITES = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership (Add/Remove self from group)",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "Validated-DNS-Host-Name",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
}

# Dangerous property GUIDs (write access to these enables attacks)
DANGEROUS_PROPERTIES = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "member",
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1": "GPC-File-Sys-Path",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName",
}


def resolve_guid(guid: str) -> str:
    """Resolve a GUID to its human-readable name."""
    guid_lower = guid.lower()
    # Check all mapping tables
    for table in [SCHEMA_GUID_NAMES, EXTENDED_RIGHTS, PROPERTY_SETS, VALIDATED_WRITES, DANGEROUS_PROPERTIES]:
        if guid_lower in table:
            return table[guid_lower]
    return guid


def is_dcsync_right(guid: str) -> bool:
    """Check if a GUID represents a DCSync-related extended right."""
    guid_lower = guid.lower()
    return guid_lower in (
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # Get-Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # Get-Changes-All
    )


def is_dangerous_write_property(guid: str) -> bool:
    """Check if a property GUID is dangerous to have write access to."""
    return guid.lower() in DANGEROUS_PROPERTIES
