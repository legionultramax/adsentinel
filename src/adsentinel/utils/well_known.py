"""Well-known SIDs, GUIDs, and OIDs database for AD security analysis."""

from __future__ import annotations

from adsentinel.constants import WELL_KNOWN_SIDS

# Extended Key Usage OID to Name mapping
EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.21.5": "CA Encryption Certificate",
}

# Schema attribute GUIDs for ACL analysis
SCHEMA_GUID_NAMES = {
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Member (Write)",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-Write-To-SPN",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "Validated-Write-To-DNS",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "ms-DS-Key-Credential-Link",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00000000-0000-0000-0000-000000000000": "All Extended Rights",
}

# Privileged group names (case-insensitive matching)
PRIVILEGED_GROUP_NAMES = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "server operators",
    "backup operators",
    "print operators",
    "group policy creator owners",
    "dnsadmins",
    "key admins",
    "enterprise key admins",
}

# Dangerous group names that shouldn't have unexpected members
DANGEROUS_BUILTIN_GROUPS = {
    "account operators": "Can create/modify non-admin accounts and groups",
    "server operators": "Can log on to DCs, manage services, shares, and printers",
    "backup operators": "Can back up and restore all files, log on to DCs",
    "print operators": "Can manage printers and load drivers on DCs",
    "dnsadmins": "Can load arbitrary DLLs on DNS server (often a DC)",
}


def resolve_sid_name(sid: str) -> str:
    """Resolve a SID to its well-known name, or return the SID itself."""
    return WELL_KNOWN_SIDS.get(sid, sid)


def is_privileged_group(group_name: str) -> bool:
    """Check if a group name is a well-known privileged group."""
    return group_name.lower().strip() in PRIVILEGED_GROUP_NAMES


def get_eku_name(oid: str) -> str:
    """Resolve an EKU OID to its human-readable name."""
    return EKU_NAMES.get(oid, f"Unknown ({oid})")


def get_schema_guid_name(guid: str) -> str:
    """Resolve a schema GUID to its human-readable name."""
    return SCHEMA_GUID_NAMES.get(guid.lower(), f"Unknown ({guid})")
