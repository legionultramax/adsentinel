"""SID (Security Identifier) binary parsing and resolution.

Parses the binary SID format defined in MS-DTYP 2.4.2 into the
standard S-1-5-21-... string representation.
"""

from __future__ import annotations

import struct
from typing import Optional

from adsentinel.constants import WELL_KNOWN_SIDS


def parse_binary_sid(raw: bytes) -> str:
    """Parse a binary SID into string format (S-1-5-21-...).

    Binary format (MS-DTYP 2.4.2):
        Byte 0:     Revision (always 1)
        Byte 1:     SubAuthorityCount
        Bytes 2-7:  IdentifierAuthority (6 bytes, big-endian)
        Bytes 8+:   SubAuthority array (4 bytes each, little-endian)
    """
    if not raw or len(raw) < 8:
        return ""

    revision = raw[0]
    sub_authority_count = raw[1]

    # Identifier Authority: 6 bytes big-endian
    identifier_authority = int.from_bytes(raw[2:8], byteorder="big")

    # Each sub-authority is 4 bytes little-endian
    sub_authorities = []
    for i in range(sub_authority_count):
        offset = 8 + (i * 4)
        if offset + 4 > len(raw):
            break
        sub_auth = struct.unpack("<I", raw[offset : offset + 4])[0]
        sub_authorities.append(str(sub_auth))

    sid = f"S-{revision}-{identifier_authority}"
    if sub_authorities:
        sid += "-" + "-".join(sub_authorities)
    return sid


def sid_to_string(raw: bytes) -> str:
    """Alias for parse_binary_sid."""
    return parse_binary_sid(raw)


def resolve_sid(sid: str) -> str:
    """Resolve a SID string to a human-readable name if well-known."""
    return WELL_KNOWN_SIDS.get(sid, sid)


def get_rid(sid: str) -> Optional[int]:
    """Extract the RID (last sub-authority) from a SID string."""
    parts = sid.split("-")
    if len(parts) < 4:
        return None
    try:
        return int(parts[-1])
    except ValueError:
        return None


def get_domain_sid(sid: str) -> str:
    """Extract the domain SID (everything except the RID) from a SID string."""
    parts = sid.split("-")
    if len(parts) < 4:
        return sid
    return "-".join(parts[:-1])


def build_sid(domain_sid: str, rid: int) -> str:
    """Build a full SID from a domain SID and RID."""
    return f"{domain_sid}-{rid}"
