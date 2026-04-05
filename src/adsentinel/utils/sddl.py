"""SDDL and ntSecurityDescriptor binary parser for ACL analysis.

Parses Security Descriptors from binary (MS-DTYP 2.4.6) and SDDL string
formats into structured ACE (Access Control Entry) lists for finding
dangerous permissions like WriteDACL, WriteOwner, GenericAll, etc.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Dict, List, Optional, Tuple

from adsentinel.constants import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_DS_WRITE_PROP,
    ADS_RIGHT_GENERIC_ALL,
    ADS_RIGHT_GENERIC_WRITE,
    ADS_RIGHT_WRITE_DAC,
    ADS_RIGHT_WRITE_OWNER,
    DANGEROUS_PERMISSIONS,
)
from adsentinel.utils.sid import parse_binary_sid


class AceType(IntFlag):
    """ACE type constants from MS-DTYP."""
    ACCESS_ALLOWED = 0x00
    ACCESS_DENIED = 0x01
    SYSTEM_AUDIT = 0x02
    ACCESS_ALLOWED_OBJECT = 0x05
    ACCESS_DENIED_OBJECT = 0x06
    SYSTEM_AUDIT_OBJECT = 0x07


@dataclass
class ACE:
    """A single Access Control Entry."""
    ace_type: int = 0
    ace_flags: int = 0
    access_mask: int = 0
    trustee_sid: str = ""
    object_type_guid: str = ""  # For object-specific ACEs
    inherited_object_type_guid: str = ""
    is_inherited: bool = False

    @property
    def type_name(self) -> str:
        """Human-readable ACE type."""
        names = {0: "Allow", 1: "Deny", 2: "Audit", 5: "AllowObject", 6: "DenyObject"}
        return names.get(self.ace_type, f"Unknown({self.ace_type})")

    @property
    def is_allow(self) -> bool:
        return self.ace_type in (AceType.ACCESS_ALLOWED, AceType.ACCESS_ALLOWED_OBJECT)

    @property
    def dangerous_permissions(self) -> List[str]:
        """List of dangerous permissions granted by this ACE."""
        perms = []
        for mask, name in DANGEROUS_PERMISSIONS.items():
            if self.access_mask & mask:
                perms.append(name)
        if self.access_mask & ADS_RIGHT_DS_WRITE_PROP:
            perms.append("WriteProperty")
        if self.access_mask & ADS_RIGHT_DS_CONTROL_ACCESS:
            perms.append("ExtendedRight")
        return perms

    @property
    def is_dangerous(self) -> bool:
        """Check if this ACE grants dangerous permissions."""
        return self.is_allow and bool(self.dangerous_permissions)


@dataclass
class ACL:
    """Access Control List containing ACEs."""
    revision: int = 0
    aces: List[ACE] = field(default_factory=list)

    @property
    def dangerous_aces(self) -> List[ACE]:
        """Get only ACEs with dangerous permissions."""
        return [ace for ace in self.aces if ace.is_dangerous and not ace.is_inherited]

    def get_aces_for_trustee(self, sid: str) -> List[ACE]:
        """Get all ACEs for a specific trustee SID."""
        return [ace for ace in self.aces if ace.trustee_sid == sid]


@dataclass
class SecurityDescriptor:
    """Parsed Security Descriptor with owner, group, DACL, and SACL."""
    owner_sid: str = ""
    group_sid: str = ""
    dacl: Optional[ACL] = None
    sacl: Optional[ACL] = None
    control_flags: int = 0


def parse_security_descriptor(raw: bytes) -> Optional[SecurityDescriptor]:
    """Parse a binary ntSecurityDescriptor into a SecurityDescriptor.

    Format (MS-DTYP 2.4.6):
        Byte 0:     Revision
        Byte 1:     Sbz1 (reserved)
        Bytes 2-3:  Control flags (little-endian)
        Bytes 4-7:  Offset to Owner SID
        Bytes 8-11: Offset to Group SID
        Bytes 12-15: Offset to SACL
        Bytes 16-19: Offset to DACL
    """
    if not raw or len(raw) < 20:
        return None

    try:
        revision = raw[0]
        control = struct.unpack_from("<H", raw, 2)[0]
        owner_offset = struct.unpack_from("<I", raw, 4)[0]
        group_offset = struct.unpack_from("<I", raw, 8)[0]
        sacl_offset = struct.unpack_from("<I", raw, 12)[0]
        dacl_offset = struct.unpack_from("<I", raw, 16)[0]

        sd = SecurityDescriptor(control_flags=control)

        # Parse Owner SID
        if owner_offset > 0 and owner_offset < len(raw):
            sd.owner_sid = _parse_sid_at_offset(raw, owner_offset)

        # Parse Group SID
        if group_offset > 0 and group_offset < len(raw):
            sd.group_sid = _parse_sid_at_offset(raw, group_offset)

        # Parse DACL
        if dacl_offset > 0 and dacl_offset < len(raw):
            sd.dacl = _parse_acl(raw, dacl_offset)

        # Parse SACL
        if sacl_offset > 0 and sacl_offset < len(raw):
            sd.sacl = _parse_acl(raw, sacl_offset)

        return sd

    except (struct.error, IndexError, ValueError):
        return None


def _parse_sid_at_offset(raw: bytes, offset: int) -> str:
    """Parse a SID at a given offset in the binary data."""
    if offset >= len(raw):
        return ""
    sub_count = raw[offset + 1] if offset + 1 < len(raw) else 0
    sid_length = 8 + (sub_count * 4)
    end = min(offset + sid_length, len(raw))
    return parse_binary_sid(raw[offset:end])


def _parse_acl(raw: bytes, offset: int) -> Optional[ACL]:
    """Parse an ACL at a given offset.

    ACL header (MS-DTYP 2.4.5):
        Byte 0:     Revision
        Byte 1:     Sbz1
        Bytes 2-3:  AclSize
        Bytes 4-5:  AceCount
        Bytes 6-7:  Sbz2
    """
    if offset + 8 > len(raw):
        return None

    revision = raw[offset]
    acl_size = struct.unpack_from("<H", raw, offset + 2)[0]
    ace_count = struct.unpack_from("<H", raw, offset + 4)[0]

    acl = ACL(revision=revision)
    ace_offset = offset + 8  # Start of first ACE

    for _ in range(ace_count):
        if ace_offset + 4 > len(raw):
            break

        ace_type = raw[ace_offset]
        ace_flags = raw[ace_offset + 1]
        ace_size = struct.unpack_from("<H", raw, ace_offset + 2)[0]

        if ace_size < 4 or ace_offset + ace_size > len(raw):
            break

        ace = _parse_ace(raw, ace_offset, ace_type, ace_flags, ace_size)
        if ace:
            # Check inherited flag (bit 4 of ace_flags)
            ace.is_inherited = bool(ace_flags & 0x10)
            acl.aces.append(ace)

        ace_offset += ace_size

    return acl


def _parse_ace(raw: bytes, offset: int, ace_type: int, ace_flags: int, ace_size: int) -> Optional[ACE]:
    """Parse a single ACE."""
    ace = ACE(ace_type=ace_type, ace_flags=ace_flags)

    if ace_type in (AceType.ACCESS_ALLOWED, AceType.ACCESS_DENIED, AceType.SYSTEM_AUDIT):
        # Standard ACE: 4-byte header + 4-byte mask + SID
        if offset + 8 > len(raw):
            return None
        ace.access_mask = struct.unpack_from("<I", raw, offset + 4)[0]
        sid_offset = offset + 8
        ace.trustee_sid = _parse_sid_at_offset(raw, sid_offset)

    elif ace_type in (AceType.ACCESS_ALLOWED_OBJECT, AceType.ACCESS_DENIED_OBJECT,
                      AceType.SYSTEM_AUDIT_OBJECT):
        # Object ACE: 4-byte header + 4-byte mask + 4-byte flags + optional GUIDs + SID
        if offset + 12 > len(raw):
            return None
        ace.access_mask = struct.unpack_from("<I", raw, offset + 4)[0]
        object_flags = struct.unpack_from("<I", raw, offset + 8)[0]

        guid_offset = offset + 12

        if object_flags & 0x01:  # ObjectType present
            if guid_offset + 16 <= len(raw):
                ace.object_type_guid = _format_guid(raw[guid_offset:guid_offset + 16])
            guid_offset += 16

        if object_flags & 0x02:  # InheritedObjectType present
            if guid_offset + 16 <= len(raw):
                ace.inherited_object_type_guid = _format_guid(raw[guid_offset:guid_offset + 16])
            guid_offset += 16

        ace.trustee_sid = _parse_sid_at_offset(raw, guid_offset)

    return ace


def _format_guid(raw: bytes) -> str:
    """Format 16 bytes as a GUID string."""
    if len(raw) < 16:
        return ""
    # GUIDs are stored in mixed-endian format
    part1 = struct.unpack_from("<IHH", raw, 0)
    part2 = raw[8:16]
    return (
        f"{part1[0]:08x}-{part1[1]:04x}-{part1[2]:04x}-"
        f"{part2[0]:02x}{part2[1]:02x}-"
        f"{part2[2]:02x}{part2[3]:02x}{part2[4]:02x}{part2[5]:02x}{part2[6]:02x}{part2[7]:02x}"
    )


def analyze_dangerous_aces(
    sd: SecurityDescriptor,
    object_dn: str = "",
    well_known_sids: Optional[Dict[str, str]] = None,
) -> List[Dict]:
    """Analyze a security descriptor for dangerous ACEs.

    Returns a list of dicts describing each dangerous permission found.
    """
    if not sd.dacl:
        return []

    results = []
    well_known = well_known_sids or {}

    for ace in sd.dacl.dangerous_aces:
        trustee_name = well_known.get(ace.trustee_sid, ace.trustee_sid)
        results.append({
            "object_dn": object_dn,
            "trustee_sid": ace.trustee_sid,
            "trustee_name": trustee_name,
            "permissions": ace.dangerous_permissions,
            "ace_type": ace.type_name,
            "object_type_guid": ace.object_type_guid,
            "inherited": ace.is_inherited,
        })

    return results
