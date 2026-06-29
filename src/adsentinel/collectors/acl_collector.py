"""ACL Collector — fetches and parses nTSecurityDescriptor for critical AD objects.

Populates context.acls with parsed ACE lists for:
  admin_sd_holder  — CN=AdminSDHolder,CN=System,{base_dn}
  domain_nc        — The domain naming context root (DCSync rights live here)

Uses SD_FLAGS control (DACL_SECURITY_INFORMATION=4) so no SeSecurityPrivilege needed.
Binary parsing uses only stdlib (struct, uuid) — no new dependencies.
"""

from __future__ import annotations

import struct
import uuid
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import ldap3

from adsentinel.collectors.base import BaseCollector
from adsentinel.logging_config import get_logger

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)

# ── Access mask bits ──────────────────────────────────────────────────────────
WRITE_DACL              = 0x00040000
WRITE_OWNER             = 0x00080000
GENERIC_ALL             = 0x10000000
GENERIC_WRITE           = 0x20000000
ADS_RIGHT_DS_WRITE_PROP = 0x00000020  # Write any attribute on the object

# ── DCSync extended right GUIDs (uppercase) ───────────────────────────────────
GUID_GET_CHANGES          = "1131F6AA-9C07-11D1-F79F-00C04FC2DCD2"
GUID_GET_CHANGES_ALL      = "1131F6AD-9C07-11D1-F79F-00C04FC2DCD2"
GUID_GET_CHANGES_FILTERED = "89E95B76-444D-4C62-991A-0FACBEDA640C"

# ── Well-known SIDs that legitimately hold DCSync / AdminSDHolder rights ──────
_STATIC_SAFE_SIDS = {
    "S-1-5-18",     # SYSTEM
    "S-1-5-32-544", # BUILTIN\Administrators
    "S-1-5-9",      # NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
    "S-1-3-0",      # Creator Owner
    "S-1-5-10",     # NT AUTHORITY\SELF
}
_SAFE_RIDS = {
    512,  # Domain Admins
    516,  # Domain Controllers
    519,  # Enterprise Admins
    498,  # Enterprise Read-Only Domain Controllers
    548,  # Account Operators (legitimate AdminSDHolder holder in some configs)
}


def build_safe_sids(domain_sid: str) -> set:
    """Return the full set of SIDs that should legitimately have elevated AD rights."""
    safe = set(_STATIC_SAFE_SIDS)
    if domain_sid:
        for rid in _SAFE_RIDS:
            safe.add(f"{domain_sid}-{rid}")
    return safe


# ── Binary security descriptor parsing ───────────────────────────────────────

def _parse_sid(data: bytes, offset: int = 0) -> str:
    """Parse a binary Windows SID into its string representation (S-R-IA-SA...)."""
    if len(data) - offset < 8:
        return "S-?"
    try:
        revision = data[offset]
        sub_count = data[offset + 1]
        ia = int.from_bytes(data[offset + 2: offset + 8], "big")
        subs = [
            struct.unpack_from("<I", data, offset + 8 + i * 4)[0]
            for i in range(sub_count)
        ]
        return "S-{}-{}-{}".format(revision, ia, "-".join(str(s) for s in subs))
    except (struct.error, IndexError):
        return "S-?"


def _parse_guid(data: bytes, offset: int) -> Optional[str]:
    """Parse a 16-byte Windows GUID (mixed LE/BE) into its canonical string form."""
    if len(data) - offset < 16:
        return None
    try:
        return str(uuid.UUID(bytes_le=data[offset: offset + 16])).upper()
    except Exception:
        return None


def _parse_single_ace(ace_type: int, ace_size: int, ace_raw: bytes) -> Optional[Dict[str, Any]]:
    """Parse one ACE from its raw bytes. Returns None for irrelevant ACE types."""
    # ACCESS_ALLOWED_ACE (0) / ACCESS_DENIED_ACE (2) — Mask(4) + SID
    if ace_type in (0x00, 0x02):
        if ace_size < 12:  # header(4) + mask(4) + min SID(8)
            return None
        mask = struct.unpack_from("<I", ace_raw, 4)[0]
        sid = _parse_sid(ace_raw, 8)
        return {
            "type": ace_type,
            "allowed": ace_type == 0x00,
            "mask": mask,
            "sid": sid,
            "object_type": None,
        }

    # ACCESS_ALLOWED_OBJECT_ACE (5) / ACCESS_DENIED_OBJECT_ACE (6) — with optional GUIDs
    if ace_type in (0x05, 0x06):
        if ace_size < 16:
            return None
        mask  = struct.unpack_from("<I", ace_raw, 4)[0]
        flags = struct.unpack_from("<I", ace_raw, 8)[0]
        sid_off = 12
        object_type = None
        if flags & 0x01:  # ObjectType present
            object_type = _parse_guid(ace_raw, sid_off)
            sid_off += 16
        if flags & 0x02:  # InheritedObjectType present
            sid_off += 16
        sid = _parse_sid(ace_raw, sid_off)
        return {
            "type": ace_type,
            "allowed": ace_type == 0x05,
            "mask": mask,
            "sid": sid,
            "object_type": object_type,
        }

    return None  # System audit, mandatory label, etc. — not relevant


def parse_dacl_aces(sd_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse all ACEs from a Windows self-relative security descriptor blob."""
    if not sd_bytes or len(sd_bytes) < 20:
        return []
    try:
        _rev, _sbz1, _ctrl, _oo, _og, _os, off_dacl = struct.unpack_from("<BBHIIII", sd_bytes, 0)
    except struct.error:
        return []

    if off_dacl == 0 or off_dacl + 8 > len(sd_bytes):
        return []

    try:
        _ar, _as, _acl_size, ace_count, _sb = struct.unpack_from("<BBHHH", sd_bytes, off_dacl)
    except struct.error:
        return []

    aces: List[Dict[str, Any]] = []
    pos = off_dacl + 8
    for _ in range(ace_count):
        if pos + 4 > len(sd_bytes):
            break
        ace_type, _flags, ace_size = struct.unpack_from("<BBH", sd_bytes, pos)
        if ace_size < 4 or pos + ace_size > len(sd_bytes):
            break
        ace = _parse_single_ace(ace_type, ace_size, sd_bytes[pos: pos + ace_size])
        if ace is not None:
            aces.append(ace)
        pos += ace_size

    return aces


# ── Collector ─────────────────────────────────────────────────────────────────

class ACLCollector(BaseCollector):
    """Fetches and parses DACLs for AdminSDHolder and the domain NC root.

    Stores structured ACE lists in context.acls so ACL-009 and ACL-010
    can identify dangerous permissions without making their own LDAP calls.
    """

    name = "acl_data"
    description = "AdminSDHolder and domain NC DACL parsing for ACL/DCSync checks"
    requires_winrm = False

    def collect(self, context: SharedContext) -> None:
        base_dn = self.ldap.base_dn
        config_dn = (
            getattr(context.domain_info, "config_dn", None)
            or f"CN=Configuration,{base_dn}"
        )

        admin_sd_dn = f"CN=AdminSDHolder,CN=System,{base_dn}"
        self._fetch_and_store(context, "admin_sd_holder", admin_sd_dn)
        self._fetch_and_store(context, "domain_nc", base_dn)
        self._collect_pki_acls(context, config_dn)
        self._collect_gpo_acls(context)

        ash_count = len(context.acls.get("admin_sd_holder", {}).get("aces", []))
        dnc_count = len(context.acls.get("domain_nc", {}).get("aces", []))
        pki_count = sum(1 for k in context.acls if k.startswith("pki_"))
        gpo_count = sum(1 for k in context.acls if k.startswith("gpo:"))
        logger.info(
            "acl_data_collected",
            admin_sd_holder_aces=ash_count,
            domain_nc_aces=dnc_count,
            pki_objects=pki_count,
            gpo_objects=gpo_count,
        )

    def _sd_controls(self) -> Optional[Any]:
        """SD_FLAGS control: request DACL only (no SACL, no privilege needed)."""
        try:
            from ldap3.protocol.microsoft import security_descriptor_control
            return security_descriptor_control(sdflags=0x04)
        except ImportError:
            return None

    def _collect_pki_acls(self, context: SharedContext, config_dn: str) -> None:
        """Fetch DACLs for PKI objects: templates, enrollment services, and CAs.

        Stored in context.acls with keys:
          pki_template:<dn>    — certificate template objects
          pki_enrollment:<dn>  — enrollment service objects (ESC5/7)
          pki_ca:<dn>          — certificationAuthority objects (ESC5)
        """
        pki_base = f"CN=Public Key Services,CN=Services,{config_dn}"
        controls = self._sd_controls()
        _targets = [
            ("(objectClass=pKICertificateTemplate)", "pki_template"),
            ("(objectClass=pKIEnrollmentService)", "pki_enrollment"),
            ("(objectClass=certificationAuthority)", "pki_ca"),
        ]
        for obj_filter, prefix in _targets:
            try:
                self.ldap.connection.search(
                    search_base=pki_base,
                    search_filter=obj_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=["nTSecurityDescriptor"],
                    controls=controls,
                )
                for entry in self.ldap.connection.response or []:
                    if entry.get("type") != "searchResEntry":
                        continue
                    dn = entry.get("dn", "")
                    raw = entry.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
                    sd_bytes = raw[0] if isinstance(raw, list) and raw else (raw or None)
                    key = f"{prefix}:{dn}"
                    if sd_bytes:
                        context.acls[key] = {
                            "dn": dn,
                            "aces": parse_dacl_aces(sd_bytes),
                            "parse_error": None,
                        }
                    else:
                        context.acls[key] = {"dn": dn, "aces": [], "parse_error": "no_sd"}
            except Exception as exc:
                logger.warning("pki_acl_collection_failed", filter=obj_filter, error=str(exc))

    def _collect_gpo_acls(self, context: SharedContext) -> None:
        """Fetch DACLs for all GPO objects (groupPolicyContainer).

        Stored in context.acls with keys: gpo:<dn>
        Used by ACL-006 to detect non-privileged principals with write access to GPOs.
        """
        controls = self._sd_controls()
        try:
            self.ldap.connection.search(
                search_base=self.ldap.base_dn,
                search_filter="(objectClass=groupPolicyContainer)",
                search_scope=ldap3.SUBTREE,
                attributes=["nTSecurityDescriptor"],
                controls=controls,
            )
            count = 0
            for entry in self.ldap.connection.response or []:
                if entry.get("type") != "searchResEntry":
                    continue
                dn = entry.get("dn", "")
                raw = entry.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
                sd_bytes = raw[0] if isinstance(raw, list) and raw else (raw or None)
                key = f"gpo:{dn}"
                if sd_bytes:
                    context.acls[key] = {
                        "dn": dn,
                        "aces": parse_dacl_aces(sd_bytes),
                        "parse_error": None,
                    }
                    count += 1
                else:
                    context.acls[key] = {"dn": dn, "aces": [], "parse_error": "no_sd"}
            logger.info("gpo_acls_collected", count=count)
        except Exception as exc:
            logger.warning("gpo_acl_collection_failed", error=str(exc))

    def _fetch_and_store(self, context: SharedContext, key: str, dn: str) -> None:
        sd_bytes = self._fetch_sd(dn)
        if sd_bytes is None:
            logger.warning("ntsecuritydescriptor_unavailable", dn=dn)
            context.acls[key] = {"dn": dn, "aces": [], "parse_error": "fetch_failed"}
            return
        aces = parse_dacl_aces(sd_bytes)
        context.acls[key] = {"dn": dn, "aces": aces, "parse_error": None}

    def _fetch_sd(self, dn: str) -> Optional[bytes]:
        """Fetch the nTSecurityDescriptor (DACL only) for a given DN."""
        try:
            # SD_FLAGS control: 0x04 = DACL_SECURITY_INFORMATION (no SACL, no audit log needed)
            from ldap3.protocol.microsoft import security_descriptor_control
            controls = security_descriptor_control(sdflags=0x04)
        except ImportError:
            controls = None

        try:
            self.ldap.connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["nTSecurityDescriptor"],
                controls=controls,
            )
            for entry in self.ldap.connection.response or []:
                if entry.get("type") != "searchResEntry":
                    continue
                raw = entry.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
                if raw:
                    return raw[0] if isinstance(raw, list) else raw
        except Exception as exc:
            logger.warning("ntsecuritydescriptor_fetch_error", dn=dn, error=str(exc))

        return None
