"""Injection-safe LDAP filter builder.

Prevents LDAP injection by escaping special characters in filter values
per RFC 4515 Section 3.
"""

from __future__ import annotations

from typing import List

# Characters that must be escaped in LDAP filter values (RFC 4515)
_ESCAPE_MAP = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\x00": "\\00",
}


def escape_filter_value(value: str) -> str:
    """Escape special characters in an LDAP filter value per RFC 4515."""
    result = []
    for char in value:
        if char in _ESCAPE_MAP:
            result.append(_ESCAPE_MAP[char])
        elif ord(char) > 127:
            # Escape non-ASCII as hex
            for byte in char.encode("utf-8"):
                result.append(f"\\{byte:02x}")
        else:
            result.append(char)
    return "".join(result)


def eq(attribute: str, value: str) -> str:
    """Build an equality filter: (attribute=value)."""
    return f"({attribute}={escape_filter_value(value)})"


def ge(attribute: str, value: str) -> str:
    """Build a greater-or-equal filter: (attribute>=value)."""
    return f"({attribute}>={escape_filter_value(value)})"


def le(attribute: str, value: str) -> str:
    """Build a less-or-equal filter: (attribute<=value)."""
    return f"({attribute}<={escape_filter_value(value)})"


def present(attribute: str) -> str:
    """Build a presence filter: (attribute=*)."""
    return f"({attribute}=*)"


def not_filter(inner: str) -> str:
    """Build a NOT filter: (!(inner))."""
    return f"(!{inner})"


def and_filter(filters: List[str]) -> str:
    """Build an AND filter: (&(f1)(f2)...)."""
    if len(filters) == 1:
        return filters[0]
    return f"(&{''.join(filters)})"


def or_filter(filters: List[str]) -> str:
    """Build an OR filter: (|(f1)(f2)...)."""
    if len(filters) == 1:
        return filters[0]
    return f"(|{''.join(filters)})"


def build_user_filter(
    enabled_only: bool = True,
    with_spn: bool = False,
    no_preauth: bool = False,
    admin_count: bool = False,
) -> str:
    """Build a common user search filter with optional conditions."""
    parts = [eq("objectCategory", "person"), eq("objectClass", "user")]

    if enabled_only:
        parts.append(not_filter(eq("userAccountControl:1.2.840.113556.1.4.803:", "2")))

    if with_spn:
        parts.append(present("servicePrincipalName"))

    if no_preauth:
        parts.append(eq("userAccountControl:1.2.840.113556.1.4.803:", "4194304"))

    if admin_count:
        parts.append(eq("adminCount", "1"))

    return and_filter(parts)


def build_group_filter(group_type: str = "security") -> str:
    """Build a group search filter."""
    parts = [eq("objectCategory", "group")]
    if group_type == "security":
        # Security groups have bit 31 set
        parts.append(eq("groupType:1.2.840.113556.1.4.803:", "2147483648"))
    return and_filter(parts)


def build_computer_filter(enabled_only: bool = True) -> str:
    """Build a computer search filter."""
    parts = [eq("objectCategory", "computer")]
    if enabled_only:
        parts.append(not_filter(eq("userAccountControl:1.2.840.113556.1.4.803:", "2")))
    return and_filter(parts)
