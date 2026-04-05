"""Utility functions for ADSentinel."""

from typing import Optional


def safe_int(value: object, default: Optional[int] = None) -> Optional[int]:
    """Safely convert a value to int, returning default on failure.

    Handles empty strings, None, and non-numeric strings that may come
    from registry values or LDAP attributes.
    """
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default