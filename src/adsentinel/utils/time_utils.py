"""Active Directory timestamp conversion utilities.

AD uses several timestamp formats:
- Windows FileTime: 100-nanosecond intervals since Jan 1, 1601 UTC
- Generalized Time: YYYYMMDDHHmmss.0Z format
- Large Integer (negative): Used for password policy durations
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Union

# Windows epoch: January 1, 1601
_WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Ticks per second (100-nanosecond intervals)
_TICKS_PER_SECOND = 10_000_000


def filetime_to_datetime(filetime: Union[int, str]) -> Optional[datetime]:
    """Convert a Windows FileTime (100-ns since 1601-01-01) to datetime.

    Returns None for special values (0, never-expires 0x7FFFFFFFFFFFFFFF).
    """
    try:
        ft = int(filetime) if isinstance(filetime, str) else filetime
    except (ValueError, TypeError):
        return None

    # Special values
    if ft <= 0 or ft >= 0x7FFFFFFFFFFFFFFF:
        return None

    seconds = ft / _TICKS_PER_SECOND
    try:
        return _WINDOWS_EPOCH + timedelta(seconds=seconds)
    except (OverflowError, OSError):
        return None


def generalized_time_to_datetime(gt: str) -> Optional[datetime]:
    """Convert AD GeneralizedTime (YYYYMMDDHHmmss.0Z) to datetime."""
    if not gt:
        return None
    try:
        # Strip trailing Z and any fractional seconds (.0, .123, etc.)
        clean = gt.rstrip("Z")
        if "." in clean:
            clean = clean.split(".")[0]
        dt = datetime.strptime(clean, "%Y%m%d%H%M%S")
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def ad_duration_to_days(duration: Union[int, str]) -> float:
    """Convert AD duration (negative 100-ns intervals) to days.

    AD stores durations like maxPwdAge as negative values.
    0 means "never expires".
    """
    try:
        val = int(duration) if isinstance(duration, str) else duration
    except (ValueError, TypeError):
        return 0.0
    if val == 0:
        return 0.0
    # Convert negative 100-ns intervals to positive days
    return abs(val) / (_TICKS_PER_SECOND * 86400)


def ad_duration_to_minutes(duration: Union[int, str]) -> float:
    """Convert AD duration (negative 100-ns intervals) to minutes."""
    try:
        val = int(duration) if isinstance(duration, str) else duration
    except (ValueError, TypeError):
        return 0.0
    if val == 0:
        return 0.0
    return abs(val) / (_TICKS_PER_SECOND * 60)


def days_since(dt: Optional[datetime]) -> int:
    """Calculate days since a given datetime. Returns -1 if None."""
    if dt is None:
        return -1
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    return max(0, delta.days)
