"""Severity levels for security findings."""

from enum import Enum


class Severity(str, Enum):
    """Finding severity levels, ordered from most to least critical."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> float:
        """Scoring weight for posture calculation."""
        return {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 10.0,
            Severity.MEDIUM: 3.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0,
        }[self]

    @property
    def color(self) -> str:
        """HTML color code for reporting."""
        return {
            Severity.CRITICAL: "#ff4444",
            Severity.HIGH: "#ff8800",
            Severity.MEDIUM: "#ffcc00",
            Severity.LOW: "#44aaff",
            Severity.INFO: "#888888",
        }[self]

    @property
    def icon(self) -> str:
        """Terminal icon for CLI output."""
        return {
            Severity.CRITICAL: "[!]",
            Severity.HIGH: "[!]",
            Severity.MEDIUM: "[~]",
            Severity.LOW: "[-]",
            Severity.INFO: "[i]",
        }[self]
