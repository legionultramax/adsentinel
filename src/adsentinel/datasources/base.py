"""Abstract base for data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class DataSource(ABC):
    """Protocol for all data sources (LDAP, WinRM, ADWS)."""

    @abstractmethod
    def connect(self) -> None:
        """Establish connection to the data source."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close the connection."""

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if the connection is active."""
