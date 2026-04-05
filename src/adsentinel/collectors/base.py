"""Base collector class — all collectors inherit from this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from adsentinel.logging_config import get_logger

if TYPE_CHECKING:
    from adsentinel.datasources.ldap_source import LDAPSource
    from adsentinel.datasources.winrm_source import WinRMSource
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)


class BaseCollector(ABC):
    """Abstract base class for data collectors.

    Collectors fetch raw AD data and populate the SharedContext.
    They run BEFORE checks, so checks can analyze pre-collected data
    without making their own LDAP queries.
    """

    name: str = ""
    description: str = ""
    requires_winrm: bool = False

    def __init__(
        self,
        ldap: LDAPSource,
        winrm: Optional[WinRMSource] = None,
    ) -> None:
        self.ldap = ldap
        self.winrm = winrm

    @abstractmethod
    def collect(self, context: SharedContext) -> None:
        """Collect data and store it in the shared context.

        Args:
            context: The shared context to populate with collected data.
        """

    def should_skip(self) -> bool:
        """Check if this collector should be skipped."""
        if self.requires_winrm and (self.winrm is None or not self.winrm.is_connected()):
            logger.info("collector_skipped", collector=self.name, reason="WinRM not available")
            return True
        return False
