"""Global check registry — singleton that tracks all registered checks."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Type

from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


class CheckRegistry:
    """Global registry of all security checks.

    Checks register themselves via the @check decorator at import time.
    The registry enforces unique IDs and supports lookup by ID, category, or severity.
    """

    _checks: Dict[str, Type] = {}  # check_id -> check_class
    _categories: Dict[str, List[str]] = {}  # category -> [check_ids]

    @classmethod
    def register(cls, check_class: Type) -> None:
        """Register a check class. Raises on duplicate IDs (unless same class re-registered)."""
        check_id = check_class.id
        if not check_id:
            logger.warning("check_missing_id", cls=check_class.__name__)
            return

        if check_id in cls._checks:
            # Allow re-registration of the same class (happens when discover_checks
            # is called multiple times in the same process, e.g. tests or multi-scan)
            if cls._checks[check_id] is check_class:
                return
            existing = cls._checks[check_id].__name__
            raise ValueError(
                f"Duplicate check ID '{check_id}': {check_class.__name__} conflicts with {existing}"
            )

        cls._checks[check_id] = check_class

        category = check_class.category
        if category not in cls._categories:
            cls._categories[category] = []
        cls._categories[category].append(check_id)

        logger.debug("check_registered", id=check_id, name=check_class.name, category=category)

    @classmethod
    def get_check_class(cls, check_id: str) -> Optional[Type]:
        """Get a check class by its ID."""
        return cls._checks.get(check_id)

    @classmethod
    def get_all_checks(cls) -> List[Type]:
        """Get all registered check classes."""
        return list(cls._checks.values())

    @classmethod
    def get_all_check_ids(cls) -> Set[str]:
        """Get all registered check IDs."""
        return set(cls._checks.keys())

    @classmethod
    def get_checks_by_category(cls, category: str) -> List[Type]:
        """Get all check classes in a category."""
        check_ids = cls._categories.get(category, [])
        return [cls._checks[cid] for cid in check_ids if cid in cls._checks]

    @classmethod
    def get_categories(cls) -> List[str]:
        """Get all registered categories."""
        return list(cls._categories.keys())

    @classmethod
    def get_checks_filtered(
        cls,
        categories: Optional[List[str]] = None,
        check_ids: Optional[List[str]] = None,
        exclude_categories: Optional[List[str]] = None,
    ) -> List[Type]:
        """Get checks filtered by categories and/or specific IDs."""
        result = []

        if check_ids:
            # Specific check IDs take priority
            for cid in check_ids:
                if cid in cls._checks:
                    result.append(cls._checks[cid])
            return result

        exclude = set(exclude_categories or [])

        if categories:
            for cat in categories:
                if cat not in exclude:
                    result.extend(cls.get_checks_by_category(cat))
        else:
            # All categories minus excluded
            for cat in cls._categories:
                if cat not in exclude:
                    result.extend(cls.get_checks_by_category(cat))

        return result

    @classmethod
    def clear(cls) -> None:
        """Clear the registry (used in testing)."""
        cls._checks.clear()
        cls._categories.clear()

    @classmethod
    def summary(cls) -> Dict[str, int]:
        """Get a summary of registered checks by category."""
        return {cat: len(ids) for cat, ids in cls._categories.items()}
