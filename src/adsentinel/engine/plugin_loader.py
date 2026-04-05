"""Plugin loader — auto-discovers check modules via importlib."""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Type

from adsentinel.checks.base import BaseCheck
from adsentinel.checks.registry import CheckRegistry
from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


def discover_checks(package_name: str = "adsentinel.checks") -> List[Type[BaseCheck]]:
    """Auto-discover all check classes in the checks package and subpackages.

    Walks through all modules in adsentinel.checks.*, imports them,
    and collects any classes that are registered in the CheckRegistry.
    """
    discovered: List[Type[BaseCheck]] = []

    try:
        package = importlib.import_module(package_name)
    except ImportError as e:
        logger.error("failed_to_import_checks_package", error=str(e))
        return discovered

    if not hasattr(package, "__path__"):
        return discovered

    for importer, modname, ispkg in pkgutil.walk_packages(
        package.__path__,
        prefix=f"{package_name}.",
    ):
        try:
            importlib.import_module(modname)
            logger.debug("loaded_check_module", module=modname)
        except Exception as e:
            logger.warning("failed_to_load_check_module", module=modname, error=str(e))

    # After all modules are imported, the @check decorator has registered them
    discovered = list(CheckRegistry.get_all_checks())
    logger.info("discovered_checks", count=len(discovered))
    return discovered


def discover_custom_checks(custom_dir: str) -> List[Type[BaseCheck]]:
    """Load custom check plugins from an external directory."""
    import sys

    path = Path(custom_dir)
    if not path.exists() or not path.is_dir():
        logger.warning("custom_checks_dir_not_found", path=custom_dir)
        return []

    # Add to sys.path so imports work
    sys.path.insert(0, str(path.parent))

    before = set(CheckRegistry.get_all_check_ids())

    for py_file in path.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        module_name = f"custom.{py_file.stem}"
        try:
            importlib.import_module(module_name)
            logger.info("loaded_custom_check", file=py_file.name)
        except Exception as e:
            logger.warning("failed_to_load_custom_check", file=py_file.name, error=str(e))

    after = set(CheckRegistry.get_all_check_ids())
    new_checks = after - before
    logger.info("custom_checks_loaded", count=len(new_checks))

    return [
        CheckRegistry.get_check_class(cid)
        for cid in new_checks
        if CheckRegistry.get_check_class(cid) is not None
    ]
