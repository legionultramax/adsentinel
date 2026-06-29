"""Execution engine — orchestrates collectors and checks.

Enhanced with better error handling and audit logging.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

from adsentinel.checks.base import BaseCheck
from adsentinel.checks.registry import CheckRegistry
from adsentinel.collectors.base import BaseCollector
from adsentinel.collectors.acl_collector import ACLCollector
from adsentinel.collectors.certificates import CertificateCollector
from adsentinel.collectors.computers import ComputerCollector
from adsentinel.collectors.dns import DNSCollector
from adsentinel.collectors.domain_info import DomainInfoCollector
from adsentinel.collectors.gpo import GPOCollector
from adsentinel.collectors.groups import GroupCollector
from adsentinel.collectors.password_policies import PasswordPolicyCollector
from adsentinel.collectors.trusts import TrustCollector
from adsentinel.collectors.users import UserCollector
from adsentinel.collectors.winrm_data import WinRMDataCollector
from adsentinel.config import ScanConfig
from adsentinel.datasources.ldap_source import LDAPSource
from adsentinel.datasources.winrm_source import WinRMSource
from adsentinel.engine.context import SharedContext
from adsentinel.engine.plugin_loader import discover_checks
from adsentinel.logging_config import get_logger
from adsentinel.models.finding import CheckResult, Finding

logger = get_logger(__name__)


# Ordered list of collectors (order matters: domain_info first, then users, then groups,
# then WinRMDataCollector last so GPO paths are already populated for the SYSVOL scan)
DEFAULT_COLLECTORS: List[Type[BaseCollector]] = [
    DomainInfoCollector,
    PasswordPolicyCollector,
    UserCollector,
    GroupCollector,
    ComputerCollector,
    TrustCollector,
    GPOCollector,
    DNSCollector,
    CertificateCollector,
    ACLCollector,        # after DomainInfoCollector (needs base_dn + domain_sid)
    WinRMDataCollector,  # must run after GPOCollector (needs gpo file_sys_path for SYSVOL scan)
]


class ScanResult:
    """Complete scan result container."""

    def __init__(self) -> None:
        self.scan_start: datetime = datetime.now(timezone.utc)
        self.scan_end: Optional[datetime] = None
        self.config_summary: Dict[str, str] = {}
        self.context: Optional[SharedContext] = None
        self.check_results: List[CheckResult] = []
        self.collection_errors: List[str] = []
        self.total_checks: int = 0
        self.checks_passed: int = 0
        self.checks_failed: int = 0
        self.checks_skipped: int = 0

    @property
    def all_findings(self) -> List[Finding]:
        """Get all findings from all check results."""
        findings = []
        for result in self.check_results:
            findings.extend(result.findings)
        return findings

    @property
    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        """Group findings by severity."""
        grouped: Dict[str, List[Finding]] = {}
        for finding in self.all_findings:
            sev = finding.severity.value
            if sev not in grouped:
                grouped[sev] = []
            grouped[sev].append(finding)
        return grouped

    @property
    def critical_count(self) -> int:
        return len(self.findings_by_severity.get("CRITICAL", []))

    @property
    def high_count(self) -> int:
        return len(self.findings_by_severity.get("HIGH", []))

    @property
    def medium_count(self) -> int:
        return len(self.findings_by_severity.get("MEDIUM", []))

    @property
    def low_count(self) -> int:
        return len(self.findings_by_severity.get("LOW", []))

    @property
    def info_count(self) -> int:
        return len(self.findings_by_severity.get("INFO", []))

    @property
    def has_scan_errors(self) -> bool:
        """True if the scan encountered errors that may have prevented checks from running."""
        return bool(self.collection_errors) and self.total_checks == 0

    @property
    def exit_code(self) -> int:
        """CI/CD exit code: 0=clean, 1=HIGH, 2=CRITICAL, 3=scan failure."""
        if self.has_scan_errors:
            return 3
        if self.critical_count > 0:
            return 2
        if self.high_count > 0:
            return 1
        return 0

    @property
    def duration_seconds(self) -> float:
        if self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return 0.0


class ScanEngine:
    """Main scan engine that orchestrates the full assessment."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.ldap = LDAPSource(config)
        self.winrm = WinRMSource(config)

    def run(self) -> ScanResult:
        """Execute a full security assessment scan."""
        result = ScanResult()
        result.config_summary = {
            "server": self.config.server,
            "domain": self.config.domain,
            "auth_method": self.config.auth_method.value,
            "ssl": str(self.config.use_ssl),
            "winrm": str(self.config.use_winrm),
        }

        try:
            # Phase 1: Connect
            logger.info("scan_starting", server=self.config.server, domain=self.config.domain)
            self._connect()

            # Phase 2: Collect data
            context = SharedContext()
            self._run_collectors(context, result)
            result.context = context

            # Phase 3: Discover and run checks
            discover_checks()
            check_classes = CheckRegistry.get_checks_filtered(
                categories=self.config.categories or None,
                check_ids=self.config.check_ids or None,
                exclude_categories=self.config.exclude_categories or None,
            )

            logger.info("running_checks", count=len(check_classes))
            result.total_checks = len(check_classes)

            for check_cls in check_classes:
                check_result = self._run_check(check_cls, context)
                result.check_results.append(check_result)

                if check_result.error:
                    result.checks_failed += 1
                elif check_result.skipped:
                    result.checks_skipped += 1
                else:
                    result.checks_passed += 1

            logger.info("scan_success")

        except Exception as e:
            logger.error("scan_failed", error=str(e))
            result.collection_errors.append(str(e))

        finally:
            self._disconnect()
            result.scan_end = datetime.now(timezone.utc)
            # Final audit log
            logger.info(
                "scan_complete",
                duration=f"{result.duration_seconds:.1f}s",
                total_findings=len(result.all_findings),
                critical=result.critical_count,
                high=result.high_count,
                medium=result.medium_count,
                low=result.low_count,
                info=result.info_count,
                errors=len(result.collection_errors),
                outcome="success" if not result.has_scan_errors else "failed",
            )

        return result

    def _connect(self) -> None:
        """Establish connections to data sources with resilience."""
        self.ldap.connect()
        if self.config.use_winrm:
            self.winrm.connect()

    def _disconnect(self) -> None:
        """Close all connections."""
        self.ldap.disconnect()
        self.winrm.disconnect()

    def _run_collectors(self, context: SharedContext, result: ScanResult) -> None:
        """Run all data collectors in order."""
        for collector_cls in DEFAULT_COLLECTORS:
            collector = collector_cls(ldap=self.ldap, winrm=self.winrm)

            if collector.should_skip():
                continue

            try:
                start = time.monotonic()
                collector.collect(context)
                duration = time.monotonic() - start
                logger.info(
                    "collector_complete",
                    collector=collector.name,
                    duration=f"{duration:.2f}s",
                )
            except Exception as e:
                error_msg = f"Collector '{collector.name}' failed: {e}"
                logger.error("collector_failed", collector=collector.name, error=str(e))
                result.collection_errors.append(error_msg)
                context.collection_errors.append(error_msg)

    def _run_check(self, check_cls: Type[BaseCheck], context: SharedContext) -> CheckResult:
        """Run a single check with error isolation."""
        try:
            check_instance = check_cls(context)
            return check_instance.execute()
        except Exception as e:
            logger.error("check_instantiation_failed", check=check_cls.__name__, error=str(e))
            return CheckResult(
                check_id=getattr(check_cls, "id", "UNKNOWN"),
                check_name=getattr(check_cls, "name", check_cls.__name__),
                category=getattr(check_cls, "category", "Unknown"),
                error=str(e),
            )
