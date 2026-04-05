"""Collector for AD Certificate Services — templates, CAs, and enrollment services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from adsentinel.collectors.base import BaseCollector
from adsentinel.constants import (
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME,
    CT_FLAG_NO_SECURITY_EXTENSION,
    CT_FLAG_PEND_ALL_REQUESTS,
    EDITF_ATTRIBUTESUBJECTALTNAME2,
    EKU_ANY_PURPOSE,
    EKU_CERTIFICATE_REQUEST_AGENT,
    EKU_CLIENT_AUTH,
    EKU_SMART_CARD_LOGON,
)
from adsentinel.logging_config import get_logger
from adsentinel.utils.ldap_filter import and_filter, eq, or_filter

if TYPE_CHECKING:
    from adsentinel.engine.context import SharedContext

logger = get_logger(__name__)


class CertificateCollector(BaseCollector):
    """Collects AD CS certificate templates, CAs, and enrollment services."""

    name = "certificates"
    description = "AD Certificate Services templates, CAs, and enrollment"

    def collect(self, context: SharedContext) -> None:
        config_dn = context.domain_info.config_dn or f"CN=Configuration,{self.ldap.base_dn}"

        self._collect_templates(context, config_dn)
        self._collect_cas(context, config_dn)
        self._collect_enrollment_services(context, config_dn)

    def _collect_templates(self, context: SharedContext, config_dn: str) -> None:
        """Collect certificate templates from AD."""
        search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}"
        try:
            entries = self.ldap.search(
                search_base=search_base,
                search_filter=eq("objectClass", "pKICertificateTemplate"),
                attributes=[
                    "distinguishedName", "cn", "displayName",
                    "msPKI-Certificate-Name-Flag",
                    "msPKI-Enrollment-Flag",
                    "msPKI-RA-Signature",
                    "msPKI-Certificate-Application-Policy",
                    "pKIExtendedKeyUsage",
                    "msPKI-Template-Schema-Version",
                    "msPKI-Private-Key-Flag",
                    "nTSecurityDescriptor",
                    "flags",
                ],
            )
        except Exception as e:
            logger.warning("certificate_template_collection_failed", error=str(e))
            return

        templates = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            name_flag = self._get_int(attrs, "msPKI-Certificate-Name-Flag")
            enrollment_flag = self._get_int(attrs, "msPKI-Enrollment-Flag")
            ra_signature = self._get_int(attrs, "msPKI-RA-Signature")
            ekus = self._get_list(attrs, "pKIExtendedKeyUsage")
            app_policies = self._get_list(attrs, "msPKI-Certificate-Application-Policy")
            schema_version = self._get_int(attrs, "msPKI-Template-Schema-Version")

            # Combine EKUs from both attributes
            all_ekus = list(set(ekus + app_policies))

            template = {
                "dn": entry.get("dn", ""),
                "name": self._get_str(attrs, "cn"),
                "display_name": self._get_str(attrs, "displayName"),
                "name_flag": name_flag,
                "enrollment_flag": enrollment_flag,
                "ra_signature": ra_signature,
                "ekus": all_ekus,
                "schema_version": schema_version,
                # Pre-compute ESC-relevant booleans
                "enrollee_supplies_subject": bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
                "enrollee_supplies_san": bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME),
                "no_security_extension": bool(name_flag & CT_FLAG_NO_SECURITY_EXTENSION),
                "requires_manager_approval": bool(enrollment_flag & CT_FLAG_PEND_ALL_REQUESTS),
                "requires_ra_signature": ra_signature > 0,
                "allows_client_auth": (
                    EKU_CLIENT_AUTH in all_ekus
                    or EKU_SMART_CARD_LOGON in all_ekus
                    or EKU_ANY_PURPOSE in all_ekus
                    or not all_ekus  # No EKU = any purpose
                ),
                "allows_any_purpose": EKU_ANY_PURPOSE in all_ekus or not all_ekus,
                "is_request_agent": EKU_CERTIFICATE_REQUEST_AGENT in all_ekus,
            }
            templates.append(template)

        context.certificate_templates = templates
        logger.info("collected_certificate_templates", count=len(templates))

    def _collect_cas(self, context: SharedContext, config_dn: str) -> None:
        """Collect Certificate Authorities."""
        search_base = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,{config_dn}"
        try:
            entries = self.ldap.search(
                search_base=search_base,
                search_filter=eq("objectClass", "certificationAuthority"),
                attributes=[
                    "distinguishedName", "cn", "cACertificate",
                    "certificateTemplates", "dNSHostName",
                ],
            )
        except Exception as e:
            logger.warning("ca_collection_failed", error=str(e))
            return

        cas = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            cas.append({
                "dn": entry.get("dn", ""),
                "name": self._get_str(attrs, "cn"),
                "dns_hostname": self._get_str(attrs, "dNSHostName"),
            })

        context.certificate_authorities = cas
        logger.info("collected_certificate_authorities", count=len(cas))

    def _collect_enrollment_services(self, context: SharedContext, config_dn: str) -> None:
        """Collect enrollment services (ESC8 - HTTP enrollment)."""
        search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}"
        try:
            entries = self.ldap.search(
                search_base=search_base,
                search_filter=eq("objectClass", "pKIEnrollmentService"),
                attributes=[
                    "distinguishedName", "cn", "dNSHostName",
                    "certificateTemplates", "flags",
                    "msPKI-Enrollment-Servers",
                ],
            )
        except Exception as e:
            logger.warning("enrollment_service_collection_failed", error=str(e))
            return

        services = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            flags = self._get_int(attrs, "flags")
            templates = self._get_list(attrs, "certificateTemplates")
            enrollment_servers = self._get_list(attrs, "msPKI-Enrollment-Servers")

            services.append({
                "dn": entry.get("dn", ""),
                "name": self._get_str(attrs, "cn"),
                "dns_hostname": self._get_str(attrs, "dNSHostName"),
                "templates": templates,
                "flags": flags,
                "san_flag_enabled": bool(flags & EDITF_ATTRIBUTESUBJECTALTNAME2),
                "enrollment_servers": enrollment_servers,
                "has_http_enrollment": any("http" in s.lower() for s in enrollment_servers),
            })

        context.enrollment_services = services
        logger.info("collected_enrollment_services", count=len(services))

    def _get_str(self, attrs: dict, key: str) -> str:
        val = attrs.get(key, "")
        return str(val[0]) if isinstance(val, list) and val else str(val) if val else ""

    def _get_int(self, attrs: dict, key: str) -> int:
        val = attrs.get(key, 0)
        if isinstance(val, list):
            val = val[0] if val else 0
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    def _get_list(self, attrs: dict, key: str) -> list:
        val = attrs.get(key, [])
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)] if val else []
