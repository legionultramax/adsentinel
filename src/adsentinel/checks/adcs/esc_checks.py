"""AD Certificate Services checks — ESC1 through ESC13 + supplemental (ADCS-001 to ADCS-020)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import (
    EKU_ANY_PURPOSE,
    EKU_CERTIFICATE_REQUEST_AGENT,
    EKU_CLIENT_AUTH,
    EKU_SMART_CARD_LOGON,
    MITRE_STEAL_OR_FORGE_CERTS,
)
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity
from adsentinel.utils import safe_int

_MITRE_ADCS = [MitreAttack(
    technique_id=MITRE_STEAL_OR_FORGE_CERTS,
    technique_name="Steal or Forge Authentication Certificates",
    tactic="Credential Access",
)]


@check
class ADCS001_ESC1(BaseCheck):
    id = "ADCS-001"
    name = "ESC1 — Template Allows SAN with Client Auth"
    description = "Templates where enrollee supplies Subject Alternative Name + client auth EKU"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        vuln = [
            t for t in self.context.certificate_templates
            if t.get("enrollee_supplies_subject")
            and t.get("allows_client_auth")
            and not t.get("requires_manager_approval")
            and not t.get("requires_ra_signature")
        ]
        if vuln:
            return [self.finding(
                title=f"ESC1: {len(vuln)} templates allow enrollee-supplied SAN with client auth",
                description=(
                    "These templates let the requester specify an arbitrary Subject Alternative Name "
                    "(SAN) and have a client authentication EKU. An attacker can request a certificate "
                    "as any user — including Domain Admin — and authenticate with it."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[AffectedObject(
                    dn=t["dn"], sam_account_name=t["name"], object_type="certificate_template",
                ) for t in vuln],
                affected_count=len(vuln),
                remediation_desc="Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from these templates or require manager approval.",
                powershell="Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties msPKI-Certificate-Name-Flag | Where-Object {$_.'msPKI-Certificate-Name-Flag' -band 1}",
                mitre=_MITRE_ADCS,
                nist_800_53=["IA-5", "SC-17"],
                details={"vulnerable_templates": [t["name"] for t in vuln]},
            )]
        return []


@check
class ADCS002_ESC2(BaseCheck):
    id = "ADCS-002"
    name = "ESC2 — Template Allows Any Purpose EKU"
    description = "Templates with Any Purpose or no EKU restrictions"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        vuln = [
            t for t in self.context.certificate_templates
            if t.get("allows_any_purpose")
            and not t.get("requires_manager_approval")
        ]
        if vuln:
            return [self.finding(
                title=f"ESC2: {len(vuln)} templates allow Any Purpose or have no EKU restrictions",
                description=(
                    "Templates with 'Any Purpose' EKU or no EKU at all can be used for client authentication, "
                    "code signing, or any other purpose. This is functionally equivalent to ESC1 when combined "
                    "with enrollee-supplied SAN."
                ),
                severity=Severity.HIGH,
                affected_objects=[AffectedObject(
                    dn=t["dn"], sam_account_name=t["name"], object_type="certificate_template",
                ) for t in vuln],
                affected_count=len(vuln),
                remediation_desc="Set explicit EKUs on these templates. Remove Any Purpose OID.",
                mitre=_MITRE_ADCS,
                nist_800_53=["IA-5"],
                details={"vulnerable_templates": [t["name"] for t in vuln]},
            )]
        return []


@check
class ADCS003_ESC3(BaseCheck):
    id = "ADCS-003"
    name = "ESC3 — Certificate Request Agent Templates"
    description = "Templates that allow enrollment agent certificates"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        vuln = [
            t for t in self.context.certificate_templates
            if t.get("is_request_agent")
            and not t.get("requires_manager_approval")
        ]
        if vuln:
            return [self.finding(
                title=f"ESC3: {len(vuln)} templates allow Certificate Request Agent enrollment",
                description=(
                    "Certificate Request Agent templates allow a user to request certificates on behalf of "
                    "other users. An attacker with an enrollment agent cert can request certs as any user."
                ),
                severity=Severity.HIGH,
                affected_objects=[AffectedObject(
                    dn=t["dn"], sam_account_name=t["name"], object_type="certificate_template",
                ) for t in vuln],
                affected_count=len(vuln),
                remediation_desc="Restrict enrollment agent template enrollment to specific trusted accounts.",
                mitre=_MITRE_ADCS,
                nist_800_53=["IA-5"],
            )]
        return []


@check
class ADCS004_ESC4(BaseCheck):
    id = "ADCS-004"
    name = "ESC4 — Template ACL Allows Modification"
    description = "Check if non-admin users can modify certificate template attributes"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        # ESC4 requires ACL analysis on templates — flag as info if templates exist
        if self.context.certificate_templates:
            return [self.finding(
                title=f"ESC4: {len(self.context.certificate_templates)} certificate templates — verify ACLs",
                description=(
                    "ESC4 occurs when non-privileged users have write access to certificate template objects. "
                    "An attacker could modify a template to enable ESC1/ESC2 conditions. "
                    "Full ACL analysis on template objects is recommended."
                ),
                severity=Severity.INFO,
                affected_count=len(self.context.certificate_templates),
                remediation_desc="Audit certificate template ACLs. Only CA Admins and Enterprise Admins should have write access.",
                powershell="foreach ($t in (Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' -Filter *)) { (Get-ACL \"AD:\\$($t.DistinguishedName)\").Access | Where-Object {$_.ActiveDirectoryRights -match 'Write'} }",
                mitre=_MITRE_ADCS,
                nist_800_53=["AC-6"],
            )]
        return []


@check
class ADCS005_ESC5(BaseCheck):
    id = "ADCS-005"
    name = "ESC5 — PKI Object ACL Abuse"
    description = "Check CA and PKI container ACL security"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        if self.context.certificate_authorities:
            return [self.finding(
                title=f"ESC5: {len(self.context.certificate_authorities)} CAs found — verify PKI object ACLs",
                description=(
                    "ESC5 targets CA server objects, enrollment service objects, and the NTAuth store. "
                    "Compromising these objects can enable certificate forgery. "
                    "Review ACLs on all objects in CN=Public Key Services."
                ),
                severity=Severity.INFO,
                affected_count=len(self.context.certificate_authorities),
                remediation_desc="Restrict write access on PKI objects to CA Admins and Enterprise Admins only.",
                mitre=_MITRE_ADCS,
                nist_800_53=["AC-6"],
            )]
        return []


@check
class ADCS006_ESC6(BaseCheck):
    id = "ADCS-006"
    name = "ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA"
    description = "CA flag allows requesters to specify SAN on any template"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        vuln = [
            es for es in self.context.enrollment_services
            if es.get("san_flag_enabled")
        ]
        if vuln:
            return [self.finding(
                title=f"ESC6: {len(vuln)} CAs have EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
                description=(
                    "This CA flag allows any certificate requester to specify a Subject Alternative Name, "
                    "regardless of template configuration. This effectively makes ALL templates vulnerable "
                    "to ESC1-style attacks."
                ),
                severity=Severity.CRITICAL,
                affected_objects=[AffectedObject(
                    dn=es["dn"], sam_account_name=es["name"], object_type="enrollment_service",
                ) for es in vuln],
                affected_count=len(vuln),
                remediation_desc="Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA.",
                powershell="certutil -config \"CA_NAME\" -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2\nnet stop certsvc && net start certsvc",
                mitre=_MITRE_ADCS,
                nist_800_53=["IA-5", "SC-17"],
            )]
        return []


@check
class ADCS007_ESC7(BaseCheck):
    id = "ADCS-007"
    name = "ESC7 — CA Manager/Officer Permissions"
    description = "Check for dangerous CA manager approvals"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        # ESC7 requires checking who has ManageCA / ManageCertificates rights
        if self.context.enrollment_services:
            return [self.finding(
                title=f"ESC7: Verify CA Manager/Officer permissions on {len(self.context.enrollment_services)} enrollment services",
                description=(
                    "ESC7 allows users with ManageCA permission to enable EDITF_ATTRIBUTESUBJECTALTNAME2, "
                    "or users with ManageCertificates to approve pending requests. "
                    "Audit who holds these rights."
                ),
                severity=Severity.MEDIUM,
                affected_count=len(self.context.enrollment_services),
                remediation_desc="Restrict ManageCA and ManageCertificates permissions to CA administrators only.",
                powershell="certutil -config \"CA_NAME\" -getacl",
                mitre=_MITRE_ADCS,
                nist_800_53=["AC-6"],
            )]
        return []


@check
class ADCS008_ESC8(BaseCheck):
    id = "ADCS-008"
    name = "ESC8 — HTTP Certificate Enrollment"
    description = "CA exposes HTTP enrollment endpoints vulnerable to NTLM relay"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        vuln = [
            es for es in self.context.enrollment_services
            if es.get("has_http_enrollment") or es.get("enrollment_servers")
        ]
        if vuln:
            return [self.finding(
                title=f"ESC8: {len(vuln)} CAs expose HTTP enrollment endpoints",
                description=(
                    "HTTP-based certificate enrollment (Web Enrollment, CEP/CES) is vulnerable to "
                    "NTLM relay attacks. An attacker can coerce a DC to authenticate and relay to the "
                    "CA's HTTP endpoint to obtain a certificate as the DC."
                ),
                severity=Severity.HIGH,
                affected_objects=[AffectedObject(
                    dn=es["dn"], sam_account_name=es["name"], object_type="enrollment_service",
                ) for es in vuln],
                affected_count=len(vuln),
                remediation_desc="Disable HTTP enrollment or enforce EPA (Extended Protection for Authentication).",
                mitre=_MITRE_ADCS,
                nist_800_53=["SC-8"],
            )]
        return []


@check
class ADCS009_ESC9(BaseCheck):
    id = "ADCS-009"
    name = "ESC9 — No Security Extension (szOID_NTDS_CA_SECURITY_EXT)"
    description = "Templates without strong mapping security extension"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        vuln = [
            t for t in self.context.certificate_templates
            if t.get("no_security_extension")
            and t.get("allows_client_auth")
        ]
        if vuln:
            return [self.finding(
                title=f"ESC9: {len(vuln)} templates lack the security extension for strong cert mapping",
                description=(
                    "Without szOID_NTDS_CA_SECURITY_EXT, certificates issued by these templates "
                    "bypass strong certificate mapping (KB5014754). An attacker with GenericWrite "
                    "on a target can modify their UPN and request a certificate to impersonate them."
                ),
                severity=Severity.HIGH,
                affected_objects=[AffectedObject(
                    dn=t["dn"], sam_account_name=t["name"], object_type="certificate_template",
                ) for t in vuln],
                affected_count=len(vuln),
                remediation_desc="Remove CT_FLAG_NO_SECURITY_EXTENSION from affected templates.",
                mitre=_MITRE_ADCS,
                nist_800_53=["IA-5"],
            )]
        return []


@check
class ADCS010_ESC10(BaseCheck):
    id = "ADCS-010"
    name = "ESC10 — Weak Certificate Mapping"
    description = "Check if strong certificate mapping is enforced"
    category = "AD Certificate Services"
    requires_winrm = True

    def run(self) -> List[Finding]:
        # Registry: HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel
        # StrongCertificateBindingEnforcement = 0 (disabled), 1 (compat), 2 (full)
        strong_mapping = safe_int(self.context.registry_values.get("StrongCertificateBindingEnforcement", ""))
        if strong_mapping is not None and strong_mapping < 2:
            return [self.finding(
                title="ESC10: Strong certificate mapping is not fully enforced",
                description=(
                    "StrongCertificateBindingEnforcement is not set to 2 (Full Enforcement). "
                    "Weak mapping allows certificate-based authentication bypass attacks."
                ),
                severity=Severity.HIGH,
                remediation_desc="Set StrongCertificateBindingEnforcement to 2 after testing compatibility.",
                powershell="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc' -Name 'StrongCertificateBindingEnforcement' -Value 2",
                mitre=_MITRE_ADCS,
                nist_800_53=["IA-5"],
                source="WinRM",
            )]
        return []


@check
class ADCS011_ESC11(BaseCheck):
    id = "ADCS-011"
    name = "ESC11 — NTLM Relay to ICPR (RPC)"
    description = "CA allows NTLM authentication for certificate enrollment over RPC"
    category = "AD Certificate Services"
    requires_winrm = True

    def run(self) -> List[Finding]:
        # IF_ENFORCEENCRYPTICERTREQUEST not set = NTLM relay possible over RPC
        if self.context.enrollment_services:
            return [self.finding(
                title=f"ESC11: Verify NTLM relay protection on {len(self.context.enrollment_services)} CAs",
                description=(
                    "ESC11 enables NTLM relay to the CA's RPC-based certificate enrollment interface (ICPR). "
                    "If the CA does not enforce encrypted ICPR requests, attackers can relay NTLM authentication "
                    "to request certificates."
                ),
                severity=Severity.MEDIUM,
                affected_count=len(self.context.enrollment_services),
                remediation_desc="Enable IF_ENFORCEENCRYPTICERTREQUEST on the CA.",
                powershell="certutil -config \"CA_NAME\" -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST",
                mitre=_MITRE_ADCS,
                nist_800_53=["SC-8"],
            )]
        return []


@check
class ADCS012_ESC13(BaseCheck):
    id = "ADCS-012"
    name = "ESC13 — Issuance Policy OID Group Link"
    description = "Templates with issuance policies linked to security groups"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        # ESC13: template has issuance policy that maps to a group via OID link
        # This requires checking msPKI-Certificate-Policy -> OID objects -> msDS-OIDToGroupLink
        # For now, flag templates with schema v2+ that have issuance policies
        v2_templates = [
            t for t in self.context.certificate_templates
            if t.get("schema_version", 0) >= 2
            and t.get("allows_client_auth")
        ]
        if v2_templates and len(v2_templates) > 5:
            return [self.finding(
                title=f"ESC13: {len(v2_templates)} v2+ templates with client auth — check issuance policy OID links",
                description=(
                    "ESC13 exploits issuance policy OIDs linked to security groups via msDS-OIDToGroupLink. "
                    "A certificate with such a policy grants the holder membership in the linked group. "
                    "Audit all OID objects for group links."
                ),
                severity=Severity.MEDIUM,
                affected_count=len(v2_templates),
                remediation_desc="Audit OID objects in CN=OID,CN=Public Key Services for msDS-OIDToGroupLink attributes.",
                mitre=_MITRE_ADCS,
                nist_800_53=["AC-6"],
            )]
        return []


@check
class ADCS013_NoCAS(BaseCheck):
    id = "ADCS-013"
    name = "Certificate Authority Inventory"
    description = "Inventory deployed Certificate Authorities"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        cas = self.context.certificate_authorities
        es = self.context.enrollment_services
        templates = self.context.certificate_templates
        if cas or es or templates:
            return [self.finding(
                title=f"AD CS deployed: {len(cas)} CAs, {len(es)} enrollment services, {len(templates)} templates",
                description="AD Certificate Services infrastructure summary for security review.",
                severity=Severity.INFO,
                remediation_desc="Ensure regular auditing of all certificate templates and CA configurations.",
                nist_800_53=["SC-17"],
                details={
                    "ca_count": len(cas),
                    "enrollment_service_count": len(es),
                    "template_count": len(templates),
                },
            )]
        return []


@check
class ADCS014_TemplateCount(BaseCheck):
    id = "ADCS-014"
    name = "Excessive Certificate Templates"
    description = "Check for large number of certificate templates"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        count = len(self.context.certificate_templates)
        if count > 50:
            return [self.finding(
                title=f"{count} certificate templates found — large attack surface",
                description="Each template is a potential misconfiguration point. Organizations should minimize the number of published templates.",
                severity=Severity.LOW,
                affected_count=count,
                remediation_desc="Review and unpublish unnecessary certificate templates.",
                powershell="Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' -Filter * | Select-Object Name",
                nist_800_53=["CM-6"],
            )]
        return []
