"""AD Certificate Services checks — ESC1 through ESC13 + supplemental (ADCS-001 to ADCS-020)."""

from __future__ import annotations

from typing import List

from adsentinel.checks.base import BaseCheck, check
from adsentinel.collectors.acl_collector import (
    GENERIC_ALL,
    GENERIC_WRITE,
    WRITE_DACL,
    WRITE_OWNER,
    build_safe_sids,
)
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
    description = "Non-admin SIDs with write/full-control on certificate template objects"
    category = "AD Certificate Services"

    _DANGEROUS = WRITE_DACL | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE

    def run(self) -> List[Finding]:
        safe_sids = build_safe_sids(self.context.domain_info.domain_sid or "")
        vuln: list = []

        for t in self.context.certificate_templates:
            dn = t.get("dn", "")
            acl_data = self.context.acls.get(f"pki_template:{dn}", {})
            if acl_data.get("parse_error") and not acl_data.get("aces"):
                continue  # ACL not available for this template

            bad_sids = [
                ace["sid"]
                for ace in acl_data.get("aces", [])
                if ace.get("allowed")
                and ace.get("sid") not in safe_sids
                and (ace.get("mask", 0) & self._DANGEROUS)
            ]
            if bad_sids:
                vuln.append({"name": t.get("name", dn), "dn": dn, "sids": bad_sids})

        if not vuln:
            return []

        return [self.finding(
            title=f"ESC4: {len(vuln)} template{'s have' if len(vuln) != 1 else ' has'} dangerous write permissions",
            description=(
                f"{len(vuln)} certificate template{'s' if len(vuln) != 1 else ''} "
                "grant non-administrative principals WriteDACL, WriteOwner, GenericAll, or GenericWrite. "
                "An attacker with these rights can reconfigure the template (enable enrollee-supplied SAN, "
                "add client auth EKU, remove manager approval) to create an ESC1 condition, then "
                "request a certificate as any domain user including Domain Admin."
            ),
            severity=Severity.CRITICAL,
            affected_objects=[
                AffectedObject(dn=v["dn"], sam_account_name=v["name"], object_type="certificate_template")
                for v in vuln
            ],
            affected_count=len(vuln),
            remediation_desc=(
                "Remove write/full-control ACEs for non-admin accounts on these templates. "
                "Only Domain Admins, Enterprise Admins, and designated CA Admins should have write access."
            ),
            powershell=(
                "# Inspect template ACLs:\n"
                "foreach ($t in (Get-ADObject -SearchBase "
                "'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' "
                "-Filter * -Properties nTSecurityDescriptor)) {\n"
                "    (Get-ACL \"AD:\\$($t.DistinguishedName)\").Access | "
                "Where-Object {$_.ActiveDirectoryRights -match 'Write|FullControl'} | "
                "Select-Object IdentityReference,ActiveDirectoryRights\n}"
            ),
            mitre=_MITRE_ADCS,
            nist_800_53=["AC-6"],
            details={"vulnerable_templates": [{"name": v["name"], "bad_sids": v["sids"]} for v in vuln]},
        )]


@check
class ADCS005_ESC5(BaseCheck):
    id = "ADCS-005"
    name = "ESC5 — PKI Object ACL Abuse"
    description = "Non-admin write rights on enrollment service and CA objects in CN=Public Key Services"
    category = "AD Certificate Services"

    _DANGEROUS = WRITE_DACL | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE

    def run(self) -> List[Finding]:
        safe_sids = build_safe_sids(self.context.domain_info.domain_sid or "")
        vuln: list = []

        # Check enrollment service and CA objects — these are the ESC5 targets
        pki_objects = (
            [("pki_enrollment", es) for es in self.context.enrollment_services]
            + [("pki_ca", ca) for ca in self.context.certificate_authorities]
        )
        for prefix, obj in pki_objects:
            dn = obj.get("dn", "")
            acl_data = self.context.acls.get(f"{prefix}:{dn}", {})
            if acl_data.get("parse_error") and not acl_data.get("aces"):
                continue

            bad_sids = [
                ace["sid"]
                for ace in acl_data.get("aces", [])
                if ace.get("allowed")
                and ace.get("sid") not in safe_sids
                and (ace.get("mask", 0) & self._DANGEROUS)
            ]
            if bad_sids:
                vuln.append({
                    "name": obj.get("name", dn),
                    "dn": dn,
                    "type": "enrollment_service" if prefix == "pki_enrollment" else "ca",
                    "sids": bad_sids,
                })

        if not vuln:
            return []

        return [self.finding(
            title=f"ESC5: {len(vuln)} PKI object{'s have' if len(vuln) != 1 else ' has'} dangerous write permissions",
            description=(
                f"{len(vuln)} PKI object{'s' if len(vuln) != 1 else ''} "
                "(enrollment services or CA objects) grant non-administrative principals "
                "WriteDACL, WriteOwner, GenericAll, or GenericWrite. "
                "Control over a CA object lets an attacker modify its templates list, enable "
                "EDITF_ATTRIBUTESUBJECTALTNAME2, or configure new enrollment paths — any of which "
                "leads to arbitrary certificate issuance and domain compromise."
            ),
            severity=Severity.CRITICAL,
            affected_objects=[
                AffectedObject(dn=v["dn"], sam_account_name=v["name"], object_type=v["type"])
                for v in vuln
            ],
            affected_count=len(vuln),
            remediation_desc=(
                "Remove write/full-control ACEs on enrollment service and CA objects for non-admin accounts. "
                "Only Enterprise Admins and designated CA Admins should have write access to PKI container objects."
            ),
            powershell=(
                "# Inspect enrollment service ACLs:\n"
                "Get-ADObject -SearchBase "
                "'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' "
                "-Filter * | ForEach-Object { "
                "(Get-ACL \"AD:\\$($_.DistinguishedName)\").Access | "
                "Where-Object {$_.ActiveDirectoryRights -match 'Write|FullControl'} }"
            ),
            mitre=_MITRE_ADCS,
            nist_800_53=["AC-6"],
            details={"vulnerable_pki_objects": [{"name": v["name"], "type": v["type"], "bad_sids": v["sids"]} for v in vuln]},
        )]


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
    description = "ManageCA / ManageCertificates rights grant CA-level control; cannot be read via LDAP"
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        if not self.context.enrollment_services:
            return []

        # ESC7 exploits ManageCA and ManageCertificates CA roles:
        #   ManageCA     → can enable EDITF_ATTRIBUTESUBJECTALTNAME2 (= ESC6) on the CA
        #   ManageCerts  → can approve any pending certificate request
        # These roles are stored in the CA's own database (certutil -getacl), NOT in LDAP.
        # nTSecurityDescriptor on the enrollment service object controls object-level AD rights
        # (covered by ADCS-005), not CA operational roles.
        # This check fires as a MEDIUM advisory whenever CAs are deployed — operators must
        # verify CA roles manually. See ADCS-005 for LDAP-readable write rights.
        es_names = [es.get("name", es.get("dn", "?")) for es in self.context.enrollment_services]
        return [self.finding(
            title=f"ESC7: CA role audit required on {len(self.context.enrollment_services)} enrollment service{'s' if len(self.context.enrollment_services) != 1 else ''}",
            description=(
                "ManageCA and ManageCertificates are CA-internal roles that cannot be read via LDAP. "
                "ManageCA lets a holder enable EDITF_ATTRIBUTESUBJECTALTNAME2 (turning all templates "
                "into ESC6 targets). ManageCertificates lets a holder approve any pending request, "
                "bypassing manager-approval controls. These roles must be audited with certutil or "
                "the CA MMC snap-in — they are not reflected in the enrollment service's AD DACL. "
                "Ensure only designated CA administrators hold these roles."
            ),
            severity=Severity.MEDIUM,
            affected_objects=[
                AffectedObject(dn=es.get("dn", ""), sam_account_name=es.get("name", ""), object_type="enrollment_service")
                for es in self.context.enrollment_services
            ],
            affected_count=len(self.context.enrollment_services),
            remediation_desc=(
                "On each CA: run 'certutil -config <CA> -getacl' and verify only named CA admin "
                "accounts hold ManageCA and ManageCertificates roles. Remove any unexpected accounts."
            ),
            powershell=(
                "# List CA roles (run on each CA host):\n"
                "certutil -config \"<CA_HOST>\\<CA_NAME>\" -getacl\n\n"
                "# Or via MMC:\n"
                "# certsrv.msc → right-click CA → Properties → Security tab"
            ),
            mitre=_MITRE_ADCS,
            nist_800_53=["AC-6"],
            details={"enrollment_services": es_names},
        )]


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
    description = "CA RPC enrollment interface may allow NTLM relay if IF_ENFORCEENCRYPTICERTREQUEST is not set"
    category = "AD Certificate Services"
    # IF_ENFORCEENCRYPTICERTREQUEST lives in CA registry (CertSvc\Configuration\<CAName>\InterfaceFlags)
    # — not in LDAP. WinRM collection would need the CA name at collection time, which is unavailable.
    # This check fires as a MEDIUM advisory whenever CAs are deployed.

    def run(self) -> List[Finding]:
        if not self.context.enrollment_services:
            return []

        es_names = [es.get("name", es.get("dn", "?")) for es in self.context.enrollment_services]
        return [self.finding(
            title=f"ESC11: Verify IF_ENFORCEENCRYPTICERTREQUEST on {len(self.context.enrollment_services)} CA{'s' if len(self.context.enrollment_services) != 1 else ''}",
            description=(
                "ESC11 exploits the CA's RPC-based enrollment interface (ICPR). "
                "If IF_ENFORCEENCRYPTICERTREQUEST is not set in the CA's InterfaceFlags, "
                "the ICPR endpoint accepts NTLM-authenticated enrollment requests without "
                "message encryption. An attacker can relay NTLM authentication (e.g., via "
                "PetitPotam or PrinterBug coercion) to the ICPR endpoint and obtain a "
                "certificate as the coerced machine account. "
                "The InterfaceFlags value is stored in the CA registry — it cannot be "
                "read remotely via LDAP. Verify it manually with certutil on each CA host."
            ),
            severity=Severity.MEDIUM,
            affected_objects=[
                AffectedObject(dn=es.get("dn", ""), sam_account_name=es.get("name", ""), object_type="enrollment_service")
                for es in self.context.enrollment_services
            ],
            affected_count=len(self.context.enrollment_services),
            remediation_desc=(
                "On each CA host, enable encrypted ICPR requests:\n"
                "  certutil -config '<host>\\<CA>' -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST\n"
                "  net stop certsvc && net start certsvc\n"
                "Also consider disabling NTLM on DCs to remove the relay precondition."
            ),
            powershell=(
                "# Check current InterfaceFlags (run on CA host):\n"
                "certutil -config \"<CA_HOST>\\<CA_NAME>\" -getreg CA\\InterfaceFlags\n\n"
                "# Enable enforcement:\n"
                "certutil -config \"<CA_HOST>\\<CA_NAME>\" -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST\n"
                "Restart-Service CertSvc"
            ),
            mitre=_MITRE_ADCS,
            nist_800_53=["SC-8"],
            details={"enrollment_services": es_names},
        )]


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
        if count > 20:
            return [self.finding(
                title=f"{count} certificate templates published — large AD CS attack surface",
                description=(
                    f"{count} certificate templates are published. Windows ships with ~32 built-in templates; "
                    "anything above that represents custom additions. Every published template is a potential "
                    "ESC1–ESC11 misconfiguration surface. Organisations should publish only templates in active use."
                ),
                severity=Severity.LOW,
                affected_count=count,
                remediation_desc="Review and unpublish unnecessary certificate templates.",
                powershell="Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' -Filter * | Select-Object Name",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class ADCS015_ESC12(BaseCheck):
    id = "ADCS-015"
    name = "ESC12 — Private Key Archival Enabled"
    description = (
        "Detect CA key archival configuration via two LDAP signals: "
        "(1) msPKI-RA-Certificate on enrollment service objects — the CA holds KRA certificates "
        "and can decrypt archived private keys; "
        "(2) CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL in msPKI-Private-Key-Flag on templates — "
        "enrollment for these templates sends the private key to the CA for escrow."
    )
    category = "AD Certificate Services"

    def run(self) -> List[Finding]:
        # Signal 1: enrollment services with KRA certificates configured
        kra_cas = [
            es for es in self.context.enrollment_services
            if es.get("has_kra_certificates")
        ]

        # Signal 2: templates requiring private key archival
        archival_templates = [
            t for t in self.context.certificate_templates
            if t.get("requires_key_archival")
        ]

        if not kra_cas and not archival_templates:
            return []

        findings = []

        if kra_cas:
            ca_lines = "\n".join(
                f"  • {es.get('name', es.get('dn', '?'))} "
                f"({es.get('kra_cert_count', '?')} KRA certificate(s))"
                for es in kra_cas
            )
            findings.append(self.finding(
                title=(
                    f"ESC12: {len(kra_cas)} CA(s) have Key Recovery Agent (KRA) certificates "
                    "configured — private key archival is active"
                ),
                description=(
                    "The following CAs have msPKI-RA-Certificate populated, meaning they hold "
                    "Key Recovery Agent (KRA) certificates and are configured to archive client "
                    "private keys. Any CA admin or KRA certificate holder can use certutil -recoverkey "
                    "to decrypt and export any archived private key issued by these CAs.\n\n"
                    "If any archived certificate was used for client authentication, S/MIME, or "
                    "code signing, the corresponding private key is now recoverable by the CA admin "
                    "— enabling impersonation of any user who enrolled under an archival-required template.\n\n"
                    "Affected CAs:\n" + ca_lines
                ),
                severity=Severity.HIGH,
                affected_objects=[
                    AffectedObject(
                        dn=es["dn"],
                        sam_account_name=es.get("name", ""),
                        object_type="enrollment_service",
                        details={"kra_cert_count": es.get("kra_cert_count", 0)},
                    )
                    for es in kra_cas
                ],
                affected_count=len(kra_cas),
                remediation_desc=(
                    "1. Determine if key archival is intentionally configured — it is required for "
                    "some smart card and S/MIME deployments. "
                    "2. If unintentional, remove the KRA certificates from the CA: "
                    "certutil -config <CA> -setcacertificate <cert_index> -delete. "
                    "3. Restrict KRA role to dedicated, highly-privileged accounts — treat KRA cert "
                    "holders as Tier 0 since they can recover authentication credentials. "
                    "4. Audit who holds the KRA certificate's private key."
                ),
                powershell=(
                    "# Check KRA certificates on each CA:\n"
                    "$configDN = (Get-ADRootDSE).configurationNamingContext\n"
                    "Get-ADObject -SearchBase "
                    "\"CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN\" "
                    "-Filter * -Properties 'msPKI-RA-Certificate' | "
                    "Select-Object Name, @{N='KRACerts';E={$_.'msPKI-RA-Certificate'.Count}}\n\n"
                    "# List archived keys on a CA (run on CA host):\n"
                    "certutil -config \"<CA_HOST>\\<CA_NAME>\" -getkey"
                ),
                mitre=_MITRE_ADCS,
                nist_800_53=["SC-17", "IA-5"],
                details={
                    "kra_cas": [
                        {"name": es.get("name"), "dn": es["dn"], "kra_cert_count": es.get("kra_cert_count", 0)}
                        for es in kra_cas
                    ],
                },
            ))

        if archival_templates:
            auth_archival = [
                t for t in archival_templates
                if t.get("allows_client_auth")
            ]
            severity = Severity.CRITICAL if auth_archival else Severity.HIGH
            template_lines = "\n".join(
                f"  • {t.get('name', t.get('dn', '?'))}"
                + (" [client auth EKU]" if t.get("allows_client_auth") else "")
                for t in archival_templates[:20]
            )
            findings.append(self.finding(
                title=(
                    f"ESC12: {len(archival_templates)} template(s) require private key archival"
                    + (f" — {len(auth_archival)} include client auth EKU" if auth_archival else "")
                ),
                description=(
                    "These certificate templates have CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL set "
                    "in msPKI-Private-Key-Flag. When a user enrolls for one of these templates, "
                    "their private key is encrypted with the CA's KRA public key and stored in "
                    "the CA database. The CA admin (or any KRA certificate holder) can later "
                    "recover the private key using certutil -recoverkey.\n\n"
                    + (
                        f"{len(auth_archival)} of these templates also have a client authentication "
                        "EKU — meaning the archived keys can be used to impersonate the certificate "
                        "holder for domain authentication (PKINIT, Schannel). A CA admin who "
                        "recovers an archived authentication cert can authenticate as that user "
                        "without needing their password.\n\n"
                        if auth_archival else ""
                    ) +
                    "Affected templates:\n" + template_lines +
                    ("\n  (and more...)" if len(archival_templates) > 20 else "")
                ),
                severity=severity,
                affected_objects=[
                    AffectedObject(
                        dn=t["dn"],
                        sam_account_name=t.get("name", ""),
                        object_type="certificate_template",
                        details={
                            "allows_client_auth": t.get("allows_client_auth", False),
                            "private_key_flag": hex(t.get("private_key_flag", 0)),
                        },
                    )
                    for t in archival_templates[:50]
                ],
                affected_count=len(archival_templates),
                remediation_desc=(
                    "1. Evaluate whether key archival is required for each template's use case. "
                    "2. If not required, remove CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL from "
                    "msPKI-Private-Key-Flag on the template. "
                    "3. For authentication templates especially, disable key archival — "
                    "private keys used for PKINIT should never leave the client. "
                    "4. If archival must remain (e.g., for S/MIME or encryption), apply strict "
                    "access controls on the CA database and KRA certificate."
                ),
                powershell=(
                    "# Find templates with key archival required:\n"
                    "$configDN = (Get-ADRootDSE).configurationNamingContext\n"
                    "Get-ADObject -SearchBase "
                    "\"CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN\" "
                    "-Filter * -Properties 'msPKI-Private-Key-Flag' | "
                    "Where-Object { $_.'msPKI-Private-Key-Flag' -band 0x10 } | "
                    "Select-Object Name, 'msPKI-Private-Key-Flag'\n\n"
                    "# Disable key archival on a template (hex 0x10 = 16):\n"
                    "$t = Get-ADObject -Identity '<template DN>' -Properties 'msPKI-Private-Key-Flag'\n"
                    "Set-ADObject $t -Replace @{'msPKI-Private-Key-Flag' = "
                    "($t.'msPKI-Private-Key-Flag' -band (-bnot 0x10))}"
                ),
                mitre=_MITRE_ADCS,
                nist_800_53=["SC-17", "IA-5"],
                details={
                    "archival_template_count": len(archival_templates),
                    "auth_archival_count": len(auth_archival),
                    "templates": [
                        {"name": t.get("name"), "allows_client_auth": t.get("allows_client_auth", False)}
                        for t in archival_templates
                    ],
                },
            ))

        return findings
