"""Attack path narrative engine — identifies and describes paths to Domain Admin."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


class AttackStep:
    """A single step in an attack path."""

    def __init__(self, technique: str, description: str,
                 from_object: str = "", to_object: str = "",
                 check_id: str = "", severity: str = "HIGH") -> None:
        self.technique = technique
        self.description = description
        self.from_object = from_object
        self.to_object = to_object
        self.check_id = check_id
        self.severity = severity

    def to_dict(self) -> Dict[str, str]:
        return {
            "technique": self.technique,
            "description": self.description,
            "from": self.from_object,
            "to": self.to_object,
            "check_id": self.check_id,
            "severity": self.severity,
        }


class AttackPath:
    """A complete attack path from initial access to objective."""

    def __init__(self, name: str, description: str, risk: str = "CRITICAL") -> None:
        self.name = name
        self.description = description
        self.risk = risk
        self.steps: List[AttackStep] = []

    @property
    def step_count(self) -> int:
        return len(self.steps)

    def add_step(self, step: AttackStep) -> None:
        self.steps.append(step)

    def narrative(self) -> str:
        """Generate a human-readable attack narrative."""
        lines = [f"Attack Path: {self.name}", f"Risk: {self.risk}", f"Steps: {self.step_count}", ""]
        for i, step in enumerate(self.steps, 1):
            arrow = f"{step.from_object} → {step.to_object}" if step.from_object and step.to_object else ""
            lines.append(f"  Step {i}: {step.technique}")
            lines.append(f"    {step.description}")
            if arrow:
                lines.append(f"    {arrow}")
            lines.append("")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "risk": self.risk,
            "steps": [s.to_dict() for s in self.steps],
            "narrative": self.narrative(),
        }


def analyze_attack_paths(context: Any, findings: List[Any]) -> List[AttackPath]:
    """Analyze collected data and findings to identify attack paths to DA."""
    paths: List[AttackPath] = []

    finding_ids = {f.id for f in findings}

    # Path 1: Kerberoasting → Domain Admin
    _check_kerberoast_path(context, finding_ids, paths)

    # Path 2: ASREPRoast → Credential → Lateral Movement
    _check_asrep_path(context, finding_ids, paths)

    # Path 3: Unconstrained Delegation + Coercion → DC TGT
    _check_unconstrained_coerce_path(context, finding_ids, paths)

    # Path 4: ADCS ESC1 → Certificate as DA
    _check_esc1_path(context, finding_ids, paths)

    # Path 5: ADCS ESC8 + Coercion → DC Certificate
    _check_esc8_coerce_path(context, finding_ids, paths)

    # Path 6: RBCD + MAQ → Privilege Escalation
    _check_rbcd_path(context, finding_ids, paths)

    # Path 7: Shadow Credentials → Impersonation
    _check_shadow_cred_path(context, finding_ids, paths)

    # Path 8: AAD Connect → DCSync
    _check_aad_connect_path(context, finding_ids, paths)

    logger.info("attack_paths_analyzed", count=len(paths))
    return paths


def _check_kerberoast_path(context: Any, fids: set, paths: List[AttackPath]) -> None:
    """Kerberoastable admin accounts → offline crack → DA."""
    kerberoastable_admins = [
        u for u in context.users
        if u.enabled and u.spn_list and u.admin_count == 1
        and not u.sam_account_name.endswith("$")
    ]
    if kerberoastable_admins:
        path = AttackPath(
            "Kerberoasting → Domain Admin",
            "Kerberoastable service accounts in privileged groups enable offline password cracking to DA.",
            risk="CRITICAL",
        )
        for u in kerberoastable_admins[:3]:
            path.add_step(AttackStep(
                technique="Kerberoasting (T1558.003)",
                description=f"Request TGS for {u.sam_account_name} ({u.spn_list[0]})",
                from_object="Any Domain User",
                to_object=f"TGS for {u.sam_account_name}",
                check_id="KRB-001",
            ))
        path.add_step(AttackStep(
            technique="Offline Cracking",
            description="Crack the RC4/AES service ticket offline using hashcat/john",
            from_object="TGS Ticket",
            to_object="Plaintext Password",
        ))
        path.add_step(AttackStep(
            technique="Privileged Access",
            description=f"Authenticate as {kerberoastable_admins[0].sam_account_name} (Domain Admin)",
            from_object="Plaintext Password",
            to_object="Domain Admin",
            check_id="PA-006",
            severity="CRITICAL",
        ))
        paths.append(path)


def _check_asrep_path(context: Any, fids: set, paths: List[AttackPath]) -> None:
    """AS-REP roastable accounts → credential → lateral movement."""
    asrep = [u for u in context.users if u.enabled and u.dont_require_preauth]
    if asrep:
        path = AttackPath(
            "AS-REP Roasting → Credential Theft",
            "Accounts without Kerberos pre-auth enable offline hash cracking.",
            risk="HIGH",
        )
        path.add_step(AttackStep(
            technique="AS-REP Roasting (T1558.004)",
            description=f"Request AS-REP for {asrep[0].sam_account_name} without authentication",
            from_object="Unauthenticated",
            to_object=f"AS-REP hash for {asrep[0].sam_account_name}",
            check_id="KRB-002",
        ))
        path.add_step(AttackStep(
            technique="Offline Cracking",
            description="Crack AS-REP hash offline",
            from_object="AS-REP Hash",
            to_object="Plaintext Password",
        ))
        paths.append(path)


def _check_unconstrained_coerce_path(context: Any, fids: set, paths: List[AttackPath]) -> None:
    """Unconstrained delegation + coercion → DC TGT capture."""
    dc_hostnames = {dc.hostname.lower() for dc in context.domain_info.domain_controllers if dc.hostname}
    unconst = [
        c for c in context.computers
        if c.enabled and c.trusted_for_delegation
        and c.dns_hostname and c.dns_hostname.lower() not in dc_hostnames
    ]
    if unconst:
        path = AttackPath(
            "Unconstrained Delegation + Coercion → DC Compromise",
            "Coerce DC authentication to unconstrained delegation server, capture TGT.",
            risk="CRITICAL",
        )
        path.add_step(AttackStep(
            technique="Compromise Unconstrained Server",
            description=f"Gain access to {unconst[0].sam_account_name}",
            from_object="Attacker",
            to_object=unconst[0].sam_account_name,
            check_id="COER-006",
        ))
        path.add_step(AttackStep(
            technique="PrinterBug / PetitPotam Coercion",
            description="Force DC to authenticate to the compromised server",
            from_object=unconst[0].sam_account_name,
            to_object="DC Authentication",
            check_id="COER-001",
        ))
        path.add_step(AttackStep(
            technique="TGT Capture",
            description="Capture DC's TGT from unconstrained delegation cache",
            from_object="DC Authentication",
            to_object="DC TGT (Domain Admin)",
            severity="CRITICAL",
        ))
        paths.append(path)


def _check_esc1_path(context: Any, fids: set, paths: List[AttackPath]) -> None:
    """ESC1 template → request cert as DA → authenticate."""
    vuln_templates = [
        t for t in context.certificate_templates
        if t.get("enrollee_supplies_subject") and t.get("allows_client_auth")
        and not t.get("requires_manager_approval")
    ]
    if vuln_templates:
        path = AttackPath(
            "AD CS ESC1 → Certificate as Domain Admin",
            "Vulnerable certificate template allows requesting a cert with any SAN.",
            risk="CRITICAL",
        )
        path.add_step(AttackStep(
            technique="ESC1 — Enrollee Supplies Subject",
            description=f"Request certificate from '{vuln_templates[0]['name']}' with SAN=Administrator",
            from_object="Any Enrolled User",
            to_object="Certificate with DA SAN",
            check_id="ADCS-001",
        ))
        path.add_step(AttackStep(
            technique="PKINIT Authentication",
            description="Use certificate to authenticate as Administrator via Kerberos PKINIT",
            from_object="Certificate",
            to_object="Domain Admin TGT",
            severity="CRITICAL",
        ))
        paths.append(path)


def _check_esc8_coerce_path(context: Any, fids: set, paths: List[AttackPath]) -> None:
    """ESC8 HTTP enrollment + coercion → DC certificate."""
    http_cas = [es for es in context.enrollment_services if es.get("has_http_enrollment")]
    if http_cas:
        path = AttackPath(
            "Coercion + ESC8 → DC Certificate",
            "Coerce DC to authenticate and relay to CA HTTP endpoint.",
            risk="CRITICAL",
        )
        path.add_step(AttackStep(
            technique="PetitPotam / PrinterBug Coercion",
            description="Coerce DC authentication via NTLM",
            from_object="Attacker",
            to_object="DC NTLM Auth",
            check_id="COER-002",
        ))
        path.add_step(AttackStep(
            technique="NTLM Relay to AD CS HTTP",
            description=f"Relay DC auth to {http_cas[0]['name']} HTTP enrollment",
            from_object="DC NTLM Auth",
            to_object="Certificate as DC",
            check_id="ADCS-008",
        ))
        path.add_step(AttackStep(
            technique="DCSync via Certificate",
            description="Use DC certificate to perform DCSync",
            from_object="DC Certificate",
            to_object="All Domain Hashes",
            severity="CRITICAL",
        ))
        paths.append(path)


def _check_rbcd_path(context: Any, fids: set, paths: List[AttackPath]) -> None:
    """MAQ + RBCD write → S4U2Self/Proxy → target impersonation."""
    maq = context.domain_info.machine_account_quota
    if maq > 0:
        path = AttackPath(
            "RBCD Abuse via Machine Account Quota",
            "Create computer, configure RBCD, impersonate admin to target.",
            risk="HIGH",
        )
        path.add_step(AttackStep(
            technique="Create Machine Account",
            description=f"Create computer account (MAQ={maq})",
            from_object="Any Domain User",
            to_object="Attacker-Owned Computer",
            check_id="ACL-005",
        ))
        path.add_step(AttackStep(
            technique="Configure RBCD",
            description="Write msDS-AllowedToActOnBehalfOfOtherIdentity on target",
            from_object="Attacker Computer",
            to_object="Target Computer",
            check_id="COER-008",
        ))
        path.add_step(AttackStep(
            technique="S4U2Self + S4U2Proxy",
            description="Impersonate admin to target via Kerberos delegation",
            from_object="Attacker Computer",
            to_object="Admin on Target",
        ))
        paths.append(path)


def _check_shadow_cred_path(context: Any, fids: set, paths: List[AttackPath]) -> None:
    """Shadow Credentials → PKINIT → target impersonation."""
    shadow = [u for u in context.users if u.enabled and u.ms_ds_key_credential_link]
    if shadow:
        path = AttackPath(
            "Shadow Credentials → Account Takeover",
            "Write to msDS-KeyCredentialLink enables PKINIT authentication as target.",
            risk="HIGH",
        )
        path.add_step(AttackStep(
            technique="Write msDS-KeyCredentialLink",
            description="Add attacker-controlled key to target's KeyCredentialLink",
            from_object="Attacker (with GenericWrite)",
            to_object=shadow[0].sam_account_name,
            check_id="COER-004",
        ))
        path.add_step(AttackStep(
            technique="PKINIT Authentication",
            description=f"Authenticate as {shadow[0].sam_account_name} using the injected key",
            from_object="Attacker Key",
            to_object=f"TGT for {shadow[0].sam_account_name}",
        ))
        paths.append(path)


def _check_aad_connect_path(context: Any, fids: set, paths: List[AttackPath]) -> None:
    """AAD Connect server → extract creds → DCSync."""
    sync_accounts = [
        u for u in context.users
        if u.enabled and (u.sam_account_name.upper().startswith("MSOL_") or u.sam_account_name.upper().startswith("AAD_"))
    ]
    if sync_accounts:
        path = AttackPath(
            "Azure AD Connect → DCSync",
            "Compromise AAD Connect server to extract sync account credentials.",
            risk="CRITICAL",
        )
        path.add_step(AttackStep(
            technique="Compromise AAD Connect Server",
            description="Gain local admin on the Azure AD Connect server",
            from_object="Attacker",
            to_object="AAD Connect Server",
            check_id="HYB-002",
        ))
        path.add_step(AttackStep(
            technique="Extract Sync Credentials",
            description=f"Extract {sync_accounts[0].sam_account_name} credentials from AAD Connect DB",
            from_object="AAD Connect Server",
            to_object=sync_accounts[0].sam_account_name,
            check_id="HYB-001",
        ))
        path.add_step(AttackStep(
            technique="DCSync",
            description="Use sync account to replicate all domain password hashes",
            from_object=sync_accounts[0].sam_account_name,
            to_object="All Domain Hashes",
            severity="CRITICAL",
        ))
        paths.append(path)


def generate_attack_path_report(paths: List[AttackPath]) -> str:
    """Generate a text report of all attack paths."""
    if not paths:
        return "No critical attack paths identified."

    lines = [
        "=" * 60,
        f"ADSentinel — Attack Path Analysis ({len(paths)} paths)",
        "=" * 60,
        "",
    ]

    for i, path in enumerate(paths, 1):
        lines.append(f"[{i}] {path.name}")
        lines.append(f"    Risk: {path.risk} | Steps: {path.step_count}")
        lines.append(f"    {path.description}")
        lines.append("")
        for j, step in enumerate(path.steps, 1):
            arrow = f"  ({step.from_object} → {step.to_object})" if step.from_object else ""
            ref = f" [{step.check_id}]" if step.check_id else ""
            lines.append(f"    {j}. {step.technique}{ref}")
            lines.append(f"       {step.description}{arrow}")
        lines.append("")
        lines.append("-" * 60)
        lines.append("")

    return "\n".join(lines)
