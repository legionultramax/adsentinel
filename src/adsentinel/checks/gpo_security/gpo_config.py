"""GPO Security checks (GPO-001 to GPO-010)."""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, FrozenSet, List, Optional

from adsentinel.checks.base import BaseCheck, check
from adsentinel.constants import MITRE_GROUP_POLICY_MODIFICATION
from adsentinel.models.compliance import MitreAttack
from adsentinel.models.finding import AffectedObject, Finding
from adsentinel.models.severity import Severity


def _decrypt_cpassword(cpassword: str) -> Optional[str]:
    """Decrypt a GPP cpassword using the AES-256 key Microsoft published (MS14-025).

    The key is public knowledge — Microsoft documented it in MS-GPPREF.
    Returns the plaintext password, or None if decryption fails.
    """
    try:
        from Crypto.Cipher import AES  # pycryptodome

        # Pad the base64 string to a multiple of 4
        pad = len(cpassword) % 4
        if pad:
            cpassword += "=" * (4 - pad)
        encrypted = base64.b64decode(cpassword)

        # 32-byte AES key published by Microsoft in [MS-GPPREF] Appendix A
        _GPP_AES_KEY = bytes([
            0x4E, 0x99, 0x06, 0xE8, 0xFC, 0xB6, 0x6C, 0xC9,
            0xFA, 0xF4, 0x93, 0x10, 0x62, 0x0F, 0xFE, 0xE8,
            0xF4, 0x96, 0xE8, 0x06, 0xCC, 0x05, 0x79, 0x90,
            0x20, 0x9B, 0x09, 0xA4, 0x33, 0xB6, 0x6C, 0x1B,
        ])
        cipher = AES.new(_GPP_AES_KEY, AES.MODE_CBC, iv=b"\x00" * 16)
        decrypted = cipher.decrypt(encrypted)
        # Strip PKCS7 padding
        pad_byte = decrypted[-1]
        if isinstance(pad_byte, int) and 1 <= pad_byte <= 16:
            decrypted = decrypted[:-pad_byte]
        return decrypted.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return None


@check
class GPO001_NoGPOs(BaseCheck):
    id = "GPO-001"
    name = "GPO Count"
    description = "Check if GPOs exist in the domain"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        if not self.context.gpos:
            return [self.finding(
                title="No Group Policy Objects found",
                description="No GPOs were discovered. This may indicate a collection issue or a domain with no policy enforcement.",
                severity=Severity.INFO,
                remediation_desc="Verify GPO collection and ensure baseline security policies are deployed.",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO002_DefaultDomainPolicy(BaseCheck):
    id = "GPO-002"
    name = "Default Domain Policy"
    description = "Check if the Default Domain Policy is properly configured"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        default_dp = None
        for gpo in self.context.gpos:
            name = gpo.get("display_name", "").lower()
            if name == "default domain policy":
                default_dp = gpo
                break

        if default_dp and default_dp.get("is_disabled"):
            return [self.finding(
                title="Default Domain Policy is disabled",
                description="The Default Domain Policy is disabled. This GPO controls critical settings including password policy and account lockout.",
                severity=Severity.CRITICAL,
                remediation_desc="Enable the Default Domain Policy immediately.",
                powershell="(Get-GPO -Name 'Default Domain Policy').GpoStatus = 'AllSettingsEnabled'",
                mitre=[MitreAttack(technique_id=MITRE_GROUP_POLICY_MODIFICATION, technique_name="Group Policy Modification", tactic="Defense Evasion")],
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO003_DefaultDCPolicy(BaseCheck):
    id = "GPO-003"
    name = "Default Domain Controllers Policy"
    description = "Check if the Default Domain Controllers Policy is properly configured"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        default_dc = None
        for gpo in self.context.gpos:
            name = gpo.get("display_name", "").lower()
            if name == "default domain controllers policy":
                default_dc = gpo
                break

        if default_dc and default_dc.get("is_disabled"):
            return [self.finding(
                title="Default Domain Controllers Policy is disabled",
                description="The Default Domain Controllers Policy is disabled. This GPO controls DC-specific security settings.",
                severity=Severity.HIGH,
                remediation_desc="Enable the Default Domain Controllers Policy.",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO004_DisabledGPOs(BaseCheck):
    id = "GPO-004"
    name = "Disabled GPOs"
    description = "Check for GPOs that are fully disabled"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        disabled = [g for g in self.context.gpos if g.get("is_disabled")]
        total = len(self.context.gpos)
        if disabled and total > 0 and len(disabled) > 5:
            return [self.finding(
                title=f"{len(disabled)} of {total} GPOs are fully disabled",
                description="Many disabled GPOs may indicate poor GPO lifecycle management. Disabled GPOs can still have ACLs that could be abused if re-enabled by an attacker.",
                severity=Severity.LOW,
                affected_count=len(disabled),
                remediation_desc="Review and remove unneeded disabled GPOs.",
                powershell="Get-GPO -All | Where-Object {$_.GpoStatus -eq 'AllSettingsDisabled'}",
                nist_800_53=["CM-6"],
                details={"disabled_gpos": [g.get("display_name", "") for g in disabled[:20]]},
            )]
        return []


@check
class GPO005_UnlinkedGPOs(BaseCheck):
    id = "GPO-005"
    name = "Unversioned GPOs"
    description = "Check for GPOs with version 0 (never modified)"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        unversioned = [g for g in self.context.gpos if g.get("version", 0) == 0 and not g.get("is_disabled")]
        if unversioned:
            return [self.finding(
                title=f"{len(unversioned)} active GPOs have never been modified (version 0)",
                description="GPOs with version 0 may be empty or misconfigured. They add processing overhead without providing policy enforcement.",
                severity=Severity.LOW,
                affected_count=len(unversioned),
                remediation_desc="Review version-0 GPOs and remove if not needed.",
                powershell="Get-GPO -All | Where-Object {$_.Computer.DSVersion -eq 0 -and $_.User.DSVersion -eq 0}",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO006_GPOCount(BaseCheck):
    id = "GPO-006"
    name = "Excessive GPO Count"
    description = "Check for excessive number of GPOs that may slow logon"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        total = len(self.context.gpos)
        if total > 100:
            return [self.finding(
                title=f"{total} GPOs detected — may cause slow logon and policy processing",
                description="Large numbers of GPOs increase logon times and make security auditing difficult. Consider consolidating policies.",
                severity=Severity.LOW,
                remediation_desc="Audit and consolidate GPOs to reduce count below 100.",
                nist_800_53=["CM-6"],
                details={"gpo_count": total},
            )]
        return []


@check
class GPO007_PartiallyDisabledGPOs(BaseCheck):
    id = "GPO-007"
    name = "Partially Disabled GPOs"
    description = "Check for GPOs with only user or computer settings disabled"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        partial = [
            g for g in self.context.gpos
            if (g.get("user_disabled") or g.get("computer_disabled"))
            and not g.get("is_disabled")
        ]
        if partial and len(partial) > 10:
            return [self.finding(
                title=f"{len(partial)} GPOs have partially disabled settings",
                description="GPOs with partially disabled sections may indicate incomplete policy configurations or migration remnants.",
                severity=Severity.INFO,
                affected_count=len(partial),
                remediation_desc="Review partially disabled GPOs to ensure the configuration is intentional.",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO008_GPOSysvol(BaseCheck):
    id = "GPO-008"
    name = "GPO SYSVOL Path Validation"
    description = "Check for GPOs without SYSVOL paths"
    category = "GPO Security"

    def run(self) -> List[Finding]:
        no_path = [g for g in self.context.gpos if not g.get("file_sys_path")]
        if no_path:
            return [self.finding(
                title=f"{len(no_path)} GPOs have no SYSVOL file system path",
                description="GPOs without a SYSVOL path cannot apply settings. This may indicate corruption or a replication issue.",
                severity=Severity.MEDIUM,
                affected_count=len(no_path),
                remediation_desc="Run gpotool or dcdiag to verify GPO health and SYSVOL replication.",
                powershell="dcdiag /test:sysvolcheck",
                nist_800_53=["CM-6"],
            )]
        return []


@check
class GPO009_GPPCpassword(BaseCheck):
    id = "GPO-009"
    name = "GPP Passwords in SYSVOL (MS14-025)"
    description = "Scan SYSVOL for Group Policy Preferences XML files containing cpassword attributes"
    category = "GPO Security"
    requires_winrm = True

    # Files GPP can write credentials into
    _GPP_FILE_DESCRIPTIONS: Dict[str, str] = {
        "Groups.xml":         "Local group / user accounts",
        "ScheduledTasks.xml": "Scheduled task run-as credentials",
        "Services.xml":       "Windows service logon accounts",
        "DataSources.xml":    "ODBC data source credentials",
        "Printers.xml":       "Printer connection credentials",
        "Drives.xml":         "Drive map credentials",
    }

    def run(self) -> List[Finding]:
        hits: List[Dict[str, Any]] = self.context.raw_entries.get("gpp_passwords", [])

        if not hits:
            return []

        # Build a lookup of GPO GUID → display name
        gpo_names: Dict[str, str] = {}
        for gpo in self.context.gpos:
            path = gpo.get("file_sys_path", "")
            if path:
                # SYSVOL path contains the GPO GUID in braces
                import re
                m = re.search(r"\{([0-9A-Fa-f-]{36})\}", path)
                if m:
                    gpo_names[m.group(1).upper()] = gpo.get("display_name", "")

        findings = []
        for hit in hits:
            gpo_guid = (hit.get("GPOGuid") or "Unknown").upper()
            gpo_display = gpo_names.get(gpo_guid, gpo_guid)
            file_name = hit.get("FileName", "unknown")
            file_desc = self._GPP_FILE_DESCRIPTIONS.get(file_name, "GPP policy file")
            user_name = hit.get("UserName") or hit.get("ItemName") or "unknown"
            cpassword = hit.get("CPassword", "")
            file_path = hit.get("FilePath", "")

            # Attempt decryption — the AES key is public knowledge (MS-GPPREF)
            plaintext = _decrypt_cpassword(cpassword) if cpassword else None
            decrypted_note = (
                f"Decrypted password: {plaintext}" if plaintext
                else "Install pycryptodome to auto-decrypt: pip install pycryptodome"
            )

            findings.append(self.finding(
                title=f"GPP cpassword found in '{gpo_display}' ({file_name})",
                description=(
                    f"A cpassword attribute was found in {file_path}. "
                    f"This file stores {file_desc} via Group Policy Preferences. "
                    "Microsoft published the AES-256 encryption key in 2012 (MS-GPPREF Appendix A), "
                    "making all cpassword values trivially decryptable by any domain user who can "
                    "read SYSVOL — which is every authenticated account by default.\n\n"
                    f"Affected account / item: {user_name}\n"
                    f"{decrypted_note}"
                ),
                severity=Severity.CRITICAL,
                affected_objects=[AffectedObject(
                    dn=file_path,
                    sam_account_name=user_name,
                    object_type="gpp_credential",
                )],
                affected_count=1,
                remediation_desc=(
                    "1. Remove all GPP settings that store passwords (Groups.xml, ScheduledTasks.xml, etc.). "
                    "2. Change any accounts whose passwords appeared in these files immediately — "
                    "they must be treated as fully compromised. "
                    "3. Install MS14-025 (KB2962486) on all management workstations if not already applied. "
                    "4. Audit SYSVOL for remaining cpassword attributes with: "
                    "findstr /S /I cpassword \\\\domain\\SYSVOL\\domain\\Policies\\**\\*.xml"
                ),
                powershell=(
                    "# Find all remaining GPP cpassword values in SYSVOL:\n"
                    "Get-ChildItem -Path \"\\\\$env:USERDNSDOMAIN\\SYSVOL\" -Recurse "
                    "-Include Groups.xml,ScheduledTasks.xml,Services.xml,DataSources.xml,Printers.xml,Drives.xml "
                    "-ErrorAction SilentlyContinue | "
                    "Select-String -Pattern 'cpassword' | Select-Object Path, LineNumber, Line"
                ),
                manual_steps=[
                    f"Navigate to the GPO '{gpo_display}' in Group Policy Management Console.",
                    f"Locate and remove the {file_desc} preference item that sets a password.",
                    "Reset the password for the account that was stored.",
                    "Verify no other GPOs in the domain contain cpassword attributes.",
                ],
                mitre=[MitreAttack(
                    technique_id="T1552.006",
                    technique_name="Group Policy Preferences",
                    tactic="Credential Access",
                )],
                cis_controls=["5.2", "16.4"],
                nist_800_53=["IA-5", "SC-28"],
                details={
                    "gpo_guid": gpo_guid,
                    "gpo_name": gpo_display,
                    "file": file_path,
                    "user": user_name,
                    "decryptable": plaintext is not None,
                },
                source="WinRM",
            ))

        return findings


@check
class GPO010_RDPLogonRights(BaseCheck):
    id = "GPO-010"
    name = "Overly Broad SeRemoteInteractiveLogonRight"
    description = (
        "Scan SYSVOL GptTmpl.inf files for GPOs granting RDP logon rights "
        "to broad or non-standard groups beyond Administrators and Remote Desktop Users"
    )
    category = "GPO Security"
    requires_winrm = True

    # SIDs that legitimately hold SeRemoteInteractiveLogonRight
    _SAFE_SIDS: FrozenSet[str] = frozenset({
        "S-1-5-32-544",   # BUILTIN\Administrators
        "S-1-5-32-555",   # BUILTIN\Remote Desktop Users
    })

    # SIDs that indicate a dangerously broad grant
    _BROAD_SIDS: Dict[str, str] = {
        "S-1-1-0":     "Everyone",
        "S-1-5-7":     "Anonymous Logon",
        "S-1-5-11":    "Authenticated Users",
        "S-1-5-32-545": "BUILTIN\\Users",
    }

    def run(self) -> List[Finding]:
        hits: List[Dict[str, Any]] = self.context.raw_entries.get("gpo_rdp_rights", [])
        if not hits:
            return []

        # GPO GUID → display name
        gpo_names: Dict[str, str] = {}
        for gpo in self.context.gpos:
            path = gpo.get("file_sys_path", "")
            if path:
                m = re.search(r"\{([0-9A-Fa-f-]{36})\}", path)
                if m:
                    gpo_names[m.group(1).upper()] = gpo.get("display_name", "")

        # Extend safe set with domain-relative privileged groups
        domain_sid = getattr(self.context.domain_info, "domain_sid", "") or ""
        safe_sids = set(self._SAFE_SIDS)
        if domain_sid:
            safe_sids.add(f"{domain_sid}-512")   # Domain Admins
            safe_sids.add(f"{domain_sid}-519")   # Enterprise Admins
            safe_sids.add(f"{domain_sid}-516")   # Domain Controllers group

        findings = []
        for hit in hits:
            gpo_guid = (hit.get("GPOGuid") or "Unknown").upper()
            gpo_name = gpo_names.get(gpo_guid, gpo_guid)
            raw_value = hit.get("RawValue", "")

            # Each entry is either *S-1-x-y or an account name
            entries = [e.strip().lstrip("*") for e in raw_value.split(",") if e.strip()]

            broad = [
                f"{e} ({self._BROAD_SIDS[e]})"
                for e in entries if e in self._BROAD_SIDS
            ]
            non_safe = [
                e for e in entries
                if e not in safe_sids and e not in self._BROAD_SIDS
            ]

            if not broad and not non_safe:
                continue

            if broad:
                severity = Severity.CRITICAL
                title = f"SeRemoteInteractiveLogonRight granted to broad group — '{gpo_name}'"
                description = (
                    f"GPO '{gpo_name}' grants RDP logon rights (SeRemoteInteractiveLogonRight) "
                    f"to: {', '.join(broad)}. Any authenticated user — or unauthenticated "
                    "attacker — can open an RDP session to every computer this GPO applies to. "
                    "If this GPO is linked to the Domain Controllers OU, every DC is directly "
                    "accessible via RDP to the entire user population."
                )
            else:
                severity = Severity.HIGH
                title = f"SeRemoteInteractiveLogonRight grants non-standard access — '{gpo_name}'"
                description = (
                    f"GPO '{gpo_name}' grants RDP logon rights to principals outside the "
                    f"expected safe set (Administrators, Remote Desktop Users): {', '.join(non_safe)}. "
                    "Verify these are intentional and that the GPO scope does not include "
                    "Domain Controllers or other Tier 0 systems."
                )

            findings.append(self.finding(
                title=title,
                description=description,
                severity=severity,
                remediation_desc=(
                    "1. Open Group Policy Management and locate the GPO. "
                    "2. Check which OUs it is linked to — if DCs are in scope, treat this as CRITICAL. "
                    "3. Navigate to Computer Configuration → Policies → Windows Settings → "
                    "Security Settings → Local Policies → User Rights Assignment → "
                    "'Allow log on through Remote Desktop Services'. "
                    "4. Remove all groups except Administrators and Remote Desktop Users. "
                    "5. Use Authentication Policies to further restrict RDP source for Tier 0 accounts."
                ),
                powershell=(
                    f"# Inspect the full GPO report for '{gpo_name}':\n"
                    f"Get-GPOReport -Guid '{{{gpo_guid}}}' -ReportType Html -Path C:\\Temp\\gpo_rdp.html\n"
                    f"# Check current effective right on a DC:\n"
                    "secedit /export /cfg C:\\Temp\\current_rights.inf /areas USER_RIGHTS\n"
                    "Select-String 'SeRemoteInteractiveLogonRight' C:\\Temp\\current_rights.inf"
                ),
                mitre=[MitreAttack(
                    technique_id="T1021.001",
                    technique_name="Remote Desktop Protocol",
                    tactic="Lateral Movement",
                )],
                cis_controls=["4.3", "6.8"],
                nist_800_53=["AC-17", "AC-6", "CM-6"],
                details={
                    "gpo_guid": gpo_guid,
                    "gpo_name": gpo_name,
                    "raw_value": raw_value,
                    "broad_grants": broad,
                    "non_standard_grants": non_safe,
                },
                source="WinRM",
            ))

        return findings


@check
class GPO011_OverlyBroadLocalAdminRights(BaseCheck):
    """Detect GPOs that grant local Administrators membership to broad or non-standard principals.

    Two GPO mechanisms write to the local Administrators group:
      - Restricted Groups (GptTmpl.inf, [Group Membership] section)
      - Group Policy Preferences — Groups.xml with action=ADD or UPDATE

    Either can silently make Domain Users — or Everyone — a local administrator
    on every machine in the GPO's scope.  If the scope includes Domain Controllers,
    the impact is domain compromise.
    """

    id = "GPO-011"
    name = "Overly Broad Local Administrators via GPO"
    description = (
        "Scan SYSVOL for Restricted Groups and GPP Groups.xml policies that grant "
        "local Administrators membership to broad or non-standard principals"
    )
    category = "GPO Security"
    requires_winrm = True

    # Well-known SIDs that are safe to appear in local Administrators
    _SAFE_SID_SUFFIXES: FrozenSet[str] = frozenset({
        "S-1-5-32-544",   # BUILTIN\Administrators (self-reference)
    })
    _SAFE_RID_SUFFIXES: FrozenSet[str] = frozenset({
        "-512",    # Domain Admins
        "-519",    # Enterprise Admins
        "-500",    # Built-in Administrator (any domain)
    })
    _BROAD_SIDS: Dict[str, str] = {
        "S-1-1-0":      "Everyone",
        "S-1-5-7":      "Anonymous Logon",
        "S-1-5-11":     "Authenticated Users",
        "S-1-5-32-545": "BUILTIN\\Users",
    }
    _BROAD_NAMES: FrozenSet[str] = frozenset({
        "everyone", "authenticated users", "domain users",
        "users", "anonymous logon", "network",
    })

    def _build_gpo_names(self) -> Dict[str, str]:
        names: Dict[str, str] = {}
        for gpo in self.context.gpos:
            path = gpo.get("file_sys_path", "")
            if path:
                m = re.search(r"\{([0-9A-Fa-f-]{36})\}", path)
                if m:
                    names[m.group(1).upper()] = gpo.get("display_name", "")
        return names

    def _build_safe_sids(self) -> set:
        safe = set(self._SAFE_SID_SUFFIXES)
        domain_sid = getattr(self.context.domain_info, "domain_sid", "") or ""
        if domain_sid:
            for suffix in self._SAFE_RID_SUFFIXES:
                safe.add(f"{domain_sid}{suffix}")
        return safe

    def _classify_sid(self, sid: str, name: str, safe_sids: set, domain_sid: str) -> str:
        """Return 'safe', 'broad', or 'review'."""
        if sid.upper() in {s.upper() for s in safe_sids}:
            return "safe"
        if sid in self._BROAD_SIDS:
            return "broad"
        if domain_sid and sid == f"{domain_sid}-513":
            return "broad"
        if name.lower().strip() in self._BROAD_NAMES:
            return "broad"
        if sid.upper().startswith("S-") or name:
            return "review"
        return "safe"

    def _parse_restricted_groups(self, raw: str) -> List[Dict[str, str]]:
        members = []
        for part in raw.split(","):
            sid = part.strip().lstrip("*")
            if sid:
                members.append({"sid": sid, "name": self._BROAD_SIDS.get(sid, ""), "action": "SET"})
        return members

    def _parse_gpp_groups(self, raw: str) -> List[Dict[str, str]]:
        members = []
        for part in raw.split(";"):
            if not part.strip():
                continue
            fields = part.split("|")
            members.append({
                "sid":    fields[1].strip() if len(fields) > 1 else "",
                "name":   fields[0].strip() if fields else "",
                "action": fields[2].strip() if len(fields) > 2 else "ADD",
            })
        return members

    def run(self) -> List[Finding]:
        hits: List[Dict[str, Any]] = self.context.raw_entries.get("gpo_local_admin", [])
        if not hits:
            return []

        gpo_names = self._build_gpo_names()
        safe_sids = self._build_safe_sids()
        domain_sid = getattr(self.context.domain_info, "domain_sid", "") or ""
        findings_out: List[Finding] = []

        for hit in hits:
            gpo_guid = (hit.get("GPOGuid") or "Unknown").upper()
            gpo_name = gpo_names.get(gpo_guid, gpo_guid)
            source = hit.get("Source", "")
            raw = hit.get("RawMembers", "")

            members = (
                self._parse_restricted_groups(raw)
                if source == "RestrictedGroups"
                else self._parse_gpp_groups(raw)
            )

            broad: List[str] = []
            review: List[str] = []

            for m in members:
                cls = self._classify_sid(m["sid"], m["name"], safe_sids, domain_sid)
                if cls == "safe":
                    continue
                if m["sid"] in self._BROAD_SIDS:
                    label = f"{m['sid']} ({self._BROAD_SIDS[m['sid']]})"
                elif domain_sid and m["sid"] == f"{domain_sid}-513":
                    label = f"{m['sid']} (Domain Users)"
                else:
                    label = m["name"] or m["sid"] or "(unknown)"

                (broad if cls == "broad" else review).append(label)

            if not broad and not review:
                continue

            source_label = (
                "Restricted Groups (GptTmpl.inf)"
                if source == "RestrictedGroups"
                else "Group Policy Preferences (Groups.xml)"
            )

            if broad:
                severity = Severity.CRITICAL
                title = f"Local Administrators granted to broad group via GPO — '{gpo_name}'"
                description = (
                    f"GPO '{gpo_name}' uses {source_label} to add the following "
                    f"broad principal(s) to the local Administrators group:\n\n"
                    f"  {', '.join(broad)}\n\n"
                    "Every computer this GPO applies to grants full local administrator "
                    "access to these principals. If the GPO scope includes Domain Controllers, "
                    "any domain account can interactively log on and dump credentials from LSASS "
                    "with no further escalation required.\n\n"
                    "This is the most common misconfiguration that collapses tier separation — "
                    "a single compromised domain user account immediately becomes local admin "
                    "on every machine in scope."
                )
            else:
                severity = Severity.HIGH
                title = f"Local Administrators granted to non-standard principals via GPO — '{gpo_name}'"
                description = (
                    f"GPO '{gpo_name}' uses {source_label} to add non-standard "
                    f"principal(s) to the local Administrators group:\n\n"
                    f"  {', '.join(review)}\n\n"
                    "Verify these are intentionally authorized and that the GPO scope "
                    "does not include Domain Controllers or Tier 0 systems. "
                    "Unrecognized groups in local Administrators are a common lateral "
                    "movement persistence mechanism left by attackers."
                )

            findings_out.append(self.finding(
                title=title,
                description=description,
                severity=severity,
                remediation_desc=(
                    "1. Open Group Policy Management and locate the GPO. "
                    "2. Check which OUs it is linked to — if DCs are in scope, treat this as P0. "
                    "3. For Restricted Groups: navigate to Computer Configuration → Policies → "
                    "Windows Settings → Security Settings → Restricted Groups. "
                    "Remove all non-administrative principals from the Administrators entry. "
                    "4. For GPP Groups.xml: navigate to Computer Configuration → Preferences → "
                    "Control Panel Settings → Local Users and Groups. "
                    "Change the Member action to REMOVE for broad principals, or delete the item. "
                    "5. Run 'gpupdate /force' on affected systems and verify: "
                    "net localgroup Administrators"
                ),
                powershell=(
                    f"# Inspect GPO '{gpo_name}':\n"
                    f"Get-GPOReport -Guid '{{{gpo_guid}}}' -ReportType Html "
                    f"-Path C:\\Temp\\gpo_localadmin_{gpo_guid[:8]}.html\n\n"
                    "# Verify current local Admins on this machine:\n"
                    "net localgroup Administrators\n\n"
                    "# Find OUs this GPO is linked to:\n"
                    "Get-ADOrganizationalUnit -Filter * | ForEach-Object {{\n"
                    "    $links = (Get-GPInheritance -Target $_.DistinguishedName).GpoLinks\n"
                    f"    if ($links.DisplayName -contains '{gpo_name}') {{ $_.DistinguishedName }}\n"
                    "}}"
                ),
                manual_steps=[
                    f"In GPMC, right-click '{gpo_name}' → Edit.",
                    "For Restricted Groups: Computer Configuration → Policies → Windows Settings "
                    "→ Security Settings → Restricted Groups — remove the broad member.",
                    "For GPP: Computer Configuration → Preferences → Control Panel Settings "
                    "→ Local Users and Groups — set action to REMOVE or delete the entry.",
                    "Check the GPO's Scope tab — flag any DC OU links immediately.",
                    "Run gpupdate /force on affected machines and verify with: "
                    "net localgroup Administrators",
                ],
                mitre=[
                    MitreAttack(
                        technique_id="T1098",
                        technique_name="Account Manipulation",
                        tactic="Persistence",
                    ),
                    MitreAttack(
                        technique_id="T1484.001",
                        technique_name="Group Policy Modification",
                        tactic="Defense Evasion",
                    ),
                ],
                cis_controls=["4.3", "5.4"],
                nist_800_53=["AC-6", "CM-6", "CM-7"],
                details={
                    "gpo_guid": gpo_guid,
                    "gpo_name": gpo_name,
                    "source": source,
                    "broad_grants": broad,
                    "review_grants": review,
                },
                source="WinRM",
            ))

        return findings_out
