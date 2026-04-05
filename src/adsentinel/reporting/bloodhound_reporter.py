"""BloodHound CE JSON exporter — generates BloodHound-compatible graph data."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from adsentinel.logging_config import get_logger

logger = get_logger(__name__)


def generate_bloodhound_export(scan_result: Any, output_path: str) -> None:
    """Generate BloodHound CE-compatible JSON files.

    Creates three files:
        - {output}_users.json
        - {output}_groups.json
        - {output}_computers.json
    """
    context = scan_result.context
    if not context:
        logger.warning("no_context_for_bloodhound_export")
        return

    base = Path(output_path).with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)

    # Users
    users_data = _export_users(context)
    _write_json(f"{base}_users.json", users_data, "users")

    # Groups
    groups_data = _export_groups(context)
    _write_json(f"{base}_groups.json", groups_data, "groups")

    # Computers
    computers_data = _export_computers(context)
    _write_json(f"{base}_computers.json", computers_data, "computers")

    # Domains
    domain_data = _export_domain(context)
    _write_json(f"{base}_domains.json", domain_data, "domains")

    total = len(users_data["data"]) + len(groups_data["data"]) + len(computers_data["data"])
    logger.info("bloodhound_export_generated", base=str(base), total_objects=total)


def _export_users(context: Any) -> Dict[str, Any]:
    """Export users in BloodHound CE format."""
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    users = []

    for u in context.users:
        last_logon_epoch = int(u.last_logon.timestamp()) if u.last_logon else 0
        pwd_set_epoch = int(u.password_last_set.timestamp()) if u.password_last_set else 0

        user_obj = {
            "ObjectIdentifier": u.sid,
            "Properties": {
                "name": f"{u.sam_account_name}@{context.domain_info.dns_name}".upper(),
                "domain": context.domain_info.dns_name.upper(),
                "domainsid": context.domain_info.domain_sid,
                "distinguishedname": u.dn,
                "samaccountname": u.sam_account_name,
                "displayname": u.display_name,
                "enabled": u.enabled,
                "admincount": u.admin_count == 1,
                "hasspn": len(u.spn_list) > 0,
                "dontreqpreauth": u.dont_require_preauth,
                "passwordnotreqd": u.password_not_required,
                "unconstraineddelegation": u.trusted_for_delegation,
                "trustedtoauth": u.trusted_to_auth_for_delegation,
                "sensitive": u.sensitive_and_not_delegated,
                "pwdneverexpires": u.password_never_expires,
                "lastlogon": last_logon_epoch,
                "lastlogontimestamp": last_logon_epoch,
                "pwdlastset": pwd_set_epoch,
                "serviceprincipalnames": u.spn_list,
                "whencreated": int(u.when_created.timestamp()) if u.when_created else 0,
                "description": u.description,
            },
            "PrimaryGroupSID": f"{context.domain_info.domain_sid}-513",
            "Members": [],
            "AllowedToDelegate": u.allowed_to_delegate_to,
            "SPNTargets": [
                {"ObjectIdentifier": spn, "ObjectType": "Computer"}
                for spn in u.spn_list
            ],
            "HasSIDHistory": [{"ObjectIdentifier": s, "ObjectType": "User"} for s in u.sid_history],
        }
        users.append(user_obj)

    return {
        "data": users,
        "meta": {
            "methods": 0,
            "type": "users",
            "count": len(users),
            "version": 5,
        },
    }


def _export_groups(context: Any) -> Dict[str, Any]:
    """Export groups in BloodHound CE format."""
    groups = []

    for g in context.groups:
        members = []
        for dn in g.member_dns:
            # Try to find the SID
            for u in context.users:
                if u.dn == dn:
                    members.append({"ObjectIdentifier": u.sid, "ObjectType": "User"})
                    break
            else:
                for c in context.computers:
                    if c.dn == dn:
                        members.append({"ObjectIdentifier": c.sid, "ObjectType": "Computer"})
                        break
                else:
                    for g2 in context.groups:
                        if g2.dn == dn:
                            members.append({"ObjectIdentifier": g2.sid, "ObjectType": "Group"})
                            break

        group_obj = {
            "ObjectIdentifier": g.sid,
            "Properties": {
                "name": f"{g.sam_account_name}@{context.domain_info.dns_name}".upper(),
                "domain": context.domain_info.dns_name.upper(),
                "domainsid": context.domain_info.domain_sid,
                "distinguishedname": g.dn,
                "samaccountname": g.sam_account_name,
                "admincount": g.admin_count == 1,
                "description": g.description,
            },
            "Members": members,
        }
        groups.append(group_obj)

    return {
        "data": groups,
        "meta": {
            "methods": 0,
            "type": "groups",
            "count": len(groups),
            "version": 5,
        },
    }


def _export_computers(context: Any) -> Dict[str, Any]:
    """Export computers in BloodHound CE format."""
    computers = []

    for c in context.computers:
        last_logon_epoch = int(c.last_logon.timestamp()) if c.last_logon else 0

        comp_obj = {
            "ObjectIdentifier": c.sid,
            "Properties": {
                "name": f"{c.dns_hostname or c.sam_account_name}".upper(),
                "domain": context.domain_info.dns_name.upper(),
                "domainsid": context.domain_info.domain_sid,
                "distinguishedname": c.dn,
                "samaccountname": c.sam_account_name,
                "enabled": c.enabled,
                "operatingsystem": c.os_version,
                "unconstraineddelegation": c.trusted_for_delegation,
                "trustedtoauth": c.trusted_to_auth_for_delegation,
                "haslaps": c.has_laps,
                "lastlogon": last_logon_epoch,
                "lastlogontimestamp": last_logon_epoch,
                "serviceprincipalnames": c.spn_list,
            },
            "PrimaryGroupSID": f"{context.domain_info.domain_sid}-515",
            "AllowedToDelegate": c.allowed_to_delegate_to,
            "AllowedToAct": [
                {"ObjectIdentifier": s, "ObjectType": "Computer"}
                for s in c.ms_ds_allowed_to_act_on_behalf
            ],
        }
        computers.append(comp_obj)

    return {
        "data": computers,
        "meta": {
            "methods": 0,
            "type": "computers",
            "count": len(computers),
            "version": 5,
        },
    }


def _export_domain(context: Any) -> Dict[str, Any]:
    """Export domain info in BloodHound CE format."""
    di = context.domain_info
    domain_obj = {
        "ObjectIdentifier": di.domain_sid,
        "Properties": {
            "name": di.dns_name.upper(),
            "domain": di.dns_name.upper(),
            "domainsid": di.domain_sid,
            "distinguishedname": di.base_dn,
            "functionallevel": di.domain_functional_level_name,
        },
        "Trusts": [
            {
                "TargetDomainSid": "",
                "TargetDomainName": t.trusted_domain.upper(),
                "TrustDirection": t.direction_name.lower(),
                "TrustType": "Unknown",
                "IsTransitive": t.is_forest_trust,
                "SidFilteringEnabled": t.sid_filtering_enabled,
            }
            for t in context.trusts
        ],
        "Links": [],
        "ChildObjects": [],
    }

    return {
        "data": [domain_obj],
        "meta": {
            "methods": 0,
            "type": "domains",
            "count": 1,
            "version": 5,
        },
    }


def _write_json(path: str, data: Dict[str, Any], label: str) -> None:
    """Write a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("bloodhound_file_written", path=path, type=label, count=data["meta"]["count"])
