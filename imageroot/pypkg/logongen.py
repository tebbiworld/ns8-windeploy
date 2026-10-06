#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Logon rights of the computers in an OU: a GPO whose GptTmpl.inf sets
[Privilege Rights] with SIDs.

A user right is not merged across GPOs: for each right the GPO applied
last replaces the whole list. Therefore the rule writes complete lists,
always keeps the local Administrators group where a lockout is possible,
and the page warns about other GPOs on the same path that set the same
right (conflicts()).

Windows restores the rights of before when the GPO is gone (measured on
Windows 11 25H2), so a rule needs no reset step when it is removed.
"""

import re

RIGHTS = {
    "interactive": "SeInteractiveLogonRight",
    "remote": "SeRemoteInteractiveLogonRight",
    "deny_interactive": "SeDenyInteractiveLogonRight",
}
PRIVILEGES = {v: k for k, v in RIGHTS.items()}

ADMINS = "S-1-5-32-544"
# Well known groups the page offers without a directory search
WELL_KNOWN = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-555": "Remote Desktop Users",
}
# Builtin groups or accounts of the domain (S-1-5-21-a-b-c-RID)
SID_RE = re.compile(r"^S-1-5-(32-5[0-9]{2}|21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10})$")
NAME_RE = re.compile(r"^[^\r\n\x00,;=\[\]]{1,256}$")
# Never denied: the local administrators and the Domain Admins group
DOMAIN_ADMINS_RID = "-512"

FILE_SECURITY = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
EXT_SECURITY = ("{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}")


class LogonError(Exception):
    """Invalid rule; the message starts with the key of the UI translation."""


def check_rights(rights):
    """Normalise {right: [{sid, name}]}: known rights only, valid and
    unique SIDs, Administrators added to the lists that grant a logon,
    never denied. Returns the cleaned dict without empty lists."""
    if not isinstance(rights, dict):
        raise LogonError("invalid_rights")
    out = {}
    for key, entries in rights.items():
        if key not in RIGHTS:
            raise LogonError(f"invalid_right: {key}")
        if not isinstance(entries, list) or len(entries) > 50:
            raise LogonError(f"invalid_right: {key}")
        seen = {}
        for e in entries:
            sid = str(e.get("sid", "")).upper() if isinstance(e, dict) else ""
            name = str(e.get("name", "")) if isinstance(e, dict) else ""
            if not SID_RE.match(sid):
                raise LogonError(f"invalid_sid: {sid}")
            if name and not NAME_RE.match(name):
                raise LogonError(f"invalid_name: {name}")
            seen[sid] = {"sid": sid, "name": name or WELL_KNOWN.get(sid, sid)}
        if not seen:
            continue
        if key == "deny_interactive":
            for sid in seen:
                if sid == ADMINS or (sid.startswith("S-1-5-21-") and sid.endswith(DOMAIN_ADMINS_RID)):
                    raise LogonError(f"deny_admins: {sid}")
        elif ADMINS not in seen:
            # lockout protection: the local administrators keep the right
            seen = {ADMINS: {"sid": ADMINS, "name": WELL_KNOWN[ADMINS]}, **seen}
        out[key] = list(seen.values())
    if not out:
        raise LogonError("right_required")
    return out


def build_template(rights):
    """GptTmpl.inf (UTF-16LE with BOM) or None without rights."""
    if not rights:
        return None
    lines = ["[Unicode]", "Unicode=yes", "[Version]", 'signature="$CHICAGO$"', "Revision=1", "[Privilege Rights]"]
    for key in sorted(rights, key=lambda k: RIGHTS[k]):
        lines.append(f"{RIGHTS[key]} = " + ",".join("*" + e["sid"] for e in rights[key]))
    return b"\xff\xfe" + ("\r\n".join(lines) + "\r\n").encode("utf-16-le")


def build_files(rights):
    """({path: bytes or None}, machine extension names) of a rule GPO."""
    data = build_template(rights)
    ext = "[" + "".join(EXT_SECURITY) + "]" if data is not None else ""
    return {FILE_SECURITY: data}, ext


def parse_privileges(text):
    """{privilege: [SID or name]} from the text of a GptTmpl.inf."""
    out = {}
    section = ""
    for line in (text or "").splitlines():
        line = line.strip().lstrip("﻿")
        if line.startswith("["):
            section = line.lower()
            continue
        if section != "[privilege rights]" or "=" not in line:
            continue
        name, _, value = line.partition("=")
        out[name.strip()] = [v.strip().lstrip("*") for v in value.split(",") if v.strip()]
    return out


def application_order(containers):
    """GPOs in the order Windows applies them to a computer in the first
    container ([MS-GPOL], as Samba's get_gpo_list): containers from the
    domain down to the OU, inside a container the gPLink entries from the
    first to the last, links of an OU that blocks inheritance stop the
    non-enforced links above it, enforced links come after all others.
    The last GPO that sets a right wins.

    containers: child first, [{dn, block, links: [{guid, enforced,
    disabled}]}]. Returns [(guid, dn, enforced)]."""
    gpo_list, forced = [], []
    only_forced = False
    for c in containers:
        for link in reversed(c["links"]):
            if link.get("disabled"):
                continue
            entry = (link["guid"].upper(), c["dn"], bool(link.get("enforced")))
            if link.get("enforced"):
                forced.insert(0, entry)
            elif not only_forced:
                gpo_list.insert(0, entry)
        if c.get("block"):
            only_forced = True
    return gpo_list + forced


def conflicts(containers, gpos, own_guid, rights):
    """Other GPOs on the path that set a right of this rule.

    gpos: {guid: {"name", "template"}} as gpowrite rights_on_path returns
    them. If the rule's GPO is not linked to the first container yet, it
    is counted as appended there (the module appends its links).
    Returns [{right, guid, name, container, enforced, wins}] where wins
    tells that the other GPO is applied after this rule and replaces its
    list."""
    own = (own_guid or "{NEW}").upper()
    containers = [dict(c, links=list(c["links"])) for c in containers]
    if containers and not any(link["guid"].upper() == own for link in containers[0]["links"]):
        containers[0]["links"].append({"guid": own})
    order = application_order(containers)
    position = {guid: i for i, (guid, _, _) in enumerate(order)}
    out = []
    for i, (guid, dn, enforced) in enumerate(order):
        if guid == own:
            continue
        info = gpos.get(guid) or {}
        privileges = parse_privileges(info.get("template"))
        for key in rights:
            if RIGHTS[key] in privileges:
                out.append({"right": key, "guid": guid, "name": info.get("name", guid), "container": dn,
                            "enforced": enforced, "wins": i > position.get(own, -1)})
    return out
