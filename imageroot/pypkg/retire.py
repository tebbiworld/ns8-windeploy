#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Retire a foreign GPO: what the GPO is changed to for the waiting
period, without touching AD.

The Preferences a computer keeps when the GPO is gone are taken back by
the GPO itself while it still applies (pypkg/gpoinventory.py decides
which ones):

  scheduled tasks, drive maps, shortcuts,   action "D": the computers
  environment variables                     delete the item
  local groups                              the added members get the
                                            action "REMOVE", the group
                                            "U"; "delete all members"
                                            is switched off
  registry                                  action "D" for the values
                                            the admin confirmed; the
                                            value of before cannot be
                                            restored
  everything else                           left as it is

The rest of the GPO keeps applying until it is deleted: what Windows
removes by itself goes with the GPO.
"""

import datetime
import re
import xml.etree.ElementTree as ET

import gpoinventory

# image attribute of an item: the editor's icon for its action
IMAGE = {"C": "0", "R": "1", "U": "2", "D": "3"}
PREFERENCES_RE = re.compile(r"^(machine|user)/preferences/[^/]+/[^/]+\.xml$", re.I)


class RetireError(ValueError):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _stamp(now):
    # the format the Group Policy editor writes into "changed"
    return now.strftime("%Y-%m-%d %H:%M:%S")


def rewrite_preferences(path, data, confirmed=(), now=None):
    """(new content or None when nothing changes, [changes]) of one
    Preferences file. confirmed: refs ("<path>|<uid>") of the registry
    items the admin agreed to delete."""
    folder = path.split("/")[-2].lower()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as ex:
        raise RetireError("preferences_unreadable", f"{path}: {ex}") from None
    changes = []
    for ref, el in gpoinventory.gpp_items(root):
        effect = gpoinventory.gpp_effect(folder, el)
        props = el.find("Properties")
        if props is None:
            continue
        name = f"{root.tag}: {gpoinventory._gpp_name(el)}"
        full_ref = f"{path}|{ref}"
        if effect == "retire_delete" or (effect == "retire_confirm" and full_ref in confirmed):
            props.set("action", "D")
            change = "delete"
        elif effect == "retire_members":
            removed = []
            for m in props.iter("Member"):
                if (m.get("action") or "ADD").upper() == "ADD":
                    m.set("action", "REMOVE")
                    removed.append(m.get("name") or m.get("sid") or "?")
            # replace would delete and create the group again
            props.set("action", "U")
            for attr in ("deleteAllUsers", "deleteAllGroups", "removeAccounts"):
                if props.get(attr) == "1":
                    props.set(attr, "0")
            change = "remove_members: " + ", ".join(removed)
        else:
            continue
        if el.get("changed") is not None:
            el.set("changed", _stamp(now))
        if el.get("image") is not None:
            # the icon of the editor follows the action
            el.set("image", IMAGE[props.get("action")])
        changes.append({"ref": full_ref, "name": gpoinventory._text(name), "change": gpoinventory._text(change)})
    if not changes:
        return None, []
    body = ET.tostring(root, encoding="unicode")
    return ('<?xml version="1.0" encoding="utf-8"?>\r\n' + body).encode("utf-8"), changes


def plan(gpo, confirmed=()):
    """The files to write for the waiting period and the changes, from
    the raw GPO of gpowrite's op "inventory": ({path: bytes}, [changes]).
    Every confirmed registry ref must belong to a registry item of the
    GPO."""
    import base64
    files, changes = {}, []
    known = set()
    for path, content in sorted(gpo.get("contents", {}).items()):
        if not PREFERENCES_RE.fullmatch(path):
            continue
        data = base64.b64decode(content)
        for item in gpoinventory.preferences_items(path, data):
            if item["effect"] == "retire_confirm":
                known.add(item["ref"])
        new, done = rewrite_preferences(path, data, confirmed)
        if new is not None:
            files[path] = new
            changes += done
    unknown = set(confirmed) - known
    if unknown:
        raise RetireError("unknown_registry_item", sorted(unknown)[0])
    return files, changes


def check_selectable(gpo_inventory_entry):
    """The inventory entry of a GPO that may be retired."""
    if gpo_inventory_entry is None:
        raise RetireError("gpo_not_found")
    if not gpo_inventory_entry.get("selectable"):
        raise RetireError("gpo_not_selectable", gpo_inventory_entry.get("kind", ""))
    if not gpo_inventory_entry.get("readable"):
        raise RetireError("gpo_unreadable")
    return gpo_inventory_entry


def needs_audit_confirmation(items):
    return any(i["effect"] == "audit_cleared" for i in items)
