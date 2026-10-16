#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Analyse the GPOs of the domain that are not the module's (page "GPO
inventory"), read only, without touching AD.

Input is what gpowrite's op "inventory" returns: the attributes, links
and files of every GPO, with the content of the files below. Output is,
per GPO, what it sets and what a computer keeps when the GPO is deleted,
as measured with Windows 11 25H2 for the module's own GPOs or known from
the Group Policy documentation:

  Registry.pol below the policy keys      Windows removes it       removed
  Registry.pol elsewhere                  stays as set             stays
  GptTmpl.inf user rights                 back to before           restored
  GptTmpl.inf other sections              stays as set             stays
  audit.csv                               ALL auditing cleared     audit_cleared
  logon/startup scripts                   do not run any more,     scripts
                                          what they made stays
  Preferences item with removePolicy      Windows removes it       removed
  Preferences item with action Delete     nothing to keep          none
  Preferences tasks, drives, shortcuts,   stays; retiring the GPO  retire_delete
    environment variables                 deletes it (action D)
  Preferences local groups                stays; retiring removes  retire_members
                                          the added members
  Preferences registry                    stays; retiring deletes  retire_confirm
                                          it after a confirmation
  other Preferences, files, folders       stays as set             stays
  any other file                          not analysed             unknown

The content comes from the domain's GPOs, which only domain admins
write: it is parsed, never executed, and shown as text.
"""

import base64
import datetime
import re
import struct
import xml.etree.ElementTree as ET

DEFAULT_DOMAIN_POLICY = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
DEFAULT_DC_POLICY = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
DEFAULTS = {DEFAULT_DOMAIN_POLICY: "default_domain", DEFAULT_DC_POLICY: "default_dc"}

EFFECTS = ("audit_cleared", "retire_delete", "retire_members", "retire_confirm", "stays", "scripts",
           "unknown", "restored", "removed", "none")
# shown first: what needs attention before a GPO is deleted
SEVERITY = {e: i for i, e in enumerate(EFFECTS)}

POLICY_KEY_RE = re.compile(
    r"^(software\\(policies|microsoft\\windows\\currentversion\\policies)|system\\currentcontrolset\\policies)(\\|$)",
    re.I)
REG_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
             5: "REG_DWORD_BIG_ENDIAN", 7: "REG_MULTI_SZ", 11: "REG_QWORD"}

# Preferences: folder below Preferences -> how retiring treats its items
GPP_RETIRE = {
    "scheduledtasks": "retire_delete",
    "drives": "retire_delete",
    "shortcuts": "retire_delete",
    "environmentvariables": "retire_delete",
    "groups": "retire_members",
    "registry": "retire_confirm",
}
# item elements of the Preferences files (collections are walked into)
GPP_CONTAINERS = {"Collection"}
GPP_SKIP = {"Filters"}

# client side extensions the analysis covers; others are listed by name
CSE_NAMES = {
    "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "Registry",
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "Security",
    "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}": "Advanced audit policy",
    "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}": "Scripts",
    "{AADCED64-746C-4633-A97C-D61349046527}": "Preferences: scheduled tasks",
    "{5794DAFD-BE60-433F-88A2-1A31939AC01F}": "Preferences: drive maps",
    "{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}": "Preferences: shortcuts",
    "{0E28E245-9368-4853-AD84-6DA3BA35BB75}": "Preferences: environment",
    "{17D89FEC-5C44-4972-B12D-241CAEF74509}": "Preferences: local users and groups",
    "{B087BE9D-ED37-454F-AF9C-04291E351182}": "Preferences: registry",
    "{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}": "Preferences: files",
    "{6232C319-91AC-4931-9385-E70C2B099F0E}": "Preferences: folders",
    "{74EE6C03-5363-4554-B161-627540339CAB}": "Preferences: ini files",
    "{91FBB303-0CD5-4055-BF42-E512A681B325}": "Preferences: services",
    "{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}": "Preferences: printers",
    "{6A4C88C6-C502-4F74-8F60-2CB23EDC24E2}": "Preferences: network shares",
    "{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}": "Preferences: power options",
    "{728EE579-943C-4519-9EF7-AB56765798ED}": "Preferences: data sources",
    "{1A6364EB-776B-4120-ADE1-B63A406A76B5}": "Preferences: devices",
    "{A3F3E39B-5D83-4940-B954-28315B82F0A8}": "Preferences: folder options",
    "{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}": "Preferences: Internet settings",
    "{E5094040-C46C-4115-B030-04FB2E545B00}": "Preferences: regional options",
    "{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}": "Preferences: start menu",
    "{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}": "Preferences: network options",
    "{C631DF4C-088F-4156-B058-4375F0853CD8}": "Offline files",
    "{25537BA6-77A8-11D2-9B6C-0000F8080861}": "Folder redirection",
    "{C6DC5466-785A-11D2-84D0-00C04FB169F7}": "Software installation",
    "{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}": "EFS recovery",
    "{3060E8D0-7020-11D2-842D-00C04FA372D4}": "Remote installation services",
    "{E437BC1C-AA7D-11D2-A382-00C04F991E27}": "IP security",
    "{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}": "Wireless network",
    "{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}": "Wired network",
    "{FB2CA36D-0B40-4307-821B-A13B252DE56C}": "Policy-based QoS",
    "{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}": "Internet Explorer zone mapping",
    "{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}": "Internet Explorer machine accelerators",
    "{D76B9641-3288-4F75-942D-087DE603E3EA}": "LAPS (legacy)",
    "{9650FDBC-053A-4715-AD14-FC2DC65E8330}": "Device installation",
    "{2A8FDC61-2347-4C87-92F6-B05EB91A201A}": "MitigationOptions",
    "{169EBF44-942F-4C43-87CE-13C93996EBBE}": "Application control (AppLocker)",
    "{D02B1F72-3407-48AE-BA88-E8213C6761F1}": "Administrative templates (editor)",
    "{D02B1F73-3407-48AE-BA88-E8213C6761F1}": "Administrative templates (editor)",
}
# extensions whose settings the files above describe (editor snap-ins and
# the null GUID carry no settings of their own)
CSE_ANALYSED = {"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
                "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}", "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}",
                "{00000000-0000-0000-0000-000000000000}"}
GPP_CSES = {g for g, n in CSE_NAMES.items() if n.startswith("Preferences:")}

# files that need no entry of their own
IGNORED_FILES_RE = re.compile(
    r"^(gpt\.ini|windeploy\.json|(machine|user)/comment\.cmtx|(machine|user)/scripts/(logon|logoff|startup|shutdown)/.*"
    r"|machine/microsoft/windows nt/secedit/gpttmpl\.inf|machine/microsoft/windows nt/audit/audit\.csv"
    r"|(machine|user)/registry\.pol|(machine|user)/scripts/(ps)?scripts\.ini"
    r"|(machine|user)/preferences/[^/]+/[^/]+\.xml|.*\.adm|adm/.*|.*\.windeploy-tmp)$", re.I)

ITEMS_MAX = 400
TEXT_MAX = 300


def _text(value, limit=TEXT_MAX):
    value = "".join(ch if ch.isprintable() else " " for ch in str(value))
    return value if len(value) <= limit else value[:limit - 1] + "…"


def _item(part, source, effect, name, detail=""):
    return {"part": part, "source": source, "effect": effect, "name": _text(name), "detail": _text(detail)}


def _part(path):
    return "user" if path.lower().startswith("user/") else "machine"


def _decode_text(data):
    """Text of an INI-like file: UTF-16 with BOM, UTF-8 (BOM or not), or
    the ANSI code page."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def parse_ini(text):
    """[(section, key, value)] of an INI text; keys without "=" get value
    None. Section names keep their case."""
    out, section = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            out.append((section, key.strip(), value.strip()))
        else:
            out.append((section, line, None))
    return out


# --------------------------------------------------------------- Registry.pol

def parse_registry_pol(data):
    """[(key, value name, type, data)] of a Registry.pol (PReg version 1).
    Data is decoded for the string and number types, hex otherwise."""
    if data[:4] != b"PReg" or struct.unpack("<I", data[4:8])[0] != 1:
        raise ValueError("not a Registry.pol")
    out, pos, n = [], 8, len(data)
    semi = ";".encode("utf-16-le")

    def field(pos):
        # a UTF-16LE string up to ";" (NUL terminated inside)
        end = pos
        while end + 1 < n and data[end:end + 2] != semi:
            end += 2
        return data[pos:end].decode("utf-16-le", "replace").rstrip("\0"), end + 2

    while pos < n:
        if data[pos:pos + 2] != "[".encode("utf-16-le"):
            raise ValueError("entry expected")
        key, pos = field(pos + 2)
        name, pos = field(pos)
        rtype = struct.unpack("<I", data[pos:pos + 4])[0]
        pos += 6
        size = struct.unpack("<I", data[pos:pos + 4])[0]
        pos += 6
        raw = data[pos:pos + size]
        pos += size + 2  # data and "]"
        if rtype in (1, 2):
            value = raw.decode("utf-16-le", "replace").rstrip("\0")
        elif rtype == 7:
            value = " | ".join(s for s in raw.decode("utf-16-le", "replace").split("\0") if s)
        elif rtype == 4 and size == 4:
            value = struct.unpack("<I", raw)[0]
        elif rtype == 11 and size == 8:
            value = struct.unpack("<Q", raw)[0]
        else:
            value = raw[:64].hex()
        out.append((key, name, rtype, value))
    return out


def registry_pol_items(path, data):
    part = _part(path)
    hive = "HKCU" if part == "user" else "HKLM"
    items = []
    for key, name, rtype, value in parse_registry_pol(data):
        lower = name.lower()
        if lower.startswith("**delvals"):
            label, detail = f"{hive}\\{key}", "**delvals"
        elif lower.startswith("**del."):
            label, detail = f"{hive}\\{key}\\{name[6:]}", "**del"
        elif lower.startswith("**deletevalues") or lower.startswith("**deletekeys"):
            label, detail = f"{hive}\\{key}", name[2:].split(";")[0]
        elif lower.startswith("**"):
            label, detail = f"{hive}\\{key}", name
        else:
            label, detail = f"{hive}\\{key}\\{name}", f"{REG_TYPES.get(rtype, rtype)} {value}"
        effect = "removed" if POLICY_KEY_RE.match(key) else "stays"
        items.append(_item(part, "registry_pol", effect, label, detail))
    return items


# ---------------------------------------------------------------- GptTmpl.inf

def security_template_items(data):
    items = []
    for section, key, value in parse_ini(_decode_text(data)):
        s = section.lower()
        if s in ("unicode", "version"):
            continue
        if s == "privilege rights":
            items.append(_item("machine", "security", "restored", key, value or ""))
        else:
            items.append(_item("machine", "security", "stays", f"[{section}] {key}", value or ""))
    return items


# ------------------------------------------------------------------- audit.csv

def audit_items(data):
    text = _decode_text(data)
    rows = [r for r in text.splitlines()[1:] if r.strip()]
    names = []
    for r in rows:
        cols = r.split(",")
        if len(cols) > 3 and cols[2].strip():
            names.append(cols[2].strip())
    detail = ", ".join(names[:12]) + (" …" if len(names) > 12 else "")
    return [_item("machine", "audit", "audit_cleared", f"audit.csv ({len(rows)})", detail)]


# --------------------------------------------------------------------- scripts

def scripts_items(path, data):
    part = _part(path)
    kind = "powershell" if path.lower().endswith("psscripts.ini") else "script"
    scripts = {}
    for section, key, value in parse_ini(_decode_text(data)):
        m = re.fullmatch(r"(\d+)(CmdLine|Parameters)", key, re.I)
        if not m or value is None:
            continue
        entry = scripts.setdefault((section, int(m.group(1))), {"cmd": "", "params": ""})
        entry["cmd" if m.group(2).lower() == "cmdline" else "params"] = value
    items = []
    for (section, _), e in sorted(scripts.items()):
        if e["cmd"]:
            items.append(_item(part, kind, "scripts", f"{section}: {e['cmd']}", e["params"]))
    return items


# ----------------------------------------------------------------- Preferences

def _gpp_name(el):
    props = el.find("Properties")
    for attr in ("name",):
        if el.get(attr):
            return el.get(attr)
    if props is not None:
        for attr in ("name", "groupName", "letter", "shortcutPath", "targetPath", "path", "key"):
            if props.get(attr):
                return props.get(attr)
    return el.tag


def _gpp_detail(folder, el):
    props = el.find("Properties")
    if props is None:
        return ""
    if folder == "registry":
        hive, key, name = props.get("hive", ""), props.get("key", ""), props.get("name", "")
        value = props.get("value", "")
        return f"{hive}\\{key}\\{name or '(default)'} = {value}"
    if folder == "groups":
        members = [m.get("name") or m.get("sid") or "?" for m in el.iter("Member")
                   if (m.get("action") or "ADD").upper() == "ADD"]
        return ("+ " + ", ".join(members)) if members else ""
    if folder == "drives":
        return props.get("path", "")
    if folder == "scheduledtasks":
        cmd = el.find(".//Exec/Command")
        if cmd is not None:
            return cmd.text or ""
        return props.get("appName", "")
    if folder == "environmentvariables":
        return f"{props.get('name', '')}={props.get('value', '')}"
    if folder == "shortcuts":
        return props.get("targetPath", "")
    for attr in ("targetPath", "path", "value", "fromPath"):
        if props.get(attr):
            return props.get(attr)
    return ""


def _gpp_elements(root):
    """The item elements of a Preferences file, collections walked into."""
    for el in root:
        if el.tag in GPP_CONTAINERS:
            yield from _gpp_elements(el)
        elif el.tag not in GPP_SKIP:
            yield el


def preferences_items(path, data):
    part = _part(path)
    folder = path.split("/")[-2].lower()
    try:
        root = ET.fromstring(data)
    except ET.ParseError as ex:
        return [_item(part, "preferences", "unknown", path, f"not readable: {ex}")]
    items = []
    for el in _gpp_elements(root):
        if el.get("disabled") == "1":
            continue
        props = el.find("Properties")
        action = (props.get("action") if props is not None else "") or "U"
        action = action.upper()[:1]
        if action == "D":
            effect = "none"
        elif el.get("removePolicy") == "1":
            effect = "removed"
        else:
            effect = GPP_RETIRE.get(folder, "stays")
            if effect == "retire_members" and (el.tag != "Group" or not _gpp_detail(folder, el)):
                # a local user, or a group without added members: retiring
                # leaves it alone
                effect = "stays"
        detail = _gpp_detail(folder, el)
        # the action as the editor abbreviates it: Create, Replace, Update, Delete
        items.append(_item(part, "preferences", effect, f"{root.tag}: {_gpp_name(el)}",
                           f"[{action}] {detail}".strip()))
    return items


# ------------------------------------------------------------------------ GPO

def extension_names(value):
    """[GUID] of the client side extensions in gPC*ExtensionNames."""
    out = []
    for group in re.findall(r"\[([^\]]*)\]", value or ""):
        guids = re.findall(r"\{[0-9A-Fa-f-]{36}\}", group)
        if guids and guids[0].upper() not in out:
            out.append(guids[0].upper())
    return out


def _when(value):
    """LDAP generalized time (20261016093419.0Z) as ISO text."""
    m = re.fullmatch(r"(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\.\d+)?Z", value or "")
    if not m:
        return ""
    return datetime.datetime(*map(int, m.groups()[:6]), tzinfo=datetime.timezone.utc).isoformat()


def classify(gpo, own_guids):
    guid = gpo["guid"].upper()
    if guid in own_guids:
        return "own"
    if guid in DEFAULTS:
        return DEFAULTS[guid]
    if "windeploy.json" in {f["path"].lower() for f in gpo.get("files", [])}:
        return "windeploy_other"
    return "foreign"


def analyse_gpo(gpo):
    """Items of one GPO, most important first."""
    items = []
    contents = gpo.get("contents", {})
    for f in gpo.get("files", []):
        path, low = f["path"], f["path"].lower()
        data = None
        if path in contents:
            data = base64.b64decode(contents[path])
        try:
            if low.endswith("registry.pol") and low.count("/") == 1:
                items += registry_pol_items(path, data) if data is not None else []
            elif low == "machine/microsoft/windows nt/secedit/gpttmpl.inf":
                items += security_template_items(data) if data is not None else []
            elif low == "machine/microsoft/windows nt/audit/audit.csv":
                items += audit_items(data) if data is not None else [
                    _item("machine", "audit", "audit_cleared", path, "")]
            elif re.fullmatch(r"(machine|user)/scripts/(ps)?scripts\.ini", low):
                items += scripts_items(path, data) if data is not None else []
            elif re.fullmatch(r"(machine|user)/preferences/[^/]+/[^/]+\.xml", low):
                items += preferences_items(path, data) if data is not None else [
                    _item(_part(path), "preferences", "unknown", path, f"{f['size']} B")]
            elif not IGNORED_FILES_RE.fullmatch(low):
                items.append(_item(_part(path), "file", "unknown", path, f"{f['size']} B"))
        except (ValueError, struct.error, UnicodeDecodeError) as ex:
            items.append(_item(_part(path), "file", "unknown", path, f"not readable: {ex}"))
    seen = set()
    for part, attr in (("machine", "machine_extensions"), ("user", "user_extensions")):
        for cse in extension_names(gpo.get(attr, "")):
            if cse in CSE_ANALYSED or cse in GPP_CSES or (part, cse) in seen:
                continue
            seen.add((part, cse))
            items.append(_item(part, "extension", "unknown", CSE_NAMES.get(cse, cse), cse if cse in CSE_NAMES else ""))
    items.sort(key=lambda i: (SEVERITY[i["effect"]], i["part"], i["source"]))
    return items


def summary(items):
    out = {}
    for i in items:
        out[i["effect"]] = out.get(i["effect"], 0) + 1
    return out


def analyse(raw, own_guids, now=None):
    """The inventory as kept in state/gpo-inventory.json and shown on the
    page: every GPO with its kind, links, versions, presence on the DCs
    and items; own GPOs only counted."""
    own = {g.upper() for g in own_guids}
    dcs = raw.get("dcs", [])
    out, own_count = [], 0
    for gpo in raw.get("gpos", []):
        kind = classify(gpo, own)
        if kind == "own":
            own_count += 1
            continue
        items = analyse_gpo(gpo) if gpo.get("readable") else []
        version = int(gpo.get("version", 0))
        flags = int(gpo.get("flags", 0))
        presence = []
        for dc in dcs:
            missing = dc.get("missing_gpos")
            presence.append({"dc": dc["name"],
                             "present": None if missing is None else gpo["guid"] not in missing})
        out.append({
            "guid": gpo["guid"],
            "name": _text(gpo.get("display_name", ""), 256),
            "kind": kind,
            "selectable": kind == "foreign",
            "links": gpo.get("links", []),
            "version_machine": version & 0xFFFF,
            "version_user": version >> 16,
            "machine_disabled": bool(flags & 2),
            "user_disabled": bool(flags & 1),
            "created": _when(gpo.get("created", "")),
            "changed": _when(gpo.get("changed", "")),
            "wmi_filter": bool(gpo.get("wmi_filter")),
            "readable": bool(gpo.get("readable")),
            "truncated": bool(gpo.get("truncated")) or len(items) > ITEMS_MAX,
            "dcs": presence,
            "summary": summary(items),
            "items": items[:ITEMS_MAX],
        })
    out.sort(key=lambda g: (g["kind"] != "foreign", g["name"].lower()))
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return {"checked": now.isoformat(timespec="seconds"), "gpos": out, "own_count": own_count,
            "dcs": [{"name": d["name"], "reachable": d.get("reachable", False)} for d in dcs]}
