#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Generate the files of a policy GPO, without touching AD.

A policy profile is one GPO with settings picked from the catalog below,
computer side only. Three kinds of files are written:

  Machine/Registry.pol                              registry policy (PReg)
  Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf  user rights
  Machine/Preferences/ScheduledTasks/ScheduledTasks.xml
                                                    a task for what needs a command

What a computer does when the GPO no longer applies, measured with
Windows 11 25H2:

- registry values below the policy keys (Software\\Policies,
  Software\\Microsoft\\Windows\\CurrentVersion\\Policies,
  System\\CurrentControlSet\\Policies) are removed;
- user rights return to what they were before the GPO;
- registry values at other places stay as they were set. A security
  option written through the security template came back to the value
  of the GPO even after a GPO had reset it, so such values are written
  as registry policy, where a reset deletes them for good;
- the advanced audit policy (audit.csv) is not restored but cleared:
  the computer audits nothing at all afterwards, less than a fresh
  Windows. The audit settings are therefore set by a task that runs
  auditpol; they stay when the GPO is gone.

Settings that stay have a "reset" state: the GPO then writes the Windows
default, to be kept until the computers have seen it.
"""

import datetime
import re
import struct

import gpogen

REG_SZ = 1
REG_DWORD = 4

# Client side extension and editor snap-in of each kind of file
EXT_REGISTRY = ("{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "{D02B1F72-3407-48AE-BA88-E8213C6761F1}")
EXT_SECURITY = ("{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}")

FILE_REGISTRY = "Machine/Registry.pol"
FILE_SECURITY = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
FILE_TASKS = "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml"

POLICY_KEY_RE = re.compile(
    r"^(software\\(policies|microsoft\\windows\\currentversion\\policies)|system\\currentcontrolset\\policies)(\\|$)", re.I)
LSA = "System\\CurrentControlSet\\Control\\Lsa"

SYSTEM = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
FVE = "Software\\Policies\\Microsoft\\FVE"
ADMINS = "*S-1-5-32-544"
LOCAL_SERVICE = "*S-1-5-19"
AUDIT_SUFFIX = "-69AE-11D9-BED3-505054503030}"


class PolicyError(ValueError):
    pass


def _audit(name, code, value, default):
    return {"name": name, "guid": "{0CCE" + code + AUDIT_SUFFIX, "value": value, "default": default}


# One entry per setting.
#   group     section of the UI
#   params    {name: {type, default, min, max, maxlength, values}}
#   reg       [(key, value name, type, data)] - data "{name}" takes a parameter
#   reg_reset [(key, value name)] outside the policy keys, deleted in the
#             reset state
#   reg_keep  [(key, value name)] outside the policy keys, left as set
#             (the value is the Windows default anyway)
#   rights    {privilege: SIDs}; Windows restores the previous list
#   audit     [subcategory, value when on, Windows default]; 0 none,
#             1 success, 2 failure, 3 both (defaults of Windows 11 25H2),
#             set with auditpol by a task
#   excludes  settings that contradict this one
#   risk      1 low, 2 check the environment first
CATALOG = {
    "session_lock": {
        "group": "logon",
        "params": {"seconds": {"type": "integer", "default": 180, "min": 60, "max": 3600}},
        "reg": [(SYSTEM, "InactivityTimeoutSecs", REG_DWORD, "{seconds}")],
        "risk": 2,
    },
    "logon_banner": {
        "group": "logon",
        "params": {"caption": {"type": "string", "default": "", "maxlength": 80},
                   "text": {"type": "string", "default": "", "maxlength": 2000}},
        "reg": [(SYSTEM, "legalnoticecaption", REG_SZ, "{caption}"),
                (SYSTEM, "legalnoticetext", REG_SZ, "{text}")],
        "risk": 1,
    },
    "hide_last_user": {
        "group": "logon",
        "reg": [(SYSTEM, "dontdisplaylastusername", REG_DWORD, 1)],
        "risk": 1,
    },
    "require_ctrl_alt_del": {
        "group": "logon",
        "reg": [(SYSTEM, "DisableCAD", REG_DWORD, 0)],
        "risk": 1,
    },
    "block_microsoft_accounts": {
        "group": "logon",
        "reg": [(SYSTEM, "NoConnectedUser", REG_DWORD, 3)],
        "risk": 1,
    },
    "usb_block": {
        "group": "media",
        "reg": [("Software\\Policies\\Microsoft\\Windows\\RemovableStorageDevices", "Deny_All", REG_DWORD, 1)],
        "excludes": ["usb_bitlocker_write"],
        "risk": 2,
    },
    "usb_bitlocker_write": {
        "group": "media",
        "reg": [("System\\CurrentControlSet\\Policies\\Microsoft\\FVE", "RDVDenyWriteAccess", REG_DWORD, 1),
                (FVE, "RDVDenyCrossOrg", REG_DWORD, 0)],
        "excludes": ["usb_block"],
        "risk": 2,
    },
    "no_autorun": {
        "group": "media",
        "reg": [("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoDriveTypeAutoRun", REG_DWORD, 255),
                ("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoAutorun", REG_DWORD, 1),
                ("Software\\Policies\\Microsoft\\Windows\\Explorer", "NoAutoplayfornonVolume", REG_DWORD, 1)],
        "risk": 1,
    },
    "bitlocker_policy": {
        "group": "media",
        "params": {"method": {"type": "string", "default": "xts256", "values": ["xts128", "xts256"]}},
        "reg": [(FVE, "EncryptionMethodWithXtsOs", REG_DWORD, "{method}"),
                (FVE, "EncryptionMethodWithXtsFdv", REG_DWORD, "{method}"),
                (FVE, "EncryptionMethodWithXtsRdv", REG_DWORD, 4),
                (FVE, "OSRecovery", REG_DWORD, 1),
                (FVE, "OSManageDRA", REG_DWORD, 1),
                (FVE, "OSRecoveryPassword", REG_DWORD, 2),
                (FVE, "OSRecoveryKey", REG_DWORD, 2),
                (FVE, "OSHideRecoveryPage", REG_DWORD, 0),
                (FVE, "OSActiveDirectoryBackup", REG_DWORD, 1),
                (FVE, "OSActiveDirectoryInfoToStore", REG_DWORD, 1),
                (FVE, "OSRequireActiveDirectoryBackup", REG_DWORD, 1),
                (FVE, "FDVRecovery", REG_DWORD, 1),
                (FVE, "FDVManageDRA", REG_DWORD, 1),
                (FVE, "FDVRecoveryPassword", REG_DWORD, 2),
                (FVE, "FDVRecoveryKey", REG_DWORD, 2),
                (FVE, "FDVHideRecoveryPage", REG_DWORD, 0),
                (FVE, "FDVActiveDirectoryBackup", REG_DWORD, 1),
                (FVE, "FDVActiveDirectoryInfoToStore", REG_DWORD, 1),
                (FVE, "FDVRequireActiveDirectoryBackup", REG_DWORD, 1)],
        "risk": 2,
    },
    "time_source_domain": {
        "group": "time",
        "reg": [("Software\\Policies\\Microsoft\\W32Time\\Parameters", "Type", REG_SZ, "NT5DS"),
                ("Software\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient", "Enabled", REG_DWORD, 1),
                ("Software\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient", "CrossSiteSyncFlags", REG_DWORD, 2),
                ("Software\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient", "ResolvePeerBackoffMinutes", REG_DWORD, 15),
                ("Software\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient", "ResolvePeerBackoffMaxTimes", REG_DWORD, 7),
                ("Software\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient", "SpecialPollInterval", REG_DWORD, 3600),
                ("Software\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient", "EventLogFlags", REG_DWORD, 0)],
        "risk": 1,
    },
    "time_change_admins_only": {
        "group": "time",
        "rights": {"SeSystemtimePrivilege": [LOCAL_SERVICE, ADMINS]},
        "risk": 1,
    },
    "timezone_change_admins_only": {
        "group": "time",
        "rights": {"SeTimeZonePrivilege": [LOCAL_SERVICE, ADMINS]},
        "risk": 1,
    },
    "defender_enforce": {
        "group": "protection",
        "reg": [("Software\\Policies\\Microsoft\\Windows Defender", "PUAProtection", REG_DWORD, 1),
                ("Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", REG_DWORD, 0)],
        "risk": 1,
    },
    "firewall_enforce": {
        "group": "protection",
        "reg": [("Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile", "EnableFirewall", REG_DWORD, 1),
                ("Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile", "EnableFirewall", REG_DWORD, 1),
                ("Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile", "EnableFirewall", REG_DWORD, 1)],
        "risk": 1,
    },
    "print_spooler_hardening": {
        "group": "protection",
        "reg": [("Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", "RestrictDriverInstallationToAdministrators", REG_DWORD, 1),
                ("Software\\Policies\\Microsoft\\Windows NT\\Printers", "RegisterSpoolerRemoteRpcEndPoint", REG_DWORD, 2)],
        "risk": 2,
    },
    "block_onedrive": {
        "group": "protection",
        "reg": [("Software\\Policies\\Microsoft\\Windows\\OneDrive", "DisableFileSyncNGSC", REG_DWORD, 1)],
        "risk": 1,
    },
    "ntlmv2_only": {
        "group": "network",
        "reg": [(LSA, "LmCompatibilityLevel", REG_DWORD, 5)],
        "reg_reset": [(LSA, "LmCompatibilityLevel")],
        "risk": 2,
    },
    "audit_extended": {
        "group": "logging",
        "audit": [_audit("Credential Validation", "923F", 3, 0),
                  _audit("Logon", "9215", 3, 3),
                  _audit("Logoff", "9216", 1, 1),
                  _audit("Account Lockout", "9217", 3, 1),
                  _audit("Special Logon", "921B", 1, 1),
                  _audit("User Account Management", "9235", 3, 1),
                  _audit("Computer Account Management", "9236", 1, 0),
                  _audit("Security Group Management", "9237", 3, 1),
                  _audit("Audit Policy Change", "922F", 3, 1),
                  _audit("Authentication Policy Change", "9230", 1, 1),
                  _audit("Process Creation", "922B", 1, 0),
                  _audit("Removable Storage", "9245", 3, 0)],
        # subcategory settings win over the nine old audit categories
        "reg": [(LSA, "SCENoApplyLegacyAuditPolicy", REG_DWORD, 1),
                (SYSTEM + "\\Audit", "ProcessCreationIncludeCmdLine_Enabled", REG_DWORD, 1)],
        "reg_keep": [(LSA, "SCENoApplyLegacyAuditPolicy")],
        "risk": 1,
    },
    "eventlog_sizes": {
        "group": "logging",
        "params": {"security_mb": {"type": "integer", "default": 192, "min": 20, "max": 4096}},
        "reg": [("Software\\Policies\\Microsoft\\Windows\\EventLog\\Security", "MaxSize", REG_DWORD, "{security_kb}"),
                ("Software\\Policies\\Microsoft\\Windows\\EventLog\\Application", "MaxSize", REG_DWORD, 32768),
                ("Software\\Policies\\Microsoft\\Windows\\EventLog\\System", "MaxSize", REG_DWORD, 32768)],
        "risk": 1,
    },
    "powershell_logging": {
        "group": "logging",
        "reg": [("Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "EnableScriptBlockLogging", REG_DWORD, 1)],
        "risk": 1,
    },
}

GROUPS = ["logon", "media", "time", "protection", "network", "logging"]
METHODS = {"xts128": 6, "xts256": 7}
STATES = ("on", "reset")


def is_tattoo(setting_id):
    """True if a computer keeps values of the setting after the GPO is
    gone, so that it needs the reset state."""
    s = CATALOG[setting_id]
    return bool(s.get("audit") or s.get("reg_reset"))


def catalog():
    """The catalog for the UI: no registry details, only what to show."""
    out = []
    for sid, s in CATALOG.items():
        out.append({"id": sid, "group": s["group"], "risk": s["risk"], "tattoo": is_tattoo(sid),
                    "params": s.get("params", {}), "excludes": s.get("excludes", [])})
    return out


def check_params(setting_id, params):
    """Validated parameters of a setting, defaults filled in."""
    if setting_id not in CATALOG:
        raise PolicyError(f"unknown setting {setting_id!r}")
    spec = CATALOG[setting_id].get("params", {})
    params = params or {}
    unknown = set(params) - set(spec)
    if unknown:
        raise PolicyError(f"{setting_id}: unknown parameter {sorted(unknown)[0]!r}")
    out = {}
    for name, p in spec.items():
        value = params.get(name, p["default"])
        if p["type"] == "integer":
            if isinstance(value, bool) or not isinstance(value, int) or not p["min"] <= value <= p["max"]:
                raise PolicyError(f"{setting_id}: {name} must be a number from {p['min']} to {p['max']}")
        elif "values" in p:
            if value not in p["values"]:
                raise PolicyError(f"{setting_id}: {name} must be one of {', '.join(p['values'])}")
        else:
            if not isinstance(value, str) or len(value) > p["maxlength"] or "\0" in value:
                raise PolicyError(f"{setting_id}: {name} is too long or not a text")
        out[name] = value
    if setting_id == "logon_banner" and not (out["caption"].strip() and out["text"].strip()):
        raise PolicyError("logon_banner: caption and text are required")
    return out


def check_settings(settings):
    """settings: {id: {"state": "on"|"reset", "params": {...}}}. Returns
    the same with validated parameters."""
    out = {}
    for sid, entry in settings.items():
        state = entry.get("state", "on")
        if state not in STATES:
            raise PolicyError(f"{sid}: invalid state {state!r}")
        if sid not in CATALOG:
            raise PolicyError(f"unknown setting {sid!r}")
        if state == "reset" and not is_tattoo(sid):
            raise PolicyError(f"{sid}: nothing to reset")
        out[sid] = {"state": state, "params": check_params(sid, entry.get("params"))}
    for sid, entry in out.items():
        for other in CATALOG[sid].get("excludes", []):
            if entry["state"] == "on" and out.get(other, {}).get("state") == "on":
                raise PolicyError(f"{sid} and {other} contradict each other")
    return out


def _value(data, params):
    if not isinstance(data, str) or not data.startswith("{"):
        return data
    name = data.strip("{}")
    if name == "method":
        return METHODS[params["method"]]
    if name == "security_kb":
        return params["security_mb"] * 1024
    return params[name]


# ------------------------------------------------------------ Registry.pol ---

def _preg_entry(key, name, rtype, data):
    if rtype == REG_DWORD:
        raw = struct.pack("<I", int(data))
    elif rtype == REG_SZ:
        raw = (str(data) + "\0").encode("utf-16-le")
    else:
        raise PolicyError(f"registry type {rtype} is not supported")
    u = lambda t: t.encode("utf-16-le")  # noqa: E731
    return (u("[") + u(key + "\0") + u(";") + u(name + "\0") + u(";") + struct.pack("<I", rtype) + u(";")
            + struct.pack("<I", len(raw)) + u(";") + raw + u("]"))


def build_registry_pol(settings):
    """Registry.pol (PReg version 1) or None when no setting needs it."""
    entries = []
    for sid, entry in settings.items():
        spec = CATALOG[sid]
        if entry["state"] == "on":
            for key, name, rtype, data in spec.get("reg", []):
                entries.append(_preg_entry(key, name, rtype, _value(data, entry["params"])))
        else:
            for key, name in spec.get("reg_reset", []):
                # "**del.<name>" deletes the value on the computer
                entries.append(_preg_entry(key, "**del." + name, REG_SZ, " "))
    if not entries:
        return None
    return b"PReg" + struct.pack("<I", 1) + b"".join(entries)


def parse_registry_pol(data):
    """[(key, value name, type, data)] of a Registry.pol, for the tests."""
    if data[:8] != b"PReg" + struct.pack("<I", 1):
        raise PolicyError("not a Registry.pol")
    out, pos = [], 8
    text = lambda b: b.decode("utf-16-le").rstrip("\0")  # noqa: E731
    while pos < len(data):
        if data[pos:pos + 2] != "[".encode("utf-16-le"):
            raise PolicyError("entry expected")
        pos += 2
        end = data.index("\0;".encode("utf-16-le"), pos)
        end += (end - pos) % 2  # align to a character
        key = text(data[pos:end]); pos = end + 4
        end = pos
        while data[end:end + 4] != "\0;".encode("utf-16-le"):
            end += 2
        name = text(data[pos:end]); pos = end + 4
        rtype = struct.unpack("<I", data[pos:pos + 4])[0]; pos += 6
        size = struct.unpack("<I", data[pos:pos + 4])[0]; pos += 6
        raw = data[pos:pos + size]; pos += size + 2
        out.append((key, name, rtype, struct.unpack("<I", raw)[0] if rtype == REG_DWORD else text(raw)))
    return out


# ------------------------------------------------------------ GptTmpl.inf ---

def build_security_template(settings):
    """GptTmpl.inf as bytes (UTF-16LE with BOM) or None. User rights
    replace the whole list of a privilege on the computer."""
    rights = {}
    for sid, entry in settings.items():
        if entry["state"] == "on":
            for privilege, sids in CATALOG[sid].get("rights", {}).items():
                rights[privilege] = ",".join(sids)
    if not rights:
        return None
    lines = ["[Unicode]", "Unicode=yes", "[Version]", 'signature="$CHICAGO$"', "Revision=1", "[Privilege Rights]"]
    lines += [f"{name} = {rights[name]}" for name in sorted(rights)]
    return b"\xff\xfe" + ("\r\n".join(lines) + "\r\n").encode("utf-16-le")


# ------------------------------------------------------------------ task ---

AUDIT_TASK = "windeploy policy audit"
# The task starts when it is registered, that is at every policy refresh;
# the daily time only keeps the task valid.
AUDIT_SCHEDULE = {"frequency": "daily", "time": "12:00", "start_date": "2026-01-01"}


def build_audit_script(settings):
    """PowerShell text that sets the audit subcategories with auditpol,
    or None."""
    lines = []
    for sid, entry in settings.items():
        for a in CATALOG[sid].get("audit", []):
            value = a["value"] if entry["state"] == "on" else a["default"]
            success = "enable" if value & 1 else "disable"
            failure = "enable" if value & 2 else "disable"
            lines.append(f"& auditpol.exe /set /subcategory:'{a['guid']}' /success:{success} /failure:{failure} | Out-Null")
    if not lines:
        return None
    return "\r\n".join(["$ErrorActionPreference = 'Stop'"] + lines + ["exit $LASTEXITCODE"]) + "\r\n"


def build_tasks_xml(settings, uid, changed=None):
    """ScheduledTasks.xml with the task that runs the audit script, or
    None. uid is the GUID of the task item, kept by the profile."""
    script = build_audit_script(settings)
    if script is None:
        return None
    task = {
        "name": AUDIT_TASK, "uid": uid,
        "changed": changed or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
        "author": "windeploy", "description": "Audit settings of a policy profile (NethServer module windeploy)",
        "arguments": gpogen.task_arguments("embedded", script_text=script),
        "schedule": AUDIT_SCHEDULE, "time_limit": "PT1H", "remove_policy": True,
    }
    return gpogen.build_scheduled_tasks_xml([task]).encode("utf-8")


# ------------------------------------------------------------------- GPO ---

def build_files(settings, task_uid=None):
    """({relative path: bytes or None}, machine extension names) of a
    policy GPO. None deletes a file that is not needed any more."""
    settings = check_settings(settings)
    files = {FILE_REGISTRY: build_registry_pol(settings),
             FILE_SECURITY: build_security_template(settings),
             FILE_TASKS: build_tasks_xml(settings, task_uid or gpogen.new_uid())}
    names = {}
    for path, (cse, tool) in ((FILE_REGISTRY, EXT_REGISTRY), (FILE_SECURITY, EXT_SECURITY)):
        if files[path] is not None:
            names.setdefault(cse, set()).add(tool)
    extensions = gpogen.format_extension_names(names)
    if files[FILE_TASKS] is not None:
        extensions = gpogen.add_scheduled_tasks_extension(extensions)
    return files, extensions


def after_removal(settings, removed):
    """Settings of a profile after the admin took `removed` out: what
    Windows cleans up by itself is dropped, the rest goes to the reset
    state and writes the Windows default."""
    out = dict(settings)
    for sid in removed:
        if sid not in out:
            continue
        if is_tattoo(sid):
            out[sid] = {"state": "reset", "params": out[sid].get("params", {})}
        else:
            del out[sid]
    return out
