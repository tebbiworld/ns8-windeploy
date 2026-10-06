#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Logon and startup scripts in a GPO: free PowerShell text written by the
admin, stored in the GPO folder and registered in psscripts.ini.

    User/Scripts/psscripts.ini                    [Logon]
    User/Scripts/Logon/windeploy-logon.ps1        runs at each user logon
    Machine/Scripts/psscripts.ini                 [Startup]
    Machine/Scripts/Startup/windeploy-startup.ps1 runs at each computer start

SYSVOL is readable by every authenticated user: a script must not hold
passwords. find_secrets() points at lines that look like one; the module
warns, it does not refuse (decision of the module owner).
"""

import hashlib
import re

PARTS = {
    # part: (side, section, folder, file name, extension names)
    "logon": ("User", "Logon", "Logon", "windeploy-logon.ps1",
              "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]"),
    "startup": ("Machine", "Startup", "Startup", "windeploy-startup.ps1",
                "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"),
}
MAX_BYTES = 64 * 1024

SECRET_PATTERNS = [
    re.compile(r"cmdkey\b.*\s/pass(word)?:", re.I),
    re.compile(r"net\s+use\b.*\s/user:\S+\s+\S+", re.I),
    re.compile(r"ConvertTo-SecureString\b.*-AsPlainText", re.I),
    re.compile(r"-Password\s+['\"]", re.I),
    re.compile(r"\b(passw(or)?d|kennwort|pwd)\s*=\s*['\"][^'\"]+['\"]", re.I),
]


class ScriptError(Exception):
    """Invalid script; the message starts with the key of the UI translation."""


def check_script(text):
    """Normalised script text (CRLF line ends) or "" for none."""
    if text is None:
        return ""
    if not isinstance(text, str) or "\x00" in text:
        raise ScriptError("invalid_script")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return ""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ScriptError("script_too_large")
    return text.rstrip("\n") + "\n"


def check_parts(parts):
    """{part: {"script", "cleanup"}} cleaned; at least one script."""
    if not isinstance(parts, dict):
        raise ScriptError("invalid_script")
    out = {}
    for name, entry in parts.items():
        if name not in PARTS or not isinstance(entry, dict):
            raise ScriptError(f"invalid_part: {name}")
        script = check_script(entry.get("script"))
        cleanup = check_script(entry.get("cleanup"))
        if not script:
            continue
        out[name] = {"script": script, "cleanup": cleanup}
    if not out:
        raise ScriptError("script_required")
    return out


def find_secrets(parts):
    """[(part, kind, line number)] of lines that look like a password."""
    found = []
    for name, entry in parts.items():
        for kind in ("script", "cleanup"):
            for no, line in enumerate((entry.get(kind) or "").splitlines(), 1):
                if any(p.search(line) for p in SECRET_PATTERNS):
                    found.append((name, kind, no))
    return found


def script_bytes(text):
    """UTF-8 with BOM (Windows PowerShell 5.1 reads UTF-8 without BOM as
    the ANSI code page) and CRLF."""
    return b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode("utf-8")


def ini_bytes(section, file_name):
    """psscripts.ini as the Group Policy editor writes it: UTF-16LE with
    BOM, CRLF, a blank first line."""
    text = f"\r\n[{section}]\r\n0CmdLine={file_name}\r\n0Parameters=\r\n"
    return b"\xff\xfe" + text.encode("utf-16-le")


def build_files(parts, removing=False):
    """({path: bytes or None}, machine extension names, user extension
    names). removing: the cleanup script runs instead of the script; a
    part without cleanup is not run any more."""
    files, ext = {}, {"Machine": "", "User": ""}
    for name, (side, section, folder, file_name, extensions) in PARTS.items():
        entry = parts.get(name)
        text = (entry["cleanup"] if removing else entry["script"]) if entry else ""
        script_path = f"{side}/Scripts/{folder}/{file_name}"
        ini_path = f"{side}/Scripts/psscripts.ini"
        if text:
            files[script_path] = script_bytes(text)
            files[ini_path] = ini_bytes(section, file_name)
            ext[side] = extensions
        else:
            files[script_path] = None
            files[ini_path] = None
    return files, ext["Machine"], ext["User"]


def summary(parts):
    """What the change log keeps of the scripts: size and SHA-256 of each
    text (the text itself is in the GPO backups)."""
    out = {}
    for name, entry in (parts or {}).items():
        out[name] = {kind: {"bytes": len(entry[kind].encode("utf-8")),
                            "sha256": hashlib.sha256(entry[kind].encode("utf-8")).hexdigest()}
                     for kind in ("script", "cleanup") if entry.get(kind)}
    return out
