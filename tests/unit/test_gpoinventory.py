#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Offline tests of the analysis of foreign GPOs."""

import base64
import os
import struct
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))

import gpoinventory  # noqa: E402
import policygen  # noqa: E402

OWN = "{11111111-1111-1111-1111-111111111111}"
FOREIGN = "{22222222-2222-2222-2222-222222222222}"


def pol(*entries):
    return b"PReg" + struct.pack("<I", 1) + b"".join(policygen._preg_entry(*e) for e in entries)


def utf16(text):
    return b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le")


def gpo(guid=FOREIGN, files=None, **attrs):
    files = files or {}
    out = {"guid": guid, "display_name": "Client security", "version": (3 << 16) | 7, "flags": 0,
           "machine_extensions": "", "user_extensions": "", "created": "20260105101112.0Z",
           "changed": "20261005080910.0Z", "wmi_filter": "", "links": [{"dn": "DC=example,DC=test",
                                                                        "enforced": False, "disabled": False}],
           "readable": True, "truncated": False,
           "files": [{"path": p, "size": len(d)} for p, d in files.items()],
           "contents": {p: base64.b64encode(d).decode() for p, d in files.items()}}
    out.update(attrs)
    return out


def effects(items):
    return [(i["effect"], i["name"]) for i in items]


TASKS_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Software update" uid="{AAAA}">
    <Properties action="U" name="Software update" runAs="NT AUTHORITY\\System">
      <Task version="1.2"><Actions><Exec><Command>winget.exe</Command></Exec></Actions></Task>
    </Properties>
  </TaskV2>
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Cleaned" removePolicy="1" uid="{BBBB}">
    <Properties action="U" name="Cleaned"/>
  </TaskV2>
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Gone" uid="{CCCC}">
    <Properties action="D" name="Gone"/>
  </TaskV2>
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Off" disabled="1" uid="{DDDD}">
    <Properties action="U" name="Off"/>
  </TaskV2>
</ScheduledTasks>
"""

GROUPS_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" uid="{EEEE}">
    <Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members><Member name="EXAMPLE\\it-admins" action="ADD" sid="S-1-5-21-1-2-3-1105"/></Members>
    </Properties>
  </Group>
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Remote Desktop Users" uid="{FFFF}">
    <Properties action="U" groupName="Remote Desktop Users"/>
  </Group>
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="service" uid="{ABAB}">
    <Properties action="U" userName="service"/>
  </User>
</Groups>
"""

REGISTRY_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">
  <Collection clsid="{53B533F5-224C-47e3-B01B-CA3B3F3FF4BF}" name="Vendor">
    <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="Proxy" uid="{1212}">
      <Properties action="U" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Vendor" name="Proxy" type="REG_SZ" value="p:8080"/>
    </Registry>
  </Collection>
</RegistrySettings>
"""


class Parts(unittest.TestCase):
    def test_registry_pol(self):
        data = pol(("Software\\Policies\\Microsoft\\FVE", "OSRecovery", 4, 1),
                   ("System\\CurrentControlSet\\Control\\Lsa", "LmCompatibilityLevel", 4, 5),
                   ("Software\\Policies\\Microsoft\\Windows\\System", "**del.Foo", 1, " "))
        items = gpoinventory.registry_pol_items("Machine/Registry.pol", data)
        self.assertEqual(effects(items), [
            ("removed", "HKLM\\Software\\Policies\\Microsoft\\FVE\\OSRecovery"),
            ("stays", "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel"),
            ("removed", "HKLM\\Software\\Policies\\Microsoft\\Windows\\System\\Foo")])
        self.assertEqual(items[0]["detail"], "REG_DWORD 1")
        self.assertEqual(items[2]["detail"], "**del")
        user = gpoinventory.registry_pol_items("User/Registry.pol", pol(("Software\\Policies\\X", "A", 1, "b")))
        self.assertEqual((user[0]["part"], user[0]["name"]), ("user", "HKCU\\Software\\Policies\\X\\A"))

    def test_registry_pol_rejects_garbage(self):
        with self.assertRaises(ValueError):
            gpoinventory.parse_registry_pol(b"nope")

    def test_security_template(self):
        text = ("[Unicode]\nUnicode=yes\n[Version]\nsignature=\"$CHICAGO$\"\n"
                "[Privilege Rights]\nSeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-21-1-2-3-1106\n"
                "[Registry Values]\nMACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1\n"
                "[System Access]\nMinimumPasswordLength = 12\n")
        items = gpoinventory.security_template_items(utf16(text))
        self.assertEqual([i["effect"] for i in items], ["restored", "stays", "stays"])
        self.assertEqual(items[0]["name"], "SeInteractiveLogonRight")
        self.assertIn("[Registry Values]", items[1]["name"])

    def test_audit(self):
        csv = ("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,"
               "Setting Value\n,System,Audit Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1\n")
        items = gpoinventory.audit_items(csv.encode())
        self.assertEqual(items[0]["effect"], "audit_cleared")
        self.assertIn("Audit Logon", items[0]["detail"])

    def test_scripts(self):
        ini = utf16("\n[Logon]\n0CmdLine=map-drives.ps1\n0Parameters=-Quiet\n1CmdLine=\\\\srv\\x.ps1\n")
        items = gpoinventory.scripts_items("User/Scripts/psscripts.ini", ini)
        self.assertEqual([(i["part"], i["effect"], i["name"], i["detail"]) for i in items], [
            ("user", "scripts", "Logon: map-drives.ps1", "-Quiet"),
            ("user", "scripts", "Logon: \\\\srv\\x.ps1", "")])

    def test_preferences_tasks(self):
        items = gpoinventory.preferences_items("Machine/Preferences/ScheduledTasks/ScheduledTasks.xml", TASKS_XML)
        self.assertEqual(effects(items), [
            ("retire_delete", "ScheduledTasks: Software update"),
            ("removed", "ScheduledTasks: Cleaned"),
            ("none", "ScheduledTasks: Gone")])
        self.assertIn("winget.exe", items[0]["detail"])

    def test_preferences_groups(self):
        items = gpoinventory.preferences_items("Machine/Preferences/Groups/Groups.xml", GROUPS_XML)
        self.assertEqual([i["effect"] for i in items], ["retire_members", "stays", "stays"])
        self.assertIn("it-admins", items[0]["detail"])

    def test_preferences_registry_collection(self):
        items = gpoinventory.preferences_items("Machine/Preferences/Registry/Registry.xml", REGISTRY_XML)
        self.assertEqual(effects(items), [("retire_confirm", "RegistrySettings: Proxy")])
        self.assertIn("SOFTWARE\\Vendor\\Proxy = p:8080", items[0]["detail"])

    def test_preferences_bad_xml(self):
        items = gpoinventory.preferences_items("Machine/Preferences/Files/Files.xml", b"<Files><broken")
        self.assertEqual(items[0]["effect"], "unknown")

    def test_text_is_cleaned(self):
        self.assertEqual(gpoinventory._text("a\nb\x00c"), "a b c")
        self.assertEqual(len(gpoinventory._text("x" * 1000)), gpoinventory.TEXT_MAX)


class Whole(unittest.TestCase):
    def test_classify_and_hide_own(self):
        raw = {"gpos": [
            gpo(OWN),
            gpo(gpoinventory.DEFAULT_DOMAIN_POLICY, display_name="Default Domain Policy"),
            gpo("{33333333-3333-3333-3333-333333333333}", files={"windeploy.json": b"{}"}, display_name="windeploy x"),
            gpo(FOREIGN, files={"Machine/Registry.pol": pol(("Software\\Policies\\A", "B", 4, 1)),
                                "Machine/Microsoft/Windows NT/Audit/audit.csv": b"h\n,,Audit Logon,{x},,,1\n",
                                "Machine/Applications/app.aas": b"x" * 10,
                                "GPT.INI": b"[General]\r\nVersion=1\r\n"},
                machine_extensions="[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
                                   "[{C6DC5466-785A-11D2-84D0-00C04FB169F7}{BACF5C8A-A3C7-11D1-A760-00C04FB9603F}]"),
        ], "dcs": [{"name": "dc1.example.test", "reachable": True, "missing_gpos": [FOREIGN]},
                   {"name": "dc2.example.test", "reachable": False, "missing_gpos": None}]}
        res = gpoinventory.analyse(raw, [OWN.lower()])
        self.assertEqual(res["own_count"], 1)
        kinds = {g["guid"]: g["kind"] for g in res["gpos"]}
        self.assertEqual(kinds, {FOREIGN: "foreign", gpoinventory.DEFAULT_DOMAIN_POLICY: "default_domain",
                                 "{33333333-3333-3333-3333-333333333333}": "windeploy_other"})
        g = res["gpos"][0]
        self.assertEqual(g["guid"], FOREIGN)
        self.assertTrue(g["selectable"])
        self.assertFalse(any(x["selectable"] for x in res["gpos"][1:]))
        self.assertEqual((g["version_machine"], g["version_user"]), (7, 3))
        self.assertEqual(g["changed"], "2026-10-05T08:09:10+00:00")
        self.assertEqual(g["dcs"], [{"dc": "dc1.example.test", "present": False},
                                    {"dc": "dc2.example.test", "present": None}])
        # most important first; GPT.INI is no entry; the software
        # installation extension and its file are not analysed
        self.assertEqual(g["items"][0]["effect"], "audit_cleared")
        self.assertEqual(g["summary"], {"audit_cleared": 1, "unknown": 2, "removed": 1})
        self.assertIn("Software installation", [i["name"] for i in g["items"]])

    def test_unreadable_folder(self):
        res = gpoinventory.analyse({"gpos": [gpo(readable=False, files={})], "dcs": []}, [])
        self.assertEqual((res["gpos"][0]["readable"], res["gpos"][0]["items"]), (False, []))

    def test_extension_names(self):
        self.assertEqual(gpoinventory.extension_names("[{a-b}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{x}]"),
                         ["{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"])


if __name__ == "__main__":
    unittest.main()
