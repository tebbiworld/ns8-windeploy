#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Offline tests of retiring a foreign GPO."""

import base64
import datetime
import os
import sys
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))
sys.path.insert(0, HERE)

import retire  # noqa: E402
from test_gpoinventory import GROUPS_XML, REGISTRY_XML, TASKS_XML, gpo  # noqa: E402

NOW = datetime.datetime(2026, 10, 17, 9, 30, tzinfo=datetime.timezone.utc)
TASKS = "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml"
GROUPS = "Machine/Preferences/Groups/Groups.xml"
REGISTRY = "Machine/Preferences/Registry/Registry.xml"

DELETE_ALL = b"""<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators" image="1" changed="2025-01-01 10:00:00" uid="{G1}">
    <Properties action="R" groupName="Administrators" deleteAllUsers="1" deleteAllGroups="1">
      <Members>
        <Member name="EXAMPLE\\a" action="ADD" sid="S-1-5-21-1-2-3-1"/>
        <Member name="EXAMPLE\\b" action="REMOVE" sid="S-1-5-21-1-2-3-2"/>
      </Members>
    </Properties>
  </Group>
</Groups>
"""


def actions(data):
    root = ET.fromstring(data)
    return {el.get("name"): el.find("Properties").get("action") for el in root.iter() if el.find("Properties") is not None}


class Rewrite(unittest.TestCase):
    def test_tasks_get_delete(self):
        new, changes = retire.rewrite_preferences(TASKS, TASKS_XML, now=NOW)
        self.assertTrue(new.startswith(b'<?xml version="1.0" encoding="utf-8"?>'))
        # removePolicy, already "D" and disabled items stay as they are
        self.assertEqual(actions(new), {"Software update": "D", "Cleaned": "U", "Gone": "D", "Off": "U"})
        self.assertEqual([c["name"] for c in changes], ["ScheduledTasks: Software update"])
        self.assertEqual(changes[0]["ref"], TASKS + "|{AAAA}")

    def test_groups_remove_added_members_only(self):
        new, changes = retire.rewrite_preferences(GROUPS, GROUPS_XML, now=NOW)
        root = ET.fromstring(new)
        admins = root.find("Group")
        self.assertEqual(admins.find("Properties").get("action"), "U")
        self.assertEqual([m.get("action") for m in admins.iter("Member")], ["REMOVE"])
        # the group without added members and the local user are untouched
        self.assertEqual(actions(new)["Remote Desktop Users"], "U")
        self.assertEqual(len(changes), 1)
        self.assertIn("it-admins", changes[0]["change"])

    def test_groups_never_delete_all_members(self):
        new, changes = retire.rewrite_preferences(GROUPS, DELETE_ALL, now=NOW)
        el = ET.fromstring(new).find("Group")
        props = el.find("Properties")
        self.assertEqual((props.get("action"), props.get("deleteAllUsers"), props.get("deleteAllGroups")),
                         ("U", "0", "0"))
        self.assertEqual([m.get("action") for m in props.iter("Member")], ["REMOVE", "REMOVE"])
        self.assertEqual((el.get("image"), el.get("changed")), ("2", "2026-10-17 09:30:00"))
        self.assertEqual(changes[0]["change"], "remove_members: EXAMPLE\\a")

    def test_registry_only_when_confirmed(self):
        self.assertEqual(retire.rewrite_preferences(REGISTRY, REGISTRY_XML, now=NOW), (None, []))
        new, changes = retire.rewrite_preferences(REGISTRY, REGISTRY_XML, confirmed={REGISTRY + "|{1212}"}, now=NOW)
        self.assertEqual(actions(new)["Proxy"], "D")
        self.assertEqual(len(changes), 1)

    def test_bad_xml(self):
        with self.assertRaises(retire.RetireError) as ctx:
            retire.rewrite_preferences(TASKS, b"<ScheduledTasks><x", now=NOW)
        self.assertEqual(ctx.exception.code, "preferences_unreadable")


class Plan(unittest.TestCase):
    def raw(self):
        return gpo(files={TASKS: TASKS_XML, GROUPS: GROUPS_XML, REGISTRY: REGISTRY_XML,
                          "Machine/Registry.pol": b"PReg\x01\x00\x00\x00"})

    def test_plan(self):
        files, changes = retire.plan(self.raw())
        self.assertEqual(sorted(files), [GROUPS, TASKS])
        self.assertEqual(len(changes), 2)
        files, changes = retire.plan(self.raw(), confirmed={REGISTRY + "|{1212}"})
        self.assertEqual(sorted(files), [GROUPS, REGISTRY, TASKS])

    def test_unknown_confirmation(self):
        with self.assertRaises(retire.RetireError) as ctx:
            retire.plan(self.raw(), confirmed={TASKS + "|{AAAA}"})
        self.assertEqual(ctx.exception.code, "unknown_registry_item")

    def test_selectable(self):
        with self.assertRaises(retire.RetireError):
            retire.check_selectable({"kind": "default_domain", "selectable": False, "readable": True})
        with self.assertRaises(retire.RetireError):
            retire.check_selectable(None)
        self.assertTrue(retire.needs_audit_confirmation([{"effect": "audit_cleared"}]))
        self.assertFalse(retire.needs_audit_confirmation([{"effect": "stays"}]))

    def test_contents_are_base64(self):
        raw = self.raw()
        self.assertEqual(base64.b64decode(raw["contents"][TASKS]), TASKS_XML)


if __name__ == "__main__":
    unittest.main()


class Steps(unittest.TestCase):
    """start, cancel, purge (pypkg/removal.py) with gpowrite replaced."""

    def setUp(self):
        import json
        import tempfile
        import types
        sys.modules.setdefault("agent", types.SimpleNamespace(SD_INFO="<6>", SD_WARNING="<4>", SD_ERR="<3>",
                                                              SD_DEBUG="<7>"))
        import gpoinventory
        import removal
        import wdcommon
        self.removal, self.wdcommon = removal, wdcommon
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["AGENT_STATE_DIR"] = self.tmp.name
        self.raw = gpo(files={TASKS: TASKS_XML, REGISTRY: REGISTRY_XML,
                              "Machine/Microsoft/Windows NT/Audit/audit.csv": b"h\n,,Audit Logon,{x},,,1\n"})
        inv = gpoinventory.analyse({"gpos": [self.raw], "dcs": []}, [])
        with open(os.path.join(self.tmp.name, wdcommon.INVENTORY_FILE), "w") as f:
            json.dump(inv, f)
        self.calls = []

        def tool(request, settings=None, **_):
            self.calls.append(request)
            if request["op"] == "inventory":
                return {"gpos": [self.raw]}
            if request["op"] == "retire_start":
                return {"version": 9, "links": self.raw["links"]}
            if request["op"] == "retire_delete":
                return {"deleted": True, "unlinked": [link["dn"] for link in self.raw["links"]]}
            return {}
        self.saved = wdcommon.run_tool
        wdcommon.run_tool = tool
        self.data = {"gpos": [], "history": []}

    def tearDown(self):
        self.wdcommon.run_tool = self.saved
        del os.environ["AGENT_STATE_DIR"]
        self.tmp.cleanup()

    def start(self, **kw):
        args = dict(confirm_audit=True)
        args.update(kw)
        return self.removal.start_retire(self.data, self.raw["guid"].lower(), "replaced", "admin", "pw",
                                         settings={}, **args)

    def test_audit_needs_confirmation(self):
        with self.assertRaises(self.removal.RemovalError) as ctx:
            self.start(confirm_audit=False)
        self.assertEqual(ctx.exception.code, "audit_confirm_required")
        self.assertEqual(self.calls, [])

    def test_start_writes_the_plan(self):
        record = self.start(confirmed=[REGISTRY + "|{1212}"])
        start = [c for c in self.calls if c["op"] == "retire_start"][0]
        self.assertEqual(sorted(start["files"]), [REGISTRY, TASKS])
        self.assertEqual((start["admin_user"], start["guid"]), ("admin", self.raw["guid"]))
        self.assertNotIn("admin_password", record)
        self.assertEqual(record["stamp"], start["stamp"])
        self.assertEqual(len(record["changes"]), 2)
        with self.assertRaises(self.removal.RemovalError):
            self.start()
        log = self.wdcommon.read_retire_log()
        self.assertEqual(log[0]["change"], "removal_started")

    def test_site_links_are_refused(self):
        self.raw["links"] = [{"dn": "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=test"}]
        with self.assertRaises(self.removal.RemovalError) as ctx:
            self.start()
        self.assertEqual(ctx.exception.code, "site_links")
        self.assertFalse([c for c in self.calls if c["op"] == "retire_start"])

    def test_not_selectable(self):
        import json
        path = os.path.join(self.tmp.name, self.wdcommon.INVENTORY_FILE)
        with open(path) as f:
            inv = json.load(f)
        inv["gpos"][0]["selectable"] = False
        with open(path, "w") as f:
            json.dump(inv, f)
        with self.assertRaises(retire.RetireError):
            self.start()

    def test_cancel_and_purge(self):
        self.start()
        with self.assertRaises(self.removal.RemovalError) as ctx:
            self.removal.purge_retire(self.data, self.raw["guid"], "now")
        self.assertEqual(ctx.exception.code, "removal_not_due")
        self.data["gpos"][0]["pending_delete"]["until"] = "2026-01-01T00:00:00+00:00"
        self.removal.purge_retire(self.data, self.raw["guid"], "over", by="timer")
        self.assertEqual(self.data["gpos"], [])
        self.assertEqual(self.data["history"][0]["by"], "timer")
        self.assertEqual(self.calls[-1], {"op": "retire_delete", "guid": self.raw["guid"]})
        self.start()
        self.removal.cancel_retire(self.data, self.raw["guid"], "kept", "admin", "pw")
        self.assertEqual((self.calls[-1]["op"], self.calls[-1]["admin_user"]), ("retire_cancel", "admin"))
        self.assertEqual(self.data["gpos"], [])

    def test_failed_cancel_blocks_the_delete(self):
        self.start()
        record = self.data["gpos"][0]
        record["pending_delete"]["until"] = "2026-01-01T00:00:00+00:00"

        def broken(request, settings=None, **_):
            raise self.wdcommon.ToolError("owner not restored", ntstatus=0xC000005A)
        self.wdcommon.run_tool = broken
        with self.assertRaises(self.wdcommon.ToolError):
            self.removal.cancel_retire(self.data, self.raw["guid"], "kept", "admin", "pw")
        self.assertIn("cancel_incomplete", record)
        with self.assertRaises(self.removal.RemovalError) as ctx:
            self.removal.purge_retire(self.data, self.raw["guid"], "over", by="timer")
        self.assertEqual(ctx.exception.code, "cancel_incomplete")

    def test_prune_keeps_pending_copies(self):
        base = os.path.join(self.tmp.name, self.wdcommon.BACKUP_DIR, self.wdcommon.RETIRED_DIR)
        for n in range(25):
            os.makedirs(os.path.join(base, "{G}", f"2026010{n // 10}T0000{n % 10}0Z"))
        os.makedirs(os.path.join(base, "{P}", "20250101T000000Z"))
        self.wdcommon.prune_retired_backups(protect=[("{P}", "20250101T000000Z")])
        # the newest 20 stay; the copy of a GPO still being retired is
        # kept on top and does not count
        self.assertEqual(len(os.listdir(os.path.join(base, "{G}"))), 20)
        self.assertTrue(os.path.isdir(os.path.join(base, "{P}", "20250101T000000Z")))
