#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Removal with a waiting period: start, cancel, purge (pypkg/removal.py),
with gpowrite replaced by a recorder."""

import base64
import datetime
import os
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))
sys.modules.setdefault("agent", types.SimpleNamespace(SD_INFO="<6>", SD_WARNING="<4>", SD_ERR="<3>", SD_DEBUG="<7>"))

import removal  # noqa: E402
import wdcommon  # noqa: E402

SETTINGS = {"realm": "AD.EXAMPLE.COM"}
XML = "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml"


class Recorder:
    def __init__(self):
        self.calls = []
        self.version = 0

    def __call__(self, request, settings=None, **_):
        self.calls.append(request)
        if request["op"] == "apply":
            self.version += 1
            return {"version": self.version}
        return {}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["AGENT_STATE_DIR"] = self.tmp.name
        self.tool = Recorder()
        self.saved = wdcommon.run_tool, wdcommon.delete_gpo
        wdcommon.run_tool = self.tool
        wdcommon.delete_gpo = lambda guid, links, settings=None: self.tool.calls.append({"op": "delete", "guid": guid})

    def tearDown(self):
        wdcommon.run_tool, wdcommon.delete_gpo = self.saved
        del os.environ["AGENT_STATE_DIR"]
        os.environ.pop("DELETE_GRACE_DAYS", None)
        self.tmp.cleanup()

    def xml(self):
        apply = [c for c in self.tool.calls if c["op"] == "apply"][-1]
        return base64.b64decode(apply["files"][XML]).decode()


def deployment():
    return {"id": "0123456789ab", "gpo_guid": "{00000000-0000-0000-0000-000000000001}", "name": "Browser",
            "delivery": "sysvol", "_scripts": [], "link_targets": ["DC=ad,DC=example,DC=com"],
            "schedule": {"frequency": "daily", "time": "12:30", "start_date": "2026-09-28"},
            "packages": [{"id": "Mozilla.Firefox", "mode": "upgrade", "now_run_id": "{00000000-0000-0000-0000-0000000000AA}"}]}


class Deployments(Base):
    def test_start_deletes_tasks_and_cancel_restores(self):
        d = deployment()
        pending = removal.start_deployment(d, "replaced", 7, settings=SETTINGS)
        self.assertEqual(pending["days"], 7)
        self.assertIn('action="D"', self.xml())
        self.assertNotIn('removePolicy="1"', self.xml())
        self.assertNotIn("ImmediateTaskV2", self.xml())  # no run now while removing
        with self.assertRaises(removal.RemovalError):
            removal.start_deployment(d, "again", settings=SETTINGS)
        removal.cancel_deployment(d, "still needed", settings=SETTINGS)
        self.assertNotIn("pending_delete", d)
        self.assertIn('action="R"', self.xml())
        log = wdcommon.read_deployment_log()
        self.assertEqual([e["change"] for e in log], ["removal_cancelled", "removal_started"])
        self.assertEqual(log[1]["reason"], "replaced")

    def test_purge_only_when_due(self):
        d = deployment()
        data = {"deployments": [d]}
        removal.start_deployment(d, "replaced", 1, settings=SETTINGS)
        with self.assertRaises(removal.RemovalError):
            removal.purge_deployment(data, d, "now", settings=SETTINGS)
        d["pending_delete"]["until"] = "2000-01-01T00:00:00+00:00"
        removal.purge_deployment(data, d, "replaced", by="timer", settings=SETTINGS)
        self.assertEqual(data["deployments"], [])
        self.assertEqual(self.tool.calls[-1]["op"], "delete")
        self.assertEqual(wdcommon.read_deployment_log()[0]["change"], "deleted_by_timer")

    def test_failed_write_keeps_state(self):
        d = deployment()

        def broken(request, **_):
            raise wdcommon.ToolError("DC down")
        wdcommon.run_tool = broken
        with self.assertRaises(wdcommon.ToolError):
            removal.start_deployment(d, "replaced", settings=SETTINGS)
        self.assertNotIn("pending_delete", d)
        self.assertEqual(wdcommon.read_deployment_log(), [])


class Profiles(Base):
    def profile(self):
        return {"id": "0123456789ab", "gpo_guid": "{00000000-0000-0000-0000-000000000002}", "name": "Workstations",
                "link_targets": [], "state": "active",
                "settings": {"hide_last_user": {"state": "on", "params": {}}}}

    def test_start_cancel(self):
        p = self.profile()
        removal.start_profile(p, "retired", settings=SETTINGS)
        self.assertEqual(p["state"], "pending_delete")
        self.assertEqual(p["settings"], {})  # Windows removes it by itself
        removal.cancel_profile(p, "not yet", settings=SETTINGS)
        self.assertEqual(p["settings"], {"hide_last_user": {"state": "on", "params": {}}})
        self.assertEqual(p["state"], "active")

    def test_purge(self):
        p = self.profile()
        data = {"profiles": [p]}
        removal.start_profile(p, "retired", settings=SETTINGS)
        p["pending_delete"]["until"] = "2000-01-01T00:00:00+00:00"
        removal.purge_profile(data, p, "retired", settings=SETTINGS)
        self.assertEqual(data["profiles"], [])


class Grace(unittest.TestCase):
    def test_default_and_range(self):
        os.environ["DELETE_GRACE_DAYS"] = "30"
        self.assertEqual(wdcommon.grace_days_default(), 30)
        os.environ["DELETE_GRACE_DAYS"] = "0"
        self.assertEqual(wdcommon.grace_days_default(), 14)
        del os.environ["DELETE_GRACE_DAYS"]
        now = datetime.datetime(2026, 10, 5, tzinfo=datetime.timezone.utc)
        self.assertEqual(wdcommon.new_pending("x", 14, now=now)["until"], "2026-10-19T00:00:00+00:00")
        with self.assertRaises(ValueError):
            wdcommon.new_pending("x", 400)
