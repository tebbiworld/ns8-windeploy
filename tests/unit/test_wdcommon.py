#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""build_files of wdcommon: run-now tasks and installer scope."""

import os
import sys
import types
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))
# the NS8 agent library is not installed outside a module
sys.modules.setdefault("agent", types.SimpleNamespace(SD_INFO="<6>", SD_WARNING="<4>", SD_ERR="<3>", SD_DEBUG="<7>"))

import base64  # noqa: E402

import wdcommon  # noqa: E402

SETTINGS = {"realm": "AD.EXAMPLE.COM"}
XML = "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml"


def deployment(**pkg_extra):
    return {
        "id": "0123456789ab", "gpo_guid": "{00000000-0000-0000-0000-000000000001}",
        "name": "Nextcloud", "delivery": "sysvol", "_scripts": [],
        "schedule": {"frequency": "daily", "time": "22:00", "start_date": "2026-09-26"},
        "packages": [dict({"id": "Nextcloud.Talk", "mode": "install"}, **pkg_extra.get("a", {})),
                     dict({"id": "Nextcloud.NextcloudDesktop", "mode": "install"}, **pkg_extra.get("b", {}))],
    }


def immediate(files):
    root = ET.fromstring(base64.b64decode(files[XML]).decode("utf-8").split("?>", 1)[1])
    return [(t.get("name"), t.find("Filters/FilterRunOnce").get("id")) for t in root.findall("ImmediateTaskV2")]


class RunNow(unittest.TestCase):
    def test_no_run_now(self):
        self.assertEqual(immediate(wdcommon.build_files(deployment(), SETTINGS)), [])

    def test_own_run_once_id_per_package(self):
        d = deployment(a={"now_run_id": "{11111111-1111-1111-1111-111111111111}"},
                       b={"now_run_id": "{22222222-2222-2222-2222-222222222222}"})
        tasks = immediate(wdcommon.build_files(d, SETTINGS))
        self.assertEqual(len(tasks), 2)
        self.assertEqual(len({rid for _, rid in tasks}), 2)

    def test_package_added_later_does_not_run_now(self):
        d = deployment(a={"now_run_id": "{11111111-1111-1111-1111-111111111111}"})
        self.assertEqual([n for n, _ in immediate(wdcommon.build_files(d, SETTINGS))],
                         ["windeploy now Nextcloud.Talk"])

    def test_old_deployment_level_id_ignored(self):
        d = deployment()
        d["run_now_id"] = "{33333333-3333-3333-3333-333333333333}"
        self.assertEqual(immediate(wdcommon.build_files(d, SETTINGS)), [])


class Scope(unittest.TestCase):
    def test_scope_in_script(self):
        files = wdcommon.build_files(deployment(a={"scope": "machine"}), SETTINGS)
        talk = base64.b64decode(files["Machine/Scripts/windeploy/Nextcloud.Talk.ps1"]).decode("utf-8-sig")
        desktop = base64.b64decode(files["Machine/Scripts/windeploy/Nextcloud.NextcloudDesktop.ps1"]).decode("utf-8-sig")
        self.assertIn("$Scope = 'machine'", talk)
        self.assertIn("$Scope = ''", desktop)


if __name__ == "__main__":
    unittest.main()


class Lifecycle(unittest.TestCase):
    def test_tasks_are_removed_with_the_gpo(self):
        files = wdcommon.build_files(deployment(), SETTINGS)
        root = ET.fromstring(base64.b64decode(files[XML]).decode("utf-8").split("?>", 1)[1])
        tasks = root.findall("TaskV2")
        self.assertEqual(len(tasks), 2)
        for t in tasks:
            self.assertEqual(t.get("removePolicy"), "1")
            self.assertIsNotNone(t.find(".//RegistrationTrigger"))

    def test_run_now_skips_the_due_test(self):
        d = deployment(a={"now_run_id": "{11111111-1111-1111-1111-111111111111}"})
        root = ET.fromstring(base64.b64decode(wdcommon.build_files(d, SETTINGS)[XML]).decode("utf-8").split("?>", 1)[1])
        self.assertTrue(root.find("ImmediateTaskV2//Arguments").text.endswith(" -RunNow"))
        self.assertFalse(root.find("TaskV2//Arguments").text.endswith(" -RunNow"))

    def test_description_file(self):
        import json
        files = wdcommon.build_files(deployment(), SETTINGS)
        info = json.loads(base64.b64decode(files[wdcommon.DESCRIPTION_FILE]))
        self.assertEqual(info["name"], "Nextcloud")
        self.assertEqual([p["id"] for p in info["packages"]], ["Nextcloud.Talk", "Nextcloud.NextcloudDesktop"])


class Backups(unittest.TestCase):
    def test_prune_and_remove(self):
        import tempfile
        guid = "{00000000-0000-0000-0000-000000000001}"
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["AGENT_STATE_DIR"] = tmp
            try:
                for n in range(13):
                    os.makedirs(os.path.join(tmp, wdcommon.BACKUP_DIR, guid, f"20260929T0000{n:02d}Z"))
                wdcommon.prune_backups(guid)
                left = sorted(os.listdir(os.path.join(tmp, wdcommon.BACKUP_DIR, guid)))
                self.assertEqual(len(left), wdcommon.BACKUPS_KEPT)
                self.assertEqual(left[0], "20260929T000003Z")
                wdcommon.prune_backups("{00000000-0000-0000-0000-000000000002}")  # no folder: no error
                wdcommon.remove_backups(guid)
                self.assertFalse(os.path.exists(os.path.join(tmp, wdcommon.BACKUP_DIR, guid)))
            finally:
                del os.environ["AGENT_STATE_DIR"]


class ResultCodes(unittest.TestCase):
    def test_codes_not_text(self):
        # "49" in the message (a DC address) is not a wrong password
        self.assertFalse(wdcommon.ToolError("cannot reach 10.0.49.50", ldap_code=1).bad_credentials)
        self.assertTrue(wdcommon.ToolError("x", ldap_code=49).bad_credentials)
        self.assertTrue(wdcommon.ToolError("x", ntstatus=0xC000006D).bad_credentials)
        self.assertTrue(wdcommon.ToolError("x", ldap_code=50).access_denied)
        self.assertFalse(wdcommon.ToolError("x").access_denied)

    def test_login_reason_plain_text(self):
        ex = wdcommon.ToolError("login refused", ldap_code=49, ad_reason="533")
        self.assertEqual(ex.login_reason("administrator"),
                         "login of 'administrator' refused: account disabled (AD code 533)")
        self.assertIn("wrong password", wdcommon.ToolError("x", ldap_code=49, ad_reason="52e").login_reason("a"))
        # unknown sub-code: shown as it is, no guess
        self.assertEqual(wdcommon.ToolError("x", ldap_code=49, ad_reason="999").login_reason("a"),
                         "login of 'a' refused (AD code 999)")


class PolicyLog(unittest.TestCase):
    def test_rename_is_logged(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["AGENT_STATE_DIR"] = tmp
            try:
                wdcommon.log_policy_change("New", "changed", "rename", {}, {}, renamed_from="Old")
                wdcommon.log_policy_change("New", "changed", "same name", {}, {}, renamed_from="New")
                log = wdcommon.read_policy_log()
                self.assertNotIn("renamed_from", log[0])
                self.assertEqual(log[1]["renamed_from"], "Old")
            finally:
                del os.environ["AGENT_STATE_DIR"]
