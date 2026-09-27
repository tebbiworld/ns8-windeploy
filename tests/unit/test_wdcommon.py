#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""build_files of wdcommon: run-now tasks."""

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


if __name__ == "__main__":
    unittest.main()
