#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Offline tests of the GPO generator against the working reference GPO."""

import datetime
import os
import sys
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))

import gpogen  # noqa: E402

REFERENCE_EXT = ("[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
                 "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]")


def canonical(elem):
    """Tree as nested tuples, whitespace-only text dropped."""
    text = (elem.text or "").strip()
    return (elem.tag, tuple(sorted(elem.attrib.items())), text, tuple(canonical(c) for c in elem))


class ReferenceXml(unittest.TestCase):
    def test_matches_reference(self):
        ref = ET.parse(os.path.join(HERE, "reference_ScheduledTasks.xml")).getroot()
        task = {
            "name": "Nextcloud-Update",
            "uid": "{FEBF5F91-4EF7-4201-8A90-61A080A40390}",
            "changed": datetime.datetime(2026, 9, 21, 15, 33, 16),
            "author": "EXAMPLE\\Administrator",
            "arguments": gpogen.task_arguments(
                "sysvol",
                script_unc="\\\\ad.example.com\\SYSVOL\\ad.example.com\\scripts\\softwareupdate\\nextcloud-update.ps1"),
            "schedule": {"frequency": "weekly", "days": ["Monday"], "time": "12:30", "start_date": "2026-09-21"},
            "time_limit": "PT0S",  # the reference has no limit; the module default is PT2H
        }
        gen = ET.fromstring(gpogen.build_scheduled_tasks_xml([task]).encode("utf-8"))
        self.assertEqual(canonical(gen), canonical(ref))

    def test_two_tasks_and_escaping(self):
        base = {"changed": datetime.datetime(2026, 1, 1), "author": "A&B",
                "arguments": "-x", "schedule": {"frequency": "daily", "time": "08:00",
                                                "start_date": "2026-01-01", "random_delay_minutes": 30}}
        xml = gpogen.build_scheduled_tasks_xml([dict(base, name="a", uid=gpogen.new_uid()),
                                                 dict(base, name="b", uid=gpogen.new_uid())])
        root = ET.fromstring(xml.encode())
        self.assertEqual(len(root), 2)
        self.assertEqual(root.find(".//Author").text, "A&B")
        self.assertEqual(root.find(".//RandomDelay").text, "PT30M")
        self.assertIsNotNone(root.find(".//ScheduleByDay"))

    def test_rejects_bad_input(self):
        with self.assertRaises(gpogen.GenError):
            gpogen.build_task({"name": 'x"><evil', "uid": gpogen.new_uid(), "changed": datetime.datetime.now(),
                               "arguments": "", "schedule": {}})
        with self.assertRaises(gpogen.GenError):
            gpogen.build_scheduled_tasks_xml([
                {"name": "x", "uid": gpogen.new_uid(), "changed": datetime.datetime.now(), "arguments": "",
                 "schedule": {"frequency": "weekly", "days": ["Funday"], "time": "12:00", "start_date": "2026-01-01"}}])
        with self.assertRaises(gpogen.GenError):
            gpogen.task_arguments("sysvol", script_unc='\\\\x\\a".ps1')


class Immediate(unittest.TestCase):
    def test_immediate_task(self):
        t = {"name": "windeploy now x", "uid": gpogen.new_uid(), "run_once_id": gpogen.new_uid(),
             "changed": datetime.datetime(2026, 9, 26), "author": "windeploy", "arguments": "-x"}
        root = ET.fromstring(gpogen.build_scheduled_tasks_xml([], [t]).encode())
        it = root.find("ImmediateTaskV2")
        self.assertEqual(it.find("Properties").get("runAs"), "NT AUTHORITY\\System")
        self.assertEqual(it.find("Filters/FilterRunOnce").get("id"), t["run_once_id"].upper())
        self.assertEqual(it.find(".//ExecutionTimeLimit").text, "PT2H")
        self.assertEqual(it.find(".//DeleteExpiredTaskAfter").text, "PT0S")

    def test_default_time_limit(self):
        t = {"name": "a", "uid": gpogen.new_uid(), "changed": datetime.datetime(2026, 1, 1), "arguments": "-x",
             "schedule": {"frequency": "daily", "time": "08:00", "start_date": "2026-01-01"}}
        root = ET.fromstring(gpogen.build_scheduled_tasks_xml([t]).encode())
        self.assertEqual(root.find(".//ExecutionTimeLimit").text, "PT2H")


class ExtensionNames(unittest.TestCase):
    def test_empty_gives_reference(self):
        self.assertEqual(gpogen.add_scheduled_tasks_extension(""), REFERENCE_EXT)

    def test_idempotent(self):
        self.assertEqual(gpogen.add_scheduled_tasks_extension(REFERENCE_EXT), REFERENCE_EXT)

    def test_keeps_other_extensions(self):
        registry = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{0F6B957D-509E-11D1-A7CC-0000F87571E3}]"
        out = gpogen.add_scheduled_tasks_extension(registry)
        self.assertIn(registry, out)
        self.assertEqual(gpogen.format_extension_names(gpogen.parse_extension_names(out)), out)

    def test_rejects_garbage(self):
        with self.assertRaises(gpogen.GenError):
            gpogen.parse_extension_names("[{AADCED64}")


class Version(unittest.TestCase):
    def test_bump(self):
        self.assertEqual(gpogen.bump_machine_version(16), 17)
        self.assertEqual(gpogen.bump_machine_version((3 << 16) | 5), (3 << 16) | 6)
        self.assertEqual(gpogen.bump_machine_version((2 << 16) | 0xFFFF), (2 << 16) | 1)


class GptIni(unittest.TestCase):
    def test_reference_bytes(self):
        # GPT.INI of the reference GPO, byte for byte (cat -A, 67 bytes)
        ref = b"[General]\r\nVersion=16\r\ndisplayName=Neues Gruppenrichtlinienobjekt\r\n"
        self.assertEqual(len(ref), 67)
        self.assertEqual(gpogen.build_gpt_ini(16, "Neues Gruppenrichtlinienobjekt").encode("utf-8"), ref)


class Script(unittest.TestCase):
    def test_script(self):
        s = gpogen.build_script("Nextcloud.NextcloudDesktop")
        self.assertIn("$PackageId = 'Nextcloud.NextcloudDesktop'", s)
        self.assertNotIn("\n", s.replace("\r\n", ""))
        self.assertTrue(gpogen.script_bytes(s).startswith(b"\xef\xbb\xbf"))
        self.assertIn("windeploy-Nextcloud.NextcloudDesktop.log", s)

    def test_rejects_injection(self):
        for bad in ["a'; Remove-Item C:\\ -Recurse; '", "a b", "$(x)", "..\\x"]:
            with self.assertRaises(gpogen.GenError):
                gpogen.build_script(bad)

    def test_embedded_roundtrip(self):
        import base64
        s = gpogen.build_script("7zip.7zip", mode="install")
        enc = gpogen.task_arguments("embedded", script_text=s).split()[-1]
        self.assertEqual(base64.b64decode(enc).decode("utf-16-le"), gpogen.compact_script(s))
        self.assertNotIn("# ", gpogen.compact_script(s))
        self.assertLess(len(gpogen.task_arguments("embedded", script_text=s)), 8000)


if __name__ == "__main__":
    unittest.main()
