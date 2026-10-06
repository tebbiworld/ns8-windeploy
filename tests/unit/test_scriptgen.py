#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Logon and startup scripts: validation, files, password hints."""

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))

import scriptgen  # noqa: E402

LOGON = "User/Scripts/Logon/windeploy-logon.ps1"
UINI = "User/Scripts/psscripts.ini"
START = "Machine/Scripts/Startup/windeploy-startup.ps1"
MINI = "Machine/Scripts/psscripts.ini"


class Check(unittest.TestCase):
    def test_normalise(self):
        p = scriptgen.check_parts({"logon": {"script": "Write-Host 1\r\nWrite-Host 2\n\n", "cleanup": " "},
                                   "startup": {"script": ""}})
        self.assertEqual(p, {"logon": {"script": "Write-Host 1\nWrite-Host 2\n", "cleanup": ""}})

    def test_rejects(self):
        for bad in ({}, {"logon": {"script": ""}}, {"logoff": {"script": "x"}},
                    {"logon": {"script": "a\x00b"}}, {"logon": {"script": "x" * (64 * 1024 + 1)}}):
            with self.assertRaises(scriptgen.ScriptError):
                scriptgen.check_parts(bad)


class Files(unittest.TestCase):
    def test_logon_only(self):
        parts = scriptgen.check_parts({"logon": {"script": "Write-Host Ä"}})
        files, machine, user = scriptgen.build_files(parts)
        self.assertEqual(files[LOGON], b"\xef\xbb\xbf" + "Write-Host Ä\r\n".encode("utf-8"))
        self.assertEqual(files[UINI][:2], b"\xff\xfe")
        self.assertEqual(files[UINI][2:].decode("utf-16-le"),
                         "\r\n[Logon]\r\n0CmdLine=windeploy-logon.ps1\r\n0Parameters=\r\n")
        self.assertIsNone(files[START])
        self.assertIsNone(files[MINI])
        self.assertEqual(machine, "")
        self.assertIn("{40B66650-4972-11D1-A7CA-0000F87571E3}", user)

    def test_removing_runs_cleanup(self):
        parts = scriptgen.check_parts({"logon": {"script": "a", "cleanup": "b"}, "startup": {"script": "c"}})
        files, machine, user = scriptgen.build_files(parts, removing=True)
        self.assertEqual(files[LOGON], b"\xef\xbb\xbfb\r\n")
        self.assertIsNone(files[START])  # no cleanup: the startup script stops
        self.assertEqual(machine, "")
        self.assertNotEqual(user, "")


class Secrets(unittest.TestCase):
    def test_finds_password_lines(self):
        parts = {"logon": {"script": "cmdkey /add:dms /user:scanner /pass:scanner\nWrite-Host ok\n",
                           "cleanup": "$pw = ConvertTo-SecureString 'x' -AsPlainText -Force\n"}}
        self.assertEqual(scriptgen.find_secrets(parts), [("logon", "script", 1), ("logon", "cleanup", 1)])
        self.assertEqual(scriptgen.find_secrets({"logon": {"script": "Get-Credential\n"}}), [])

    def test_summary_has_no_text(self):
        s = scriptgen.summary({"logon": {"script": "secret text\n", "cleanup": ""}})
        self.assertEqual(set(s["logon"]), {"script"})
        self.assertEqual(s["logon"]["script"]["bytes"], 12)
