#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Logon rights: validation, GptTmpl.inf, application order, conflicts."""

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))

import logongen  # noqa: E402

DOM = "S-1-5-21-1000-2000-3000"
PRIVA = {"sid": DOM + "-1105", "name": "priva-user"}


class Rights(unittest.TestCase):
    def test_admins_always_kept(self):
        r = logongen.check_rights({"interactive": [PRIVA]})
        self.assertEqual([e["sid"] for e in r["interactive"]], [logongen.ADMINS, PRIVA["sid"]])

    def test_deny_never_admins(self):
        for sid in (logongen.ADMINS, DOM + "-512"):
            with self.assertRaises(logongen.LogonError):
                logongen.check_rights({"deny_interactive": [{"sid": sid}]})
        r = logongen.check_rights({"deny_interactive": [{"sid": DOM + "-501", "name": "Guest"}]})
        self.assertEqual(len(r["deny_interactive"]), 1)

    def test_rejects_bad_input(self):
        for bad in ({}, {"interactive": []}, {"logon_as_service": [PRIVA]},
                    {"interactive": [{"sid": "S-1-5-21-1-2-3-4,*S-1-1-0"}]},
                    {"interactive": [{"sid": "S-1-1-0"}]},
                    {"interactive": [{"sid": PRIVA["sid"], "name": "x\r\n[Privilege Rights]"}]}):
            with self.assertRaises(logongen.LogonError):
                logongen.check_rights(bad)

    def test_template(self):
        rights = logongen.check_rights({"interactive": [PRIVA], "remote": [{"sid": "S-1-5-32-555"}]})
        data = logongen.build_template(rights)
        self.assertEqual(data[:2], b"\xff\xfe")
        text = data[2:].decode("utf-16-le")
        self.assertIn(f"SeInteractiveLogonRight = *S-1-5-32-544,*{PRIVA['sid']}\r\n", text)
        self.assertIn("SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555\r\n", text)
        parsed = logongen.parse_privileges(text)
        self.assertEqual(parsed["SeInteractiveLogonRight"], ["S-1-5-32-544", PRIVA["sid"]])
        self.assertEqual(logongen.build_files({}), ({logongen.FILE_SECURITY: None}, ""))


def link(guid, enforced=False, disabled=False):
    return {"guid": guid, "enforced": enforced, "disabled": disabled}


OU = "OU=Laptops,DC=ad,DC=example,DC=com"
ROOT = "DC=ad,DC=example,DC=com"


class Order(unittest.TestCase):
    def test_domain_then_ou_last_link_wins(self):
        c = [{"dn": OU, "block": False, "links": [link("{A}"), link("{B}")]},
             {"dn": ROOT, "block": False, "links": [link("{D}")]}]
        self.assertEqual([g for g, _, _ in logongen.application_order(c)], ["{D}", "{A}", "{B}"])

    def test_block_and_enforced(self):
        c = [{"dn": OU, "block": True, "links": [link("{A}")]},
             {"dn": ROOT, "block": False, "links": [link("{D}"), link("{E}", enforced=True), link("{X}", disabled=True)]}]
        self.assertEqual([g for g, _, _ in logongen.application_order(c)], ["{A}", "{E}"])

    def test_conflicts(self):
        h4 = "[Privilege Rights]\r\nSeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-21-1-2-3-1105\r\n"
        c = [{"dn": OU, "block": False, "links": [link("{H4}")]},
             {"dn": ROOT, "block": False, "links": [link("{W1}"), link("{EN}", enforced=True)]}]
        gpos = {"{H4}": {"name": "H4", "template": h4}, "{W1}": {"name": "W1", "template": None},
                "{EN}": {"name": "EN", "template": h4}}
        rights = logongen.check_rights({"interactive": [PRIVA]})
        found = logongen.conflicts(c, gpos, None, rights)
        # our new link is appended after H4 in the OU: we win over H4, the enforced one wins over us
        self.assertEqual([(f["name"], f["wins"]) for f in found], [("H4", False), ("EN", True)])
        self.assertEqual(logongen.conflicts(c, gpos, None, logongen.check_rights({"remote": [PRIVA]})), [])
