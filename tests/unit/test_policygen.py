#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Offline tests of the policy generator."""

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))

import policygen  # noqa: E402

ON = {"state": "on"}


class Catalog(unittest.TestCase):
    def test_every_setting_builds(self):
        for sid, spec in policygen.CATALOG.items():
            params = {"caption": "Notice", "text": "Authorised use only"} if sid == "logon_banner" else {}
            settings = {sid: {"state": "on", "params": params}}
            for needed in spec.get("requires", []):
                settings[needed] = {"state": "on"}
            files, ext = policygen.build_files(settings)
            self.assertTrue(any(v is not None for v in files.values()), sid)
            self.assertRegex(ext, r"^(\[\{[0-9A-F-]{36}\}\{[0-9A-F-]{36}\}\])+$")
            self.assertIn(spec["group"], policygen.GROUPS)
            for other in spec.get("excludes", []):
                self.assertIn(sid, policygen.CATALOG[other]["excludes"])

    def test_catalog_hides_registry_details(self):
        for entry in policygen.catalog():
            self.assertEqual(set(entry), {"id", "group", "risk", "tattoo", "params", "excludes", "requires"})

    def test_tattoo(self):
        self.assertFalse(policygen.is_tattoo("session_lock"))
        self.assertFalse(policygen.is_tattoo("usb_block"))
        # measured: removed or restored by Windows when the GPO is gone
        for sid in ("usb_bitlocker_write", "time_change_admins_only", "timezone_change_admins_only"):
            self.assertFalse(policygen.is_tattoo(sid), sid)
        for sid in ("ntlmv2_only", "audit_extended"):
            self.assertTrue(policygen.is_tattoo(sid), sid)
        # a value outside the policy keys is reset or kept on purpose
        for sid, spec in policygen.CATALOG.items():
            outside = {(k, n) for k, n, _, _ in spec.get("reg", []) if not policygen.POLICY_KEY_RE.match(k)}
            self.assertEqual(outside, set(spec.get("reg_reset", [])) | set(spec.get("reg_keep", [])), sid)


class RegistryPol(unittest.TestCase):
    def test_roundtrip(self):
        settings = policygen.check_settings({
            "session_lock": {"state": "on", "params": {"seconds": 180}},
            "logon_banner": {"state": "on", "params": {"caption": "Hinweis; [Test]", "text": "Nur für Befugte"}},
            "bitlocker_policy": ON,
        })
        data = policygen.build_registry_pol(settings)
        self.assertEqual(data[:8], b"PReg\x01\x00\x00\x00")
        entries = policygen.parse_registry_pol(data)
        self.assertIn((policygen.SYSTEM, "InactivityTimeoutSecs", 4, 180), entries)
        self.assertIn((policygen.SYSTEM, "legalnoticecaption", 1, "Hinweis; [Test]"), entries)
        self.assertIn((policygen.SYSTEM, "legalnoticetext", 1, "Nur für Befugte"), entries)
        self.assertIn((policygen.FVE, "EncryptionMethodWithXtsOs", 4, 7), entries)
        self.assertIn((policygen.FVE, "OSRequireActiveDirectoryBackup", 4, 1), entries)

    def test_bytes_of_one_entry(self):
        # [key;value;type;size;data] in UTF-16LE, as MS-GPREG describes it
        data = policygen.build_registry_pol(policygen.check_settings({"hide_last_user": ON}))
        expected = (b"PReg\x01\x00\x00\x00" + "[".encode("utf-16-le")
                    + (policygen.SYSTEM + "\0").encode("utf-16-le") + ";".encode("utf-16-le")
                    + "dontdisplaylastusername\0".encode("utf-16-le") + ";".encode("utf-16-le")
                    + b"\x04\x00\x00\x00" + ";".encode("utf-16-le") + b"\x04\x00\x00\x00" + ";".encode("utf-16-le")
                    + b"\x01\x00\x00\x00" + "]".encode("utf-16-le"))
        self.assertEqual(data, expected)

    def test_reset_deletes_values_outside_the_policy_keys(self):
        data = policygen.build_registry_pol(policygen.check_settings({"ntlmv2_only": {"state": "reset"}}))
        self.assertEqual(policygen.parse_registry_pol(data),
                         [("System\\CurrentControlSet\\Control\\Lsa", "**del.LmCompatibilityLevel", 1, " ")])


class SecurityTemplate(unittest.TestCase):
    def test_rights(self):
        data = policygen.build_security_template(policygen.check_settings(
            {"timezone_change_admins_only": ON, "time_change_admins_only": ON}))
        self.assertEqual(data[:2], b"\xff\xfe")
        self.assertEqual(data[2:].decode("utf-16-le"),
                         '[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature="$CHICAGO$"\r\nRevision=1\r\n'
                         "[Privilege Rights]\r\n"
                         "SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544\r\n"
                         "SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544\r\n")
        self.assertIsNone(policygen.build_security_template(policygen.check_settings({"session_lock": ON})))


class Audit(unittest.TestCase):
    def test_script(self):
        on = policygen.build_audit_script(policygen.check_settings({"audit_extended": ON}))
        self.assertIn("/subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable", on)
        self.assertIn("/subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable /failure:disable", on)
        reset = policygen.build_audit_script(policygen.check_settings({"audit_extended": {"state": "reset"}}))
        # back to what a fresh Windows audits, never to nothing at all
        self.assertIn("/subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable", reset)
        self.assertIn("/subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:disable /failure:disable", reset)
        self.assertIsNone(policygen.build_audit_script(policygen.check_settings({"session_lock": ON})))

    def test_task(self):
        import xml.etree.ElementTree as ET
        uid = "{11111111-2222-3333-4444-555555555555}"
        files, ext = policygen.build_files({"audit_extended": ON}, task_uid=uid)
        root = ET.fromstring(files[policygen.FILE_TASKS].decode("utf-8").split("?>", 1)[1])
        task = root.find("TaskV2")
        self.assertEqual((task.get("name"), task.get("uid"), task.get("removePolicy")), ("windeploy policy audit", uid, "1"))
        self.assertIsNotNone(task.find(".//RegistrationTrigger"))
        self.assertIn("-EncodedCommand ", task.find(".//Arguments").text)
        self.assertNotIn("audit.csv", " ".join(files))
        self.assertEqual(ext, "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
                              "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
                              "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]")


class Profile(unittest.TestCase):
    def test_files_and_extensions(self):
        files, ext = policygen.build_files({"session_lock": ON})
        self.assertIsNotNone(files[policygen.FILE_REGISTRY])
        self.assertIsNone(files[policygen.FILE_SECURITY])
        self.assertIsNone(files[policygen.FILE_TASKS])
        self.assertEqual(ext, "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]")
        _, ext = policygen.build_files({"session_lock": ON, "time_change_admins_only": ON})
        self.assertEqual(ext, "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
                              "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]")

    def test_bad_input(self):
        for bad in ({"nope": ON},
                    {"session_lock": {"state": "on", "params": {"seconds": 5}}},
                    {"session_lock": {"state": "on", "params": {"seconds": True}}},
                    {"session_lock": {"state": "on", "params": {"minutes": 3}}},
                    {"session_lock": {"state": "reset"}},
                    {"session_lock": {"state": "off"}},
                    {"logon_banner": ON},
                    {"bitlocker_policy": {"state": "on", "params": {"method": "rot13"}}},
                    {"usb_block": ON, "usb_bitlocker_write": ON}):
            with self.assertRaises(policygen.PolicyError, msg=str(bad)):
                policygen.build_files(bad)

    def test_after_removal(self):
        settings = policygen.check_settings({"session_lock": ON, "ntlmv2_only": ON, "hide_last_user": ON})
        left = policygen.after_removal(settings, ["session_lock", "ntlmv2_only"])
        self.assertEqual(set(left), {"ntlmv2_only", "hide_last_user"})
        self.assertEqual(left["ntlmv2_only"]["state"], "reset")


if __name__ == "__main__":
    unittest.main()


class PinLogon(unittest.TestCase):
    def test_registry_value(self):
        files, ext = policygen.build_files({"domain_pin_logon": {"state": "on", "params": {}}})
        entries = policygen.parse_registry_pol(files[policygen.FILE_REGISTRY])
        self.assertIn(("Software\\Policies\\Microsoft\\Windows\\System", "AllowDomainPINLogon"),
                      [(e[0], e[1]) for e in entries])
        self.assertFalse(policygen.is_tattoo("domain_pin_logon"))
        self.assertEqual(policygen.CATALOG["domain_pin_logon"]["risk"], 2)


class DisplayRequests(unittest.TestCase):
    LOCK = {"session_lock": {"state": "on", "params": {"seconds": 300}}}

    def overrides(self, processes=None, services=None, state="on", cleanup=None):
        params = {}
        if processes is not None:
            params["processes"] = processes
        if services is not None:
            params["services"] = services
        entry = {"state": state, "params": params}
        if cleanup:
            entry["cleanup"] = cleanup
        return dict(self.LOCK, display_request_overrides=entry)

    def script(self, settings):
        return policygen.build_power_script(policygen.check_settings(settings))

    def test_defaults(self):
        s = policygen.check_settings(self.overrides())
        self.assertEqual(s["display_request_overrides"]["params"]["processes"],
                         ["AnyDesk.exe", "RustDesk.exe", "TeamViewer.exe"])
        self.assertEqual(s["display_request_overrides"]["params"]["services"], [])

    def test_names_are_allowlisted(self):
        bad = ["a b.exe", "x.exe'; Remove-Item C:\\ -Recurse #.exe", "..\\evil.exe", "evil", "evil.exe\n",
               "$(calc).exe", "a\"b.exe", "", "x" * 61 + ".exe", 5]
        for name in bad:
            with self.assertRaises(policygen.PolicyError, msg=repr(name)):
                policygen.check_settings(self.overrides([name]))
        for name in ("evil service", "svc;calc", "svc'x", "a/b"):
            with self.assertRaises(policygen.PolicyError, msg=repr(name)):
                policygen.check_settings(self.overrides(services=[name]))
        with self.assertRaises(policygen.PolicyError):
            policygen.check_settings(self.overrides(["a%d.exe" % i for i in range(policygen.LIST_MAX + 1)]))
        with self.assertRaises(policygen.PolicyError):
            policygen.check_settings(self.overrides("AnyDesk.exe"))

    def test_duplicates_dropped(self):
        s = policygen.check_settings(self.overrides(["vncviewer.exe", "VNCViewer.EXE", "winvnc.exe"]))
        self.assertEqual(s["display_request_overrides"]["params"]["processes"], ["vncviewer.exe", "winvnc.exe"])

    def test_script_sets_display_only(self):
        text = self.script(self.overrides(["RustDesk.exe"], ["TermService"]))
        self.assertIn("& powercfg.exe /requestsoverride PROCESS 'RustDesk.exe' DISPLAY | Out-Null", text)
        self.assertIn("& powercfg.exe /requestsoverride SERVICE 'TermService' DISPLAY | Out-Null", text)
        self.assertNotIn("SYSTEM", text)
        self.assertTrue(text.endswith("exit $failed\r\n"))

    def test_task_in_gpo(self):
        files, ext = policygen.build_files(self.overrides(), task_uid="{11111111-1111-1111-1111-111111111111}",
                                           power_task_uid="{22222222-2222-2222-2222-222222222222}")
        xml = files[policygen.FILE_TASKS].decode()
        self.assertIn(policygen.POWER_TASK, xml)
        self.assertIn("{22222222-2222-2222-2222-222222222222}", xml)
        self.assertNotIn(policygen.AUDIT_TASK, xml)
        self.assertIn("removePolicy=\"1\"", xml)

    def test_requires_session_lock(self):
        for sid in ("display_request_overrides", "display_requests_ignore_all"):
            with self.assertRaises(policygen.PolicyError, msg=sid):
                policygen.check_settings({sid: {"state": "on"}})
        # the reset state removes the names also without the lock
        policygen.check_settings({"display_request_overrides": {"state": "reset", "params": {}}})

    def test_removed_names_are_cleaned_up(self):
        before = policygen.check_settings(self.overrides(["AnyDesk.exe", "RustDesk.exe"], ["TermService"]))
        after = policygen.check_settings(self.overrides(["rustdesk.exe"]))
        merged = policygen.check_settings(policygen.carry_cleanup(before, after))
        self.assertEqual(merged["display_request_overrides"]["cleanup"],
                         {"process": ["AnyDesk.exe"], "service": ["TermService"]})
        text = policygen.build_power_script(merged)
        self.assertIn("PROCESS 'AnyDesk.exe' | Out-Null", text)
        self.assertIn("SERVICE 'TermService' | Out-Null", text)
        self.assertIn("PROCESS 'rustdesk.exe' DISPLAY", text)
        self.assertNotIn("PROCESS 'RustDesk.exe' | Out-Null", text)
        # removals run before the names that are set
        self.assertLess(text.index("'AnyDesk.exe' |"), text.index("'rustdesk.exe' DISPLAY"))
        # a name set again leaves the cleanup list
        again = policygen.carry_cleanup(merged, policygen.check_settings(self.overrides(["AnyDesk.exe"])))
        self.assertEqual(again["display_request_overrides"]["cleanup"]["process"], ["rustdesk.exe"])

    def test_switched_off_removes_everything(self):
        before = policygen.check_settings(self.overrides(["AnyDesk.exe"], cleanup={"process": ["old.exe"]}))
        reset = policygen.after_removal(before, ["display_request_overrides", "session_lock"])
        self.assertNotIn("session_lock", reset)
        merged = policygen.check_settings(policygen.carry_cleanup(before, reset))
        self.assertEqual(merged["display_request_overrides"]["state"], "reset")
        text = policygen.build_power_script(merged)
        self.assertNotIn("DISPLAY", text)
        self.assertEqual(text.count("'AnyDesk.exe'"), 1)
        self.assertIn("PROCESS 'old.exe' | Out-Null", text)

    def test_ignore_all_is_a_policy_value(self):
        files, _ = policygen.build_files(dict(self.LOCK, display_requests_ignore_all=ON))
        entries = policygen.parse_registry_pol(files[policygen.FILE_REGISTRY])
        keys = {(k.lower(), n) for k, n, *_ in entries}
        key = policygen.ALLOW_DISPLAY.lower()
        self.assertIn((key, "ACSettingIndex"), keys)
        self.assertIn((key, "DCSettingIndex"), keys)
        self.assertTrue(policygen.POLICY_KEY_RE.match(policygen.ALLOW_DISPLAY))
        self.assertFalse(policygen.is_tattoo("display_requests_ignore_all"))
        self.assertIsNone(files[policygen.FILE_TASKS])
