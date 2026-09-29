#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Offline tests of the DNS rules."""

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))

import dnsrules  # noqa: E402

ZONE = "ad.example.com"
DCS = ["dc1.ad.example.com", "DC2"]


class Input(unittest.TestCase):
    def test_names(self):
        self.assertEqual(dnsrules.check_name(""), "@")
        self.assertEqual(dnsrules.check_name("Printer-1."), "printer-1")
        self.assertEqual(dnsrules.check_name("*.apps"), "*.apps")
        self.assertEqual(dnsrules.check_name("_acme-challenge.www"), "_acme-challenge.www")
        for bad in ("a b", "a..b", "-x", "x-", "a.*.b", "ä", "x" * 64, "a;b", "a\nb"):
            with self.assertRaises(dnsrules.RuleError, msg=bad):
                dnsrules.check_name(bad)

    def test_data(self):
        self.assertEqual(dnsrules.normalize("a", " 192.168.001.10 ".replace("001", "1")), ("A", "192.168.1.10"))
        self.assertEqual(dnsrules.normalize("AAAA", "FD00:0:0:0::1"), ("AAAA", "fd00::1"))
        self.assertEqual(dnsrules.normalize("CNAME", "Host.Example.COM."), ("CNAME", "host.example.com"))
        self.assertEqual(dnsrules.normalize("MX", "mail.example.com 010"), ("MX", "mail.example.com 10"))
        self.assertEqual(dnsrules.normalize("SRV", "sip.example.com 5060 0 100"), ("SRV", "sip.example.com 5060 0 100"))
        self.assertEqual(dnsrules.normalize("TXT", 'v=spf1 mx "-all"'), ("TXT", 'v=spf1 mx "-all"'))
        for rtype, bad in (("A", "fd00::1"), ("A", "1.2.3"), ("A", "1.2.3.4; rm"), ("AAAA", "1.2.3.4"),
                           ("CNAME", "1.2.3.4"), ("CNAME", "a b"), ("CNAME", "under_score.example.com"),
                           ("MX", "mail.example.com"), ("MX", "mail.example.com 70000"), ("SRV", "h 0 0 0"),
                           ("SRV", "h 5060 0"), ("TXT", ""), ("TXT", "a\nb"), ("TXT", "x" * 2001),
                           ("NS", "ns.example.com"), ("SOA", "x"), ("HTTPS", "x")):
            with self.assertRaises(dnsrules.RuleError, msg=f"{rtype} {bad!r}"):
                dnsrules.normalize(rtype, bad)

    def test_ttl(self):
        self.assertEqual(dnsrules.check_ttl(900), 900)
        for bad in (0, 59, 604801, "900", True, None):
            with self.assertRaises(dnsrules.RuleError):
                dnsrules.check_ttl(bad)

    def test_txt_strings(self):
        self.assertEqual(dnsrules.txt_strings("abc"), ["abc"])
        parts = dnsrules.txt_strings("ä" * 300)
        self.assertEqual("".join(parts), "ä" * 300)
        self.assertTrue(all(len(p.encode()) <= 255 for p in parts))


class Protection(unittest.TestCase):
    def test_protected(self):
        for name in ("@", "_tcp", "_ldap._tcp", "_kerberos._udp", "_msdcs", "_sites",
                     "_ldap._tcp.default-first-site-name._sites", "DomainDnsZones", "_ldap._tcp.forestdnszones",
                     "gc", "dc1", "DC2", "dc1.ad.example.com"):
            self.assertIsNotNone(dnsrules.protected(ZONE, name, DCS), name)
        for name in ("printer", "www", "*.apps", "_acme-challenge.www", "dc10", "gc2", "tcp",
                     "_sip._tcp", "_sip._tcp.phones", "_ldap._tcp.phones", "_minecraft._tcp.games"):
            self.assertIsNone(dnsrules.protected(ZONE, name, DCS), name)
        self.assertEqual(dnsrules.protected("_msdcs.ad.example.com", "anything"), "ad_zone")

    def test_change(self):
        self.assertEqual(dnsrules.check_change(ZONE, "Printer", "a", "10.0.0.5", []), ("printer", "A", "10.0.0.5"))
        cases = [
            ("dc1", "A", "10.0.0.9", [], None, "protected_domain_controller"),
            ("_tcp", "TXT", "x", [], None, "protected_ad_node"),
            ("@", "TXT", "x", [], None, "protected_zone_root"),
            ("p", "A", "10.0.0.5", [("A", "10.0.0.5", False)], None, "record_exists"),
            ("p", "CNAME", "q.example.com", [("A", "10.0.0.5", False)], None, "cname_not_alone"),
            ("p", "A", "10.0.0.5", [("CNAME", "q.example.com", False)], None, "cname_present"),
            ("p", "PTR", "q.example.com", [], None, "ptr_needs_reverse_zone"),
            ("p", "A", "10.0.0.6", [("A", "10.0.0.5", True)], ("A", "10.0.0.5"), "dynamic_record"),
        ]
        for name, rtype, data, existing, replaces, code in cases:
            with self.assertRaises(dnsrules.RuleError, msg=code) as ctx:
                dnsrules.check_change(ZONE, name, rtype, data, existing, DCS, replaces)
            self.assertEqual(ctx.exception.code, code)
        # changing a record to a CNAME is fine when it was the only one
        dnsrules.check_change(ZONE, "p", "CNAME", "q.example.com", [("A", "10.0.0.5", False)], DCS, ("A", "10.0.0.5"))
        with self.assertRaises(dnsrules.RuleError):
            dnsrules.check_change("0.0.10.in-addr.arpa", "5", "A", "10.0.0.5", [])
        dnsrules.check_change("0.0.10.in-addr.arpa", "5", "PTR", "p.ad.example.com", [])


class Reverse(unittest.TestCase):
    def test_reverse_node(self):
        zones = ["ad.example.com", "10.in-addr.arpa", "0.0.10.in-addr.arpa"]
        self.assertEqual(dnsrules.reverse_node("10.0.0.5", zones), ("0.0.10.in-addr.arpa", "5"))
        self.assertEqual(dnsrules.reverse_node("10.1.2.3", zones), ("10.in-addr.arpa", "3.2.1"))
        self.assertIsNone(dnsrules.reverse_node("192.168.1.1", zones))


if __name__ == "__main__":
    unittest.main()
