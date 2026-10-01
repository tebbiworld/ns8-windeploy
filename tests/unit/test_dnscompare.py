#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Offline tests of the comparison with the public DNS."""

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "imageroot", "pypkg"))

import dnscompare  # noqa: E402

ZONE = "example.com"
PUBLIC = {
    ("example.com", "SOA"): (0, [("SOA", "ns.example.com. hostmaster.example.com. 1 2 3 4 5")]),
    ("www.example.com", "A"): (0, [("A", "203.0.113.10")]),
    ("invest.example.com", "CNAME"): (0, [("CNAME", "ad.example.com.")]),
    ("shop.example.com", "A"): (0, [("CNAME", "shops.example.net."), ("A", "198.51.100.7")]),
    ("multi.example.com", "A"): (0, [("A", "203.0.113.2"), ("A", "203.0.113.1")]),
    ("mail.example.com", "MX"): (0, [("MX", "10 MX1.example.com.")]),
    ("txt.example.com", "TXT"): (0, [("TXT", '"v=spf1 " "mx -all"')]),
    ("empty.example.com", "A"): (0, []),
    ("moved.example.com", "CNAME"): (0, []),
    ("moved.example.com", "A"): (0, [("A", "203.0.113.77")]),
    ("v6.example.com", "AAAA"): (0, [("AAAA", "2001:DB8:0:0::1")]),
    ("_sip._tcp.example.com", "SRV"): (0, [("SRV", "0 100 5060 Sip.example.com.")]),
}


def lookup(name, rtype):
    return PUBLIC.get((name, rtype), (3, []))


def rec(name, rtype, data, locked=""):
    return {"name": name, "type": rtype, "data": data, "ttl": 3600, "dynamic": False, "locked": locked}


class Public(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(dnscompare.normalize_public("MX", "10 MX1.Example.com."), "mx1.example.com 10")
        self.assertEqual(dnscompare.normalize_public("SRV", "0 100 5060 Sip.example.com."), "sip.example.com 5060 0 100")
        self.assertEqual(dnscompare.normalize_public("TXT", '"v=spf1 " "mx -all"'), "v=spf1 mx -all")
        self.assertEqual(dnscompare.normalize_public("TXT", '"say \\"hi\\""'), 'say "hi"')
        self.assertEqual(dnscompare.normalize_public("AAAA", "2001:DB8:0:0::1"), "2001:db8::1")
        self.assertEqual(dnscompare.normalize_public("CNAME", "Ad.Example.com."), "ad.example.com")

    def test_public_records(self):
        self.assertEqual(dnscompare.public_records("www.example.com", "A", lookup), ("records", "A", ["203.0.113.10"]))
        self.assertEqual(dnscompare.public_records("shop.example.com", "A", lookup), ("alias", "CNAME", ["shops.example.net"]))
        self.assertEqual(dnscompare.public_records("empty.example.com", "A", lookup), ("empty", "A", []))
        self.assertEqual(dnscompare.public_records("nope.example.com", "A", lookup), ("missing", "A", []))
        with self.assertRaises(dnscompare.LookupError_):
            dnscompare.public_records("x", "A", lambda n, t: (2, []))

    def test_zone(self):
        self.assertTrue(dnscompare.is_public_zone("example.com", lookup))
        self.assertFalse(dnscompare.is_public_zone("ad.example.internal", lookup))


class Compare(unittest.TestCase):
    def test_rows(self):
        records = [
            rec("www", "A", "203.0.113.10"),
            rec("invest", "CNAME", "cdn.provider.example"),
            rec("shop", "A", "10.0.0.5"),
            rec("multi", "A", "203.0.113.1"), rec("multi", "A", "203.0.113.2"),
            rec("mail", "MX", "mx1.example.com 10"),
            rec("txt", "TXT", "v=spf1 mx -all"),
            rec("v6", "AAAA", "2001:db8::1"),
            rec("_sip._tcp", "SRV", "sip.example.com 5060 0 100"),
            rec("printer", "A", "10.0.0.20"),
            rec("moved", "CNAME", "cdn.provider.example"),
            rec("empty", "A", "10.0.0.21"),
            rec("*.apps", "A", "10.0.0.30"),
            rec("dc1", "A", "10.0.0.2", locked="domain_controller"),
            rec("@", "NS", "dc1.example.com", locked="zone_root"),
        ]
        rows, skipped = dnscompare.compare(ZONE, records, lookup)
        self.assertEqual(skipped, 0)
        by = {(r["name"], r["type"]): r for r in rows}
        self.assertEqual(set(n for n, _ in by), {"www", "invest", "shop", "multi", "mail", "txt", "v6", "_sip._tcp", "printer", "empty", "moved"})
        # an alias inside, an address outside: that differs
        self.assertEqual((by[("moved", "CNAME")]["status"], by[("moved", "CNAME")]["public_type"], by[("moved", "CNAME")]["public"]),
                         ("differs", "A", ["203.0.113.77"]))
        for key in (("www", "A"), ("multi", "A"), ("mail", "MX"), ("txt", "TXT"), ("v6", "AAAA"), ("_sip._tcp", "SRV")):
            self.assertEqual(by[key]["status"], "same", key)
        self.assertEqual(by[("invest", "CNAME")]["status"], "differs")
        self.assertEqual(by[("invest", "CNAME")]["public"], ["ad.example.com"])
        self.assertEqual((by[("shop", "A")]["status"], by[("shop", "A")]["public_type"]), ("differs", "CNAME"))
        self.assertEqual(by[("printer", "A")]["status"], "internal_only")
        self.assertEqual(by[("empty", "A")]["status"], "internal_only")
        # differences first
        self.assertEqual([r["status"] for r in rows][:3], ["differs", "differs", "differs"])

    def test_limit(self):
        records = [rec(f"h{i}", "A", "10.0.0.1") for i in range(dnscompare.MAX_NAMES + 5)]
        rows, skipped = dnscompare.compare(ZONE, records, lookup)
        self.assertEqual((len(rows), skipped), (dnscompare.MAX_NAMES, 5))


class Adoption(unittest.TestCase):
    def test_same_type(self):
        node = [("CNAME", "cdn.provider.example", False)]
        self.assertEqual(dnscompare.adoption("invest", "CNAME", node, "records", "CNAME", ["ad.example.com"]),
                         ([("CNAME", "cdn.provider.example")], [("CNAME", "ad.example.com")]))

    def test_addresses(self):
        node = [("A", "10.0.0.5", False), ("A", "203.0.113.1", False), ("TXT", "note", False)]
        delete, add = dnscompare.adoption("multi", "A", node, "records", "A", ["203.0.113.1", "203.0.113.2"])
        self.assertEqual((delete, add), ([("A", "10.0.0.5")], [("A", "203.0.113.2")]))

    def test_public_alias_replaces_everything(self):
        node = [("A", "10.0.0.5", False), ("TXT", "note", False)]
        delete, add = dnscompare.adoption("shop", "A", node, "alias", "CNAME", ["shops.example.net"])
        self.assertEqual((delete, add), ([("A", "10.0.0.5"), ("TXT", "note")], [("CNAME", "shops.example.net")]))

    def test_alias_becomes_address(self):
        node = [("CNAME", "old.example.net", False)]
        delete, add = dnscompare.adoption("www", "CNAME", node, "empty", "CNAME", [])
        self.assertEqual((delete, add), ([], []))
        delete, add = dnscompare.adoption("www", "A", node, "records", "A", ["203.0.113.10"])
        self.assertEqual((delete, add), ([("CNAME", "old.example.net")], [("A", "203.0.113.10")]))

    def test_nothing_public(self):
        self.assertEqual(dnscompare.adoption("p", "A", [("A", "10.0.0.20", False)], "missing", "A", []), ([], []))


if __name__ == "__main__":
    unittest.main()
