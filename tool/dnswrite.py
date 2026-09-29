#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Records of the internal DNS zones, read and written through the DNS
management RPC of the domain controller (the interface samba-tool dns
and the Windows DNS console use).

Runs with the session of gpowrite: the service account for reading and
writing, a domain admin once for giving the module group its rights on
a zone. The rules (what is a valid record, which nodes belong to Active
Directory and are only shown) are in dnsrules.
"""

import ldb
from samba.dcerpc import dnsp, dnsserver, security
from samba.dnsserver import AAAARecord, ARecord, CNAMERecord, MXRecord, PTRRecord, SRVRecord, TXTRecord
from samba.ndr import ndr_unpack

import dnsrules

VERSION = dnsserver.DNS_CLIENT_VERSION_LONGHORN
TYPE_NAMES = {
    dnsp.DNS_TYPE_A: "A", dnsp.DNS_TYPE_AAAA: "AAAA", dnsp.DNS_TYPE_CNAME: "CNAME", dnsp.DNS_TYPE_MX: "MX",
    dnsp.DNS_TYPE_NS: "NS", dnsp.DNS_TYPE_PTR: "PTR", dnsp.DNS_TYPE_SOA: "SOA", dnsp.DNS_TYPE_SRV: "SRV",
    dnsp.DNS_TYPE_TXT: "TXT",
}
# Rights of the module group on a zone, inherited by its nodes: create and
# delete nodes, read and write their records. Not more: no change of the
# permissions or of the owner.
ZONE_ACE = "(A;CI;CCDCLCRPWPSDRC;;;{sid})"
MAX_RECORDS = 5000


class DnsError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


class Dns:
    def __init__(self, session):
        self.s = session
        self.server = session.host
        self.conn = dnsserver.dnsserver(f"ncacn_ip_tcp:{self.server}[sign]", session.lp, session.creds)

    # ---- reading ---------------------------------------------------------
    def _zone_objects(self):
        """{zone name: (dn, sddl)} of the dnsZone objects in both DNS
        partitions."""
        out = {}
        for part in ("DomainDnsZones", "ForestDnsZones"):
            base = f"CN=MicrosoftDNS,DC={part},{self.s.domain_dn}"
            try:
                res = self.s.samdb.search(base, scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=dnsZone)",
                                          attrs=["name", "nTSecurityDescriptor"], controls=["sd_flags:1:4"])
            except ldb.LdbError:
                continue
            for r in res:
                sddl = ""
                if "nTSecurityDescriptor" in r:
                    sddl = ndr_unpack(security.descriptor, r["nTSecurityDescriptor"][0]).as_sddl(self.s.domain_sid)
                out[str(r["name"][0]).lower()] = (str(r.dn), sddl)
        return out

    def _granted(self, sddl, sid):
        """True if the zone gives the module group the rights of ZONE_ACE."""
        if not sid:
            return False
        wanted = security.descriptor.from_sddl("D:" + ZONE_ACE.format(sid=sid), self.s.domain_sid)
        return wanted.as_sddl(self.s.domain_sid)[2:].lower() in sddl.lower()

    def zones(self):
        _, res = self.conn.DnssrvComplexOperation2(VERSION, 0, self.server, None, "EnumZones",
                                                  dnsserver.DNSSRV_TYPEID_DWORD, dnsserver.DNS_ZONE_REQUEST_PRIMARY)
        objects = self._zone_objects()
        gsid = self.s.group_sid()
        out = []
        for z in res.ZoneArray:
            name = z.pszZoneName.lower()
            if name in ("..rootdnsservers", "rootdnsservers"):
                continue
            dn, sddl = objects.get(name, ("", ""))
            out.append({
                "name": name,
                "reverse": name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"),
                "ad_zone": dnsrules.is_ad_zone(name),
                "writable": bool(dn) and not dnsrules.is_ad_zone(name) and self._granted(sddl, gsid),
            })
        return sorted(out, key=lambda z: (z["reverse"], z["ad_zone"], z["name"]))

    def dc_names(self):
        res = self.s.samdb.search(self.s.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                  expression="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                                  attrs=["dNSHostName", "sAMAccountName"])
        names = []
        for r in res:
            if "dNSHostName" in r:
                names.append(str(r["dNSHostName"][0]))
            names.append(str(r["sAMAccountName"][0]).rstrip("$"))
        return names

    @staticmethod
    def _data(rec):
        t, d = rec.wType, rec.data
        if t in (dnsp.DNS_TYPE_A, dnsp.DNS_TYPE_AAAA):
            return str(d)
        if t in (dnsp.DNS_TYPE_CNAME, dnsp.DNS_TYPE_NS, dnsp.DNS_TYPE_PTR):
            return d.str.rstrip(".").lower()
        if t == dnsp.DNS_TYPE_MX:
            return f"{d.nameExchange.str.rstrip('.').lower()} {d.wPreference}"
        if t == dnsp.DNS_TYPE_SRV:
            return f"{d.nameTarget.str.rstrip('.').lower()} {d.wPort} {d.wPriority} {d.wWeight}"
        if t == dnsp.DNS_TYPE_TXT:
            return "".join(s.str for s in d.str)
        if t == dnsp.DNS_TYPE_SOA:
            return f"{d.NamePrimaryServer.str.rstrip('.')} serial {d.dwSerialNo}"
        return ""

    def _enum(self, zone, name):
        """The result of an enumeration, or None if the node does not exist.
        Callers keep the result while they read its records: the records
        are freed with it."""
        try:
            _, res = self.conn.DnssrvEnumRecords2(VERSION, 0, self.server, zone, name, None, dnsp.DNS_TYPE_ALL,
                                                  dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA, None, None)
        except Exception as ex:
            if "DNS_ERROR_NAME_DOES_NOT_EXIST" in str(ex):
                return None
            raise
        return res

    def records(self, zone):
        """Every record of the zone, flat: the node tree is walked."""
        zone = dnsrules.check_zone(zone)
        dcs = self.dc_names()
        out = []
        todo = ["@"]
        while todo:
            node = todo.pop()
            res = self._enum(zone, node)
            for i, rec in enumerate(res.rec if res else []):
                # the first entry is the node itself, the others its children
                child = rec.dnsNodeName.str.lower()
                name = node if i == 0 or not child else (child if node == "@" else f"{child}.{node}")
                if i > 0 and rec.dwChildCount:
                    todo.append(name)
                reason = dnsrules.protected(zone, name, dcs)
                for r in rec.records:
                    rtype = TYPE_NAMES.get(r.wType, str(r.wType))
                    dynamic = bool(r.dwTimeStamp)
                    out.append({
                        "name": name, "type": rtype, "data": self._data(r), "ttl": r.dwTtlSeconds,
                        "dynamic": dynamic,
                        "locked": reason or ("read_only_type" if rtype not in dnsrules.TYPES else
                                             "dynamic" if dynamic else ""),
                    })
                    if len(out) > MAX_RECORDS:
                        raise DnsError("too_many_records", zone)
        return sorted(out, key=lambda r: (r["name"] != "@", r["name"].split(".")[::-1], r["type"], r["data"]))

    def _node(self, zone, name):
        """[(type, data, dynamic)] of one node."""
        res = self._enum(zone, name)
        if not res or not res.rec:
            return []
        return [(TYPE_NAMES.get(r.wType, str(r.wType)), self._data(r), bool(r.dwTimeStamp)) for r in res.rec[0].records]

    # ---- writing ---------------------------------------------------------
    @staticmethod
    def _build(rtype, data, ttl):
        kw = {"ttl": ttl}
        if rtype == "A":
            return ARecord(data, **kw)
        if rtype == "AAAA":
            return AAAARecord(data, **kw)
        if rtype == "CNAME":
            return CNAMERecord(data, **kw)
        if rtype == "PTR":
            return PTRRecord(data, **kw)
        if rtype == "MX":
            host, pref = data.split()
            return MXRecord(host, int(pref), **kw)
        if rtype == "SRV":
            host, port, prio, weight = data.split()
            return SRVRecord(host, int(port), priority=int(prio), weight=int(weight), **kw)
        return TXTRecord(dnsrules.txt_strings(data), **kw)

    def _update(self, zone, name, add=None, delete=None):
        a = d = None
        if add is not None:
            a = dnsserver.DNS_RPC_RECORD_BUF()
            a.rec = add
        if delete is not None:
            d = dnsserver.DNS_RPC_RECORD_BUF()
            d.rec = delete
        try:
            self.conn.DnssrvUpdateRecord2(VERSION, 0, self.server, zone, name, a, d)
        except Exception as ex:
            text = str(ex)
            if "ACCESS_DENIED" in text:
                raise DnsError("access_denied", zone) from None
            if "RECORD_DOES_NOT_EXIST" in text or "NAME_DOES_NOT_EXIST" in text:
                raise DnsError("record_not_found", name) from None
            if "RECORD_ALREADY_EXISTS" in text:
                raise DnsError("record_exists", name) from None
            raise

    def _find(self, existing, rtype, data):
        for t, d, dynamic in existing:
            if t == rtype and d.lower() == data.lower():
                return t, d, dynamic
        return None

    def _pointer(self, address, host, ttl, remove=False):
        """Add or remove the PTR record of an address, if a reverse zone
        with the rights of the module exists. Returns what was done."""
        zones = [z for z in self.zones() if z["reverse"] and z["writable"]]
        where = dnsrules.reverse_node(address, [z["name"] for z in zones])
        if where is None:
            return "no_reverse_zone"
        zone, node = where
        existing = self._node(zone, node)
        found = self._find(existing, "PTR", host)
        if remove:
            if not found or found[2]:
                return "kept"
            self._update(zone, node, delete=self._build("PTR", host, ttl))
            return "removed"
        if found:
            return "present"
        self._update(zone, node, add=self._build("PTR", host, ttl))
        return "added"

    def save(self, zone, name, rtype, data, ttl, replaces=None, pointer=False):
        zone = dnsrules.check_zone(zone)
        ttl = dnsrules.check_ttl(ttl)
        if replaces:
            replaces = dnsrules.normalize(replaces["type"], replaces["data"])
        try:
            existing = self._node(zone, dnsrules.check_name(name))
            name, rtype, data = dnsrules.check_change(zone, name, rtype, data, existing, self.dc_names(), replaces)
        except dnsrules.RuleError as ex:
            raise DnsError(ex.code, str(ex)) from None
        old = None
        if replaces:
            if not self._find(existing, *replaces):
                raise DnsError("record_not_found", name)
            old = self._build(replaces[0], replaces[1], ttl)
        self._update(zone, name, add=self._build(rtype, data, ttl), delete=old)
        result = {"zone": zone, "name": name, "type": rtype, "data": data, "ttl": ttl, "pointer": ""}
        if pointer and rtype in ("A", "AAAA"):
            host = zone if name == "@" else f"{name}.{zone}"
            if replaces and replaces[0] == rtype and replaces[1] != data:
                self._pointer(replaces[1], host, ttl, remove=True)
            result["pointer"] = self._pointer(data, host, ttl)
        return result

    def delete(self, zone, name, rtype, data, pointer=False):
        zone = dnsrules.check_zone(zone)
        try:
            name = dnsrules.check_name(name)
            rtype, data = dnsrules.normalize(rtype, data)
        except dnsrules.RuleError as ex:
            raise DnsError(ex.code, str(ex)) from None
        reason = dnsrules.protected(zone, name, self.dc_names())
        if reason:
            raise DnsError("protected_" + reason, name)
        found = self._find(self._node(zone, name), rtype, data)
        if not found:
            raise DnsError("record_not_found", name)
        if found[2]:
            raise DnsError("dynamic_record", name)
        self._update(zone, name, delete=self._build(rtype, data, dnsrules.TTL_DEFAULT))
        result = {"zone": zone, "name": name, "type": rtype, "data": data, "pointer": ""}
        if pointer and rtype in ("A", "AAAA"):
            host = zone if name == "@" else f"{name}.{zone}"
            result["pointer"] = self._pointer(data, host, dnsrules.TTL_DEFAULT, remove=True)
        return result

    # ---- rights (as a domain admin) -----------------------------------------
    def delegate(self, zone, grant=True):
        """Give the module group its rights on a zone, or take them away.
        Never on the zones Active Directory keeps for itself."""
        zone = dnsrules.check_zone(zone)
        if dnsrules.is_ad_zone(zone):
            raise DnsError("protected_ad_zone", zone)
        objects = self._zone_objects()
        if zone not in objects:
            raise DnsError("zone_not_found", zone)
        gsid = self.s.group_sid()
        if not gsid:
            raise DnsError("group_missing", self.s.group_name)
        dn = objects[zone][0]
        ace = ZONE_ACE.format(sid=gsid)
        changed = self.s._add_ace(dn, ace) if grant else self.s._remove_ace(dn, ace)
        return {"zone": zone, "granted": grant, "changed": changed}


def run(session, request):
    op = request["op"]
    dns = Dns(session)
    if op == "dns_zones":
        return dns.zones()
    if op == "dns_records":
        return dns.records(request["zone"])
    if op == "dns_save":
        return dns.save(request["zone"], request["name"], request["type"], request["data"],
                        request.get("ttl", dnsrules.TTL_DEFAULT), request.get("replaces"), request.get("pointer", False))
    if op == "dns_delete":
        return dns.delete(request["zone"], request["name"], request["type"], request["data"],
                          request.get("pointer", False))
    if op == "dns_delegate":
        return dns.delegate(request["zone"], request.get("grant", True))
    raise DnsError("unknown_operation", op)
