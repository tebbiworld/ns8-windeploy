#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Rules for the records of the internal DNS zones, without touching AD.

Used twice: by the actions to refuse bad input early, and by the samba
runtime (tool/dnswrite.py), which enforces them. The rights given to the
module group on a zone also cover the records Active Directory needs
(measured: the service account could change the record of the DC), so
the protection is here and not in the ACL.
"""

import ipaddress
import re

TYPES = ("A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT")
# shown, never changed
READ_ONLY_TYPES = ("SOA", "NS")

TTL_MIN, TTL_MAX, TTL_DEFAULT = 60, 604800, 3600
LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# Nodes Active Directory keeps its own records in. Below _tcp and _udp
# other services may live (_sip._tcp), only the ones of AD are locked.
AD_NODES = ("_msdcs", "_sites", "domaindnszones", "forestdnszones", "gc")
AD_SERVICES = ("_ldap", "_kerberos", "_kpasswd", "_gc")


class RuleError(ValueError):
    """code is a key of the UI translations."""

    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def check_zone(zone):
    zone = str(zone).strip().rstrip(".").lower()
    labels = zone.split(".")
    if not zone or len(zone) > 253 or not all(LABEL_RE.match(x) for x in labels):
        raise RuleError("invalid_zone", zone)
    return zone


def check_name(name):
    """Name of a node relative to its zone, "@" for the zone itself. A
    wildcard is the single label "*" at the left."""
    name = str(name).strip().rstrip(".").lower() or "@"
    if name == "@":
        return name
    labels = name.split(".")
    if labels[0] == "*":
        labels = labels[1:]
    if len(name) > 253 or not all(LABEL_RE.match(x) for x in labels):
        raise RuleError("invalid_name", name)
    return name


def check_host(value):
    """A host name as the target of CNAME, MX, SRV or PTR (no address)."""
    host = str(value).strip().rstrip(".").lower()
    labels = host.split(".")
    if not host or len(host) > 253 or not all(HOST_LABEL_RE.match(x) for x in labels) or labels[-1].isdigit():
        raise RuleError("invalid_host", str(value))
    return host


def check_ttl(ttl):
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not TTL_MIN <= ttl <= TTL_MAX:
        raise RuleError("invalid_ttl", str(ttl))
    return ttl


def _number(value, low, high, code):
    try:
        n = int(str(value), 10)
    except ValueError:
        raise RuleError(code, str(value)) from None
    if not low <= n <= high:
        raise RuleError(code, str(value))
    return n


def normalize(rtype, data):
    """One spelling for the data of a record, as the UI shows it:
    A/AAAA address; CNAME/PTR host; MX "host preference";
    SRV "host port priority weight"; TXT the text."""
    rtype = str(rtype).upper()
    if rtype not in TYPES:
        raise RuleError("invalid_type", rtype)
    data = str(data).strip()
    if rtype in ("A", "AAAA"):
        try:
            ip = ipaddress.ip_address(data)
        except ValueError:
            raise RuleError("invalid_address", data) from None
        if ip.version != (4 if rtype == "A" else 6):
            raise RuleError("invalid_address", data)
        return rtype, str(ip)
    if rtype in ("CNAME", "PTR"):
        return rtype, check_host(data)
    if rtype == "MX":
        parts = data.split()
        if len(parts) != 2:
            raise RuleError("invalid_mx", data)
        return rtype, f"{check_host(parts[0])} {_number(parts[1], 0, 65535, 'invalid_mx')}"
    if rtype == "SRV":
        parts = data.split()
        if len(parts) != 4:
            raise RuleError("invalid_srv", data)
        port = _number(parts[1], 1, 65535, "invalid_srv")
        prio = _number(parts[2], 0, 65535, "invalid_srv")
        weight = _number(parts[3], 0, 65535, "invalid_srv")
        return rtype, f"{check_host(parts[0])} {port} {prio} {weight}"
    # TXT: printable text, stored in strings of at most 255 bytes
    if not data or len(data.encode("utf-8")) > 2000 or any(ord(c) < 32 or ord(c) == 127 for c in data):
        raise RuleError("invalid_txt", data[:40])
    return rtype, data


def txt_strings(text):
    """A TXT value as character strings of at most 255 bytes each."""
    raw = text.encode("utf-8")
    out = []
    while raw:
        cut = raw[:255]
        # do not split inside a UTF-8 sequence
        while len(cut) < len(raw) and (raw[len(cut)] & 0xC0) == 0x80:
            cut = cut[:-1]
        out.append(cut.decode("utf-8"))
        raw = raw[len(cut):]
    return out


def is_ad_zone(zone):
    zone = zone.lower().rstrip(".")
    return zone.startswith("_msdcs.") or zone in ("rootdnsservers", "..rootdnsservers", ".", "")


def protected(zone, name, dc_names=()):
    """Reason why the records of a node are only shown, or None.
    dc_names: host names of the domain controllers (short or full)."""
    if is_ad_zone(zone):
        return "ad_zone"
    name = name.lower()
    if name == "@":
        return "zone_root"
    labels = name.split(".")
    if labels[-1] in AD_NODES:
        return "ad_node"
    if labels[-1] in ("_tcp", "_udp") and (len(labels) == 1 or labels[0] in AD_SERVICES):
        return "ad_node"
    full = f"{name}.{zone.lower()}"
    for dc in dc_names:
        dc = dc.lower().rstrip(".")
        if dc and (name == dc or full == dc or name == dc.split(".")[0] and dc.endswith("." + zone.lower())):
            return "domain_controller"
    return None


def check_change(zone, name, rtype, data, existing, dc_names=(), replaces=None):
    """Validate a record to add. existing: [(type, data, dynamic)] of the
    node; replaces: (type, data) of the record that is changed. Returns
    (name, type, data)."""
    zone = check_zone(zone)
    name = check_name(name)
    rtype, data = normalize(rtype, data)
    reason = protected(zone, name, dc_names)
    if reason:
        raise RuleError("protected_" + reason, name)
    is_reverse = zone.endswith(".in-addr.arpa") or zone.endswith(".ip6.arpa")
    if rtype == "PTR" and not is_reverse:
        raise RuleError("ptr_needs_reverse_zone", zone)
    if is_reverse and rtype not in ("PTR", "TXT", "CNAME"):
        raise RuleError("reverse_zone_type", rtype)
    others = [(t, d) for t, d, _ in existing if (t, d) != tuple(replaces or ())]
    if any(dyn for t, d, dyn in existing if (t, d) == tuple(replaces or ())):
        raise RuleError("dynamic_record", name)
    if (rtype, data) in others:
        raise RuleError("record_exists", data)
    if rtype == "CNAME" and others:
        raise RuleError("cname_not_alone", name)
    if rtype != "CNAME" and any(t == "CNAME" for t, _ in others):
        raise RuleError("cname_present", name)
    return name, rtype, data


def reverse_node(address, zones):
    """(zone, node) where the PTR record of an address belongs, among the
    given zone names, or None. The longest matching zone wins."""
    ip = ipaddress.ip_address(address)
    full = ip.reverse_pointer.lower()
    best = None
    for zone in zones:
        z = zone.lower().rstrip(".")
        if full.endswith("." + z) and (best is None or len(z) > len(best)):
            best = z
    if best is None:
        return None
    return best, full[:-(len(best) + 1)]


# ------------------------------------------------------------------ zones ---

def reverse_zone(network):
    """Name of the reverse zone of a network, e.g. 192.168.1.0/24 ->
    1.168.192.in-addr.arpa. IPv4 networks end on a byte (/8, /16, /24),
    IPv6 networks on a nibble (/4 ... /124), as reverse zones do."""
    try:
        net = ipaddress.ip_network(str(network).strip(), strict=False)
    except ValueError:
        raise RuleError("invalid_network", str(network)) from None
    step = 8 if net.version == 4 else 4
    low, high = (8, 24) if net.version == 4 else (16, 124)
    if net.prefixlen % step or not low <= net.prefixlen <= high:
        raise RuleError("invalid_prefix", str(network))
    labels = net.network_address.reverse_pointer.split(".")
    keep = net.prefixlen // step
    return ".".join(labels[len(labels) - 2 - keep:])


def check_new_zone(zone, existing, realm=""):
    """Name of a zone to create. existing: names of the zones there are;
    realm: DNS name of the domain."""
    zone = check_zone(zone)
    labels = zone.split(".")
    if len(labels) < 2:
        raise RuleError("zone_single_label", zone)
    if any(x.startswith("_") for x in labels) or is_ad_zone(zone):
        raise RuleError("protected_ad_zone", zone)
    if zone.endswith(".arpa") and not (zone.endswith(".in-addr.arpa") or zone.endswith(".ip6.arpa")):
        raise RuleError("invalid_zone", zone)
    if zone in (z.lower() for z in existing):
        raise RuleError("zone_exists", zone)
    realm = realm.lower().rstrip(".")
    if realm and realm.endswith("." + zone):
        # the domain would become a part of the new zone without a delegation
        raise RuleError("zone_above_domain", zone)
    return zone


def zone_locked(zone, realm):
    """Reason why a zone is never deleted, or None: the zones Active
    Directory lives in."""
    zone = zone.lower().rstrip(".")
    realm = realm.lower().rstrip(".")
    if is_ad_zone(zone):
        return "ad_zone"
    if realm and zone == realm:
        return "domain_zone"
    return None
