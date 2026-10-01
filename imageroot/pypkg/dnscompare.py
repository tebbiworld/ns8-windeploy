#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Compare the records of an internal zone with the public DNS.

An internal zone answers for its whole name: a record changed at the
public DNS provider keeps its old value for everybody who asks the
domain controller, until the internal record is changed as well. This
module finds such records.

The public side is asked over DNS over HTTPS (JSON), not over port 53:
routers often redirect plain DNS to the internal server, which would
compare the zone with itself. The names of the zone are sent to the
public resolver; the page says so before it asks.
"""

import json
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

RESOLVERS = (
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Google", "https://dns.google/resolve"),
)
TYPE_NUMBERS = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
TYPE_NAMES = {v: k for k, v in TYPE_NUMBERS.items()}
# the types that are compared; PTR lives in reverse zones, which are not public
COMPARED = ("A", "AAAA", "CNAME", "MX", "SRV", "TXT")
MAX_NAMES = 400
NXDOMAIN = 3


class LookupError_(Exception):
    pass


def _fetch(url, name, rtype, timeout):
    query = urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(f"{url}?{query}", headers={"Accept": "application/dns-json",
                                                         "User-Agent": "ns8-windeploy"})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.load(res)


def doh_lookup(name, rtype, timeout=8):
    """(status, [(type, data)]) from the first resolver that answers."""
    last = None
    for _, url in RESOLVERS:
        try:
            data = _fetch(url, name, rtype, timeout)
            return int(data.get("Status", 2)), [(TYPE_NAMES.get(a.get("type"), str(a.get("type"))), str(a.get("data", "")))
                                                for a in data.get("Answer") or []]
        except Exception as ex:
            last = ex
    raise LookupError_(f"no public resolver reachable: {last}")


def _unquote_txt(data):
    """'"abc" "def"' -> 'abcdef' (the strings of one TXT record)."""
    out, cur, inside, i = [], "", False, 0
    while i < len(data):
        c = data[i]
        if c == "\\" and i + 1 < len(data):
            cur += data[i + 1]
            i += 2
            continue
        if c == '"':
            if inside:
                out.append(cur)
                cur = ""
            inside = not inside
        elif inside:
            cur += c
        i += 1
    return "".join(out) if out else data


def normalize_public(rtype, data):
    """The data of a public answer in the spelling of dnsrules.normalize."""
    data = data.strip()
    if rtype in ("CNAME", "NS"):
        return data.rstrip(".").lower()
    if rtype == "MX":
        pref, _, host = data.partition(" ")
        return f"{host.rstrip('.').lower()} {int(pref)}"
    if rtype == "SRV":
        prio, weight, port, host = data.split()
        return f"{host.rstrip('.').lower()} {int(port)} {int(prio)} {int(weight)}"
    if rtype == "TXT":
        return _unquote_txt(data)
    if rtype == "AAAA":
        import ipaddress
        return str(ipaddress.ip_address(data))
    return data


def public_records(name, rtype, lookup=doh_lookup):
    """What the public DNS says for name and type: (kind, type, values).

    kind "missing": the name does not exist; "empty": it exists without
    such records; "records": values of the asked type; "alias": the name
    is a CNAME in the public DNS (type is then "CNAME")."""
    status, answers = lookup(name, rtype)
    if status == NXDOMAIN:
        return "missing", rtype, []
    if status != 0:
        raise LookupError_(f"public DNS answered {name} {rtype} with status {status}")
    own = [d for t, d in answers if t == rtype]
    if rtype != "CNAME" and answers and answers[0][0] == "CNAME":
        return "alias", "CNAME", [normalize_public("CNAME", answers[0][1])]
    if not own:
        return "empty", rtype, []
    return "records", rtype, sorted({normalize_public(rtype, d) for d in own})


def public_view(name, rtype, lookup=doh_lookup):
    """public_records, and for an internal alias also what the public DNS
    has instead: a name that is a CNAME inside and an address outside
    differs, it is not "only internal"."""
    kind, ptype, values = public_records(name, rtype, lookup)
    if kind == "empty" and rtype == "CNAME":
        for other in ("A", "AAAA"):
            k, t, v = public_records(name, other, lookup)
            if k == "records":
                return k, t, v
    return kind, ptype, values


def is_public_zone(zone, lookup=doh_lookup):
    """True if the public DNS knows the zone or a name in it."""
    status, _ = lookup(zone, "SOA")
    return status != NXDOMAIN


def fqdn(zone, name):
    return zone if name == "@" else f"{name}.{zone}"


def compare(zone, records, lookup=doh_lookup, workers=8):
    """Rows for the records of a zone the module may change.

    records: as dnswrite lists them. Wildcards are skipped, a public
    resolver cannot be asked for them. Status of a row:
      same           internal and public values are equal
      differs        both exist with other values (also: public is an alias)
      internal_only  the public DNS has no such record
    """
    groups = {}
    for r in records:
        if r.get("locked") or r["type"] not in COMPARED or r["name"].startswith("*"):
            continue
        groups.setdefault((r["name"], r["type"]), []).append(r["data"])
    keys = sorted(groups)[:MAX_NAMES]

    def one(key):
        name, rtype = key
        kind, ptype, values = public_view(fqdn(zone, name), rtype, lookup)
        internal = sorted(groups[key], key=str.lower)
        if kind in ("missing", "empty"):
            status = "internal_only"
        elif ptype == rtype and [v.lower() for v in values] == [v.lower() for v in internal]:
            status = "same"
        else:
            status = "differs"
        return {"name": name, "type": rtype, "internal": internal, "public_type": ptype, "public": values,
                "status": status}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        rows = list(pool.map(one, keys))
    order = {"differs": 0, "internal_only": 1, "same": 2}
    return sorted(rows, key=lambda r: (order[r["status"]], r["name"], r["type"])), len(groups) - len(keys)


def adoption(name, rtype, node_records, kind, public_type, values):
    """(to delete, to add) so that the node says what the public DNS says.

    node_records: [(type, data, dynamic)] of the node. Only records of the
    compared type and of the public type are touched; a public alias
    replaces every other record of the name, as a CNAME stands alone."""
    if kind in ("missing", "empty"):
        return [], []
    wanted = {(public_type, v) for v in values}
    if public_type == "CNAME":
        scope = {t for t, _, _ in node_records}
    else:
        scope = {rtype, public_type, "CNAME"}
    have = {(t, d) for t, d, _ in node_records if t in scope}
    lower = {(t, d.lower()) for t, d in wanted}
    delete = sorted((t, d) for t, d in have if (t, d.lower()) not in lower)
    present = {(t, d.lower()) for t, d in have}
    add = sorted((t, d) for t, d in wanted if (t, d.lower()) not in present)
    return delete, add
