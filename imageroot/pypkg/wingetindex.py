#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Read the winget community source without Windows.

The source is published as a pre-indexed MSIX package (a ZIP file) on the
winget CDN. Its Public/index.db is an SQLite database (schema version 2) with
one row per package and the latest version. Per-package details come from the
same CDN and are chained by SHA-256:

    packages.hash  = sha256(packages/<id>/<hash[:8]>/versionData.mszyml)
    versionData    lists every version with rP (manifest path) and s256H
    s256H          = sha256(<rP>)   (merged YAML manifest of that version)

Every download goes over HTTPS with certificate verification and is size
limited. Nothing downloaded is ever executed: the database is opened
read-only, YAML is parsed with safe_load.
"""

import datetime
import email.utils
import hashlib
import io
import json
import os
import re
import sqlite3
import struct
import tempfile
import urllib.parse
import zipfile
import zlib

CDN = "https://cdn.winget.microsoft.com/cache"
SOURCE_URL = CDN + "/source2.msix"
INDEX_MEMBER = "Public/index.db"

MAX_MSIX = 64 * 2**20        # source2.msix is ~4 MB today
MAX_INDEX = 256 * 2**20      # index.db is ~9 MB today
MAX_SMALL = 4 * 2**20        # versionData / manifest are a few KB
MAX_MSZYML_OUT = 32 * 2**20
TIMEOUT = 60

# Characters seen in real package identifiers (letters and digits of any
# script plus . - _ + & , ! @). No quotes, no spaces, no path separators, so
# an identifier that passes can be embedded in a single-quoted PowerShell
# string and in a URL path segment.
PACKAGE_ID_RE = re.compile(r"^[\w][\w.\-+&,!@]{0,127}$")


class IndexError_(Exception):
    """Raised for every problem with the index or the CDN data."""


def valid_package_id(package_id):
    return isinstance(package_id, str) and bool(PACKAGE_ID_RE.match(package_id)) and "__" not in package_id[:2]


def _index_dir(state_dir):
    # Not listed in etc/state-include.conf: the index is downloaded again
    # after a restore and must not bloat the backup.
    return os.path.join(state_dir, "wingetindex")


def db_path(state_dir):
    return os.path.join(_index_dir(state_dir), "index.db")


def meta_path(state_dir):
    return os.path.join(_index_dir(state_dir), "meta.json")


def read_meta(state_dir):
    try:
        with open(meta_path(state_dir)) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _get(url, limit, session=None, headers=None):
    """GET url, refusing bodies larger than limit. Returns the response with
    .content filled in."""
    import requests  # only needed for downloads; keeps the module importable without it

    s = session or requests
    resp = s.get(url, stream=True, timeout=TIMEOUT, headers=headers or {})
    if resp.status_code == 304:
        return resp
    if resp.status_code != 200:
        raise IndexError_(f"{url}: HTTP {resp.status_code}")
    declared = resp.headers.get("Content-Length")
    if declared and int(declared) > limit:
        raise IndexError_(f"{url}: {declared} bytes exceeds the limit of {limit}")
    buf = io.BytesIO()
    for chunk in resp.iter_content(65536):
        buf.write(chunk)
        if buf.tell() > limit:
            raise IndexError_(f"{url}: response exceeds the limit of {limit} bytes")
    resp._content = buf.getvalue()
    return resp


def _check_db(path):
    """Open the database read-only and make sure it is a schema-2 index."""
    con = sqlite3.connect(f"file:{urllib.parse.quote(path)}?mode=ro", uri=True)
    try:
        meta = dict(con.execute("SELECT name, value FROM metadata").fetchall())
        if meta.get("majorVersion") != "2":
            raise IndexError_(f"unsupported index schema {meta.get('majorVersion')}.{meta.get('minorVersion')}")
        count = con.execute("SELECT count(*) FROM packages").fetchone()[0]
        if count == 0:
            raise IndexError_("the index contains no packages")
        return meta, count
    except sqlite3.DatabaseError as ex:
        raise IndexError_(f"index.db is not readable: {ex}") from ex
    finally:
        con.close()


def refresh(state_dir, force=False, session=None):
    """Download source2.msix if it changed and replace index.db atomically.

    Returns the new metadata dictionary and whether anything changed.
    """
    os.makedirs(_index_dir(state_dir), mode=0o700, exist_ok=True)
    old = read_meta(state_dir)
    headers = {}
    if not force and old.get("etag") and os.path.exists(db_path(state_dir)):
        headers["If-None-Match"] = old["etag"]
    resp = _get(SOURCE_URL, MAX_MSIX, session=session, headers=headers)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    if resp.status_code == 304:
        old["checked"] = now
        _write_meta(state_dir, old)
        return old, False

    try:
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        info = zf.getinfo(INDEX_MEMBER)
    except (zipfile.BadZipFile, KeyError) as ex:
        raise IndexError_(f"source2.msix does not contain {INDEX_MEMBER}: {ex}") from ex
    if info.file_size > MAX_INDEX:
        raise IndexError_(f"{INDEX_MEMBER} is {info.file_size} bytes, over the limit of {MAX_INDEX}")

    fd, tmp = tempfile.mkstemp(dir=_index_dir(state_dir), prefix=".index-", suffix=".db")
    try:
        with os.fdopen(fd, "wb") as out, zf.open(info) as src:
            written = 0
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_INDEX:
                    raise IndexError_("index.db grew over the size limit while unpacking")
                out.write(chunk)
        db_meta, count = _check_db(tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, db_path(state_dir))
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

    last_modified = resp.headers.get("Last-Modified", "")
    meta = {
        "etag": resp.headers.get("ETag", ""),
        "last_modified": _http_date_to_iso(last_modified),
        "checked": now,
        "fetched": now,
        "packages": count,
        "schema": f"{db_meta.get('majorVersion')}.{db_meta.get('minorVersion')}",
        "sha256": hashlib.sha256(resp.content).hexdigest(),
    }
    _write_meta(state_dir, meta)
    return meta, True


def _http_date_to_iso(value):
    if not value:
        return ""
    try:
        return email.utils.parsedate_to_datetime(value).astimezone(datetime.timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError):
        return ""


def _write_meta(state_dir, meta):
    fd, tmp = tempfile.mkstemp(dir=_index_dir(state_dir), prefix=".meta-")
    with os.fdopen(fd, "w") as f:
        json.dump(meta, f)
    os.replace(tmp, meta_path(state_dir))


def _connect(state_dir):
    path = db_path(state_dir)
    if not os.path.exists(path):
        raise IndexError_("the package index has not been downloaded yet")
    return sqlite3.connect(f"file:{urllib.parse.quote(path)}?mode=ro", uri=True)


def _like(term):
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def search(state_dir, query, limit=50):
    """Find packages by identifier, name, moniker, publisher or tag.

    Exact identifier matches come first, then identifiers starting with the
    query, then everything else by name.
    """
    query = (query or "").strip()
    if not query:
        return []
    if len(query) > 100:
        raise IndexError_("the search term is too long")
    limit = max(1, min(int(limit), 200))
    pattern = _like(query.lower())
    norm = re.sub(r"[^\w]", "", query.lower())
    con = _connect(state_dir)
    try:
        rows = con.execute(
            """
            SELECT id, name, moniker, latest_version,
                   CASE WHEN lower(id) = ? THEN 0
                        WHEN lower(id) LIKE ? ESCAPE '\\' THEN 1
                        WHEN lower(name) = ? OR moniker = ? THEN 2
                        ELSE 3 END AS rank
            FROM packages p
            WHERE lower(id) LIKE ? ESCAPE '\\'
               OR lower(name) LIKE ? ESCAPE '\\'
               OR moniker LIKE ? ESCAPE '\\'
               OR rowid IN (SELECT package FROM norm_publishers2
                            WHERE ? <> '' AND norm_publisher LIKE ? ESCAPE '\\')
               OR rowid IN (SELECT tm.package FROM tags2_map tm JOIN tags2 t ON t.rowid = tm.tag
                            WHERE t.tag = ?)
            ORDER BY rank, lower(name), id
            LIMIT ?
            """,
            (
                query.lower(), _like(query.lower())[1:], query.lower(), query.lower(),
                pattern, pattern, pattern,
                norm, _like(norm), query.lower(),
                limit,
            ),
        ).fetchall()
    finally:
        con.close()
    return [{"id": r[0], "name": r[1], "moniker": r[2] or "", "latest_version": r[3]} for r in rows]


def lookup(state_dir, package_id):
    """Return the index row of one package, or None."""
    if not valid_package_id(package_id):
        return None
    con = _connect(state_dir)
    try:
        row = con.execute(
            "SELECT id, name, moniker, latest_version, hash FROM packages WHERE id = ?", (package_id,)
        ).fetchone()
    finally:
        con.close()
    if not row:
        return None
    return {"id": row[0], "name": row[1], "moniker": row[2] or "", "latest_version": row[3], "hash": (row[4] or b"").hex()}


def decode_mszyml(data):
    """Decompress an .mszyml file (MSZIP blocks, as written by winget).

    Layout: 8 byte signature, 8 byte uncompressed size, 8 byte (unused here),
    then blocks of u32 compressed length + "CK" + raw deflate. Each block may
    reference the output of the previous one (dictionary).
    """
    if len(data) < 28:
        raise IndexError_("mszyml: file too short")
    (size,) = struct.unpack_from("<Q", data, 8)
    if size > MAX_MSZYML_OUT:
        raise IndexError_(f"mszyml: declared size {size} exceeds the limit")
    out = bytearray()
    pos = 24
    while pos < len(data) and len(out) < size:
        (blen,) = struct.unpack_from("<I", data, pos)
        block = data[pos + 4 : pos + 4 + blen]
        if len(block) != blen or block[:2] != b"CK":
            raise IndexError_("mszyml: malformed block")
        dec = zlib.decompressobj(-15, zdict=bytes(out[-32768:])) if out else zlib.decompressobj(-15)
        out += dec.decompress(block[2:], size - len(out) + 1)
        pos += 4 + blen
    if len(out) != size:
        raise IndexError_(f"mszyml: got {len(out)} bytes, expected {size}")
    return bytes(out)


def _verified(url, expected_sha256, limit, session=None):
    body = _get(url, limit, session=session).content
    actual = hashlib.sha256(body).hexdigest()
    if actual != expected_sha256.lower():
        raise IndexError_(f"{url}: SHA-256 mismatch (expected {expected_sha256}, got {actual})")
    return body


def install_scope(installers):
    """How the package can be installed as SYSTEM: "machine" when a
    machine-wide installer exists (winget is asked for it), "user" when
    every installer names the user scope (a per-user install, nothing to
    deploy to a computer), "" when the manifest does not say."""
    scopes = {i.get("scope", "").lower() for i in installers}
    if "machine" in scopes:
        return "machine"
    if scopes == {"user"}:
        return "user"
    return ""


def details(state_dir, package_id, session=None):
    """Versions and metadata of one package, verified along the hash chain."""
    import yaml
    row = lookup(state_dir, package_id)
    if not row:
        raise IndexError_(f"package {package_id!r} is not in the index")
    if len(row["hash"]) != 64:
        raise IndexError_(f"package {package_id!r} has no version data hash in the index")
    vd_url = f"{CDN}/packages/{urllib.parse.quote(row['id'], safe='')}/{row['hash'][:8]}/versionData.mszyml"
    vd = yaml.safe_load(decode_mszyml(_verified(vd_url, row["hash"], MAX_SMALL, session)))
    versions = vd.get("vD") or []
    if not versions:
        raise IndexError_(f"package {package_id!r}: version data lists no versions")
    latest = versions[0]
    rel = str(latest.get("rP", ""))
    if not rel.startswith("manifests/") or ".." in rel:
        raise IndexError_(f"package {package_id!r}: unexpected manifest path {rel!r}")
    manifest = yaml.safe_load(_verified(f"{CDN}/{urllib.parse.quote(rel)}", latest.get("s256H", ""), MAX_SMALL, session))
    installers = []
    for inst in manifest.get("Installers") or []:
        installers.append({
            "architecture": str(inst.get("Architecture", "")),
            "type": str(inst.get("InstallerType", manifest.get("InstallerType", ""))),
            "scope": str(inst.get("Scope", manifest.get("Scope", ""))),
        })
    return {
        "id": row["id"],
        "name": str(manifest.get("PackageName", row["name"])),
        "publisher": str(manifest.get("Publisher", "")),
        "version": str(manifest.get("PackageVersion", latest.get("v", ""))),
        "short_description": str(manifest.get("ShortDescription", "")).strip(),
        "license": str(manifest.get("License", "")),
        "homepage": str(manifest.get("PackageUrl", manifest.get("PublisherUrl", ""))),
        "installers": installers,
        "scope": install_scope(installers),
        "versions": [str(v.get("v", "")) for v in versions][:50],
    }
