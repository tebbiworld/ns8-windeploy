#!/usr/bin/env python3

#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Write deployment GPOs to a Samba (or Windows) AD over LDAP and SMB.

Runs inside the windeploy-samba image (python3-samba). One JSON request on
stdin, one JSON response on stdout, log lines on stderr.

Connection data comes from the environment:
  GPO_DC_HOST   DNS name of the domain controller (resolved by the caller
                with --add-host, the LAN DNS may point elsewhere)
  GPO_REALM     AD realm, e.g. AD.EXAMPLE.COM
  GPO_WORKGROUP NetBIOS domain name
  GPO_USER      service account (sAMAccountName)
  PASSWD        its password (read by the Samba credentials code, never on
                a command line)
  GPO_DC_IP     IP address of the domain controller: Kerberos is pointed
                at it directly (no DNS lookup of the KDC)

Requests (field "op"):
  check                   bind, report the rights the account has
  list    {guids}         attributes of the given GPOs
  create  {display_name}  new empty GPO, returns its GUID
  apply   {guid, files, add_cse, backup_dir}
                          write files below the GPO folder, register the
                          scheduled task CSE, bump the computer version
  link    {guid, target_dn}      append the GPO to gPLink of target_dn
  unlink  {guid, target_dn}
  delete  {guid}          remove links are the caller's job; removes the
                          GPO object and its SYSVOL folder
  targets                 domain root and organizational units (link targets)
  provision {admin_user, admin_password, username, password, link_targets}
                          one-time setup with domain admin credentials (not
                          stored): create or reset the service account, add
                          it to Group Policy Creator Owners and delegate GPO
                          creation and linking to it
"""

import base64
import io
import json
import os
import re
import sys
import traceback
import uuid

import ldb
from samba import credentials, param
from samba.credentials import SMB_SIGNING_REQUIRED
from samba.dcerpc import security
from samba.ndr import ndr_pack, ndr_unpack
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param
from samba.samdb import SamDB

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gpogen  # noqa: E402

GUID_RE = re.compile(r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$")
# Relative paths the module may write below a GPO folder
ALLOWED_FILE_RE = re.compile(r"^Machine/(Preferences/ScheduledTasks/ScheduledTasks\.xml|Scripts/windeploy/[A-Za-z0-9._-]{1,120}\.ps1)$")

SCHEMA_GPC = "f30e3bc2-9ff0-11d1-b603-0000f80367c1"      # groupPolicyContainer
ATTR_GPLINK = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
ATTR_GPOPTIONS = "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
CLASS_OU = "bf967aa5-0de6-11d0-a285-00aa003049e2"            # organizationalUnit


def log(msg):
    print(msg, file=sys.stderr, flush=True)


class GpoError(Exception):
    pass


def _write_krb5_conf(realm, kdc_ip):
    """Kerberos must not look up the KDC in DNS: on a LAN with split DNS the
    realm may resolve to another domain's controller."""
    import ipaddress
    import tempfile
    ipaddress.ip_address(kdc_ip)
    fd, path = tempfile.mkstemp(prefix="krb5-", suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write("[libdefaults]\n"
                f"    default_realm = {realm}\n"
                "    dns_lookup_kdc = false\n"
                "    dns_lookup_realm = false\n"
                "[realms]\n"
                f"    {realm} = {{\n        kdc = {kdc_ip}\n    }}\n")
    os.environ["KRB5_CONFIG"] = path


class Session:
    def __init__(self, user=None, password=None):
        env = os.environ
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", env["GPO_REALM"]):
            raise GpoError("invalid realm")
        if env.get("GPO_DC_IP"):
            _write_krb5_conf(env["GPO_REALM"].upper(), env["GPO_DC_IP"])
        self.host = env["GPO_DC_HOST"]
        self.realm = env["GPO_REALM"].upper()
        self.workgroup = env["GPO_WORKGROUP"].upper()
        self.lp = param.LoadParm()
        self.lp.load(env.get("SMB_CONF", "/etc/samba/smb.conf"))
        creds = credentials.Credentials()
        creds.guess(self.lp)
        creds.set_username(user or env["GPO_USER"])
        creds.set_domain(self.workgroup)
        creds.set_realm(self.realm)
        creds.set_password(password if password is not None else env["PASSWD"])
        self.creds = creds
        # LDAP with SASL sign+seal (the DC refuses simple binds in clear text)
        self.samdb = SamDB(url=f"ldap://{self.host}", credentials=creds, lp=self.lp)
        self.domain_dn = str(self.samdb.get_default_basedn())
        root = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_BASE, attrs=["objectSid"])[0]
        self.domain_sid = ndr_unpack(security.dom_sid, root["objectSid"][0])
        self.dns_domain = self.realm.lower()
        self._smb = None

    @property
    def smb(self):
        if self._smb is None:
            saved = self.creds.get_smb_signing()
            self.creds.set_smb_signing(SMB_SIGNING_REQUIRED)
            s3_lp = s3param.get_context()
            s3_lp.load(self.lp.configfile)
            self._smb = libsmb.Conn(self.host, "sysvol", lp=s3_lp, creds=self.creds)
            self.creds.set_smb_signing(saved)
        return self._smb

    # ---- names -------------------------------------------------------------
    def gpo_dn(self, guid):
        return f"CN={guid},CN=Policies,CN=System,{self.domain_dn}"

    def share_path(self, guid, rel=""):
        base = f"{self.dns_domain}\\Policies\\{guid}"
        return base + ("\\" + rel.replace("/", "\\") if rel else "")

    def unc_path(self, guid):
        return f"\\\\{self.dns_domain}\\SysVol\\{self.dns_domain}\\Policies\\{guid}"

    def account_sid(self):
        res = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                expression=f"(sAMAccountName={ldb.binary_encode(os.environ['GPO_USER'])})",
                                attrs=["objectSid"])
        if len(res) != 1:
            raise GpoError("service account not found")
        return str(ndr_unpack(security.dom_sid, res[0]["objectSid"][0]))

    # ---- SMB helpers ---------------------------------------------------------
    def mkdirs(self, path):
        cur = ""
        for part in path.split("\\"):
            cur = cur + "\\" + part if cur else part
            if not self.smb.chkpath(cur):
                self.smb.mkdir(cur)

    def read_file(self, path):
        try:
            return self.smb.loadfile(path)
        except Exception:
            return None

    def write_file(self, path, data):
        """Write via a temporary name and rename, so a client never reads a
        half written file."""
        tmp = path + ".windeploy-tmp"
        self.smb.savefile(tmp, data)
        if self.smb.chkpath(path) or self.read_file(path) is not None:
            self.smb.unlink(path)
        self.smb.rename(tmp, path)

    def remove_tree(self, path):
        for entry in self.smb.list(path):
            name = entry["name"]
            child = path + "\\" + name
            if entry["attrib"] & 0x10:  # FILE_ATTRIBUTE_DIRECTORY
                self.remove_tree(child)
            else:
                self.smb.unlink(child)
        self.smb.rmdir(path)

    # ---- operations ----------------------------------------------------------
    def check(self):
        sid = self.account_sid()
        res = {"domain_dn": self.domain_dn, "realm": self.realm, "account_sid": sid}
        policies = self.samdb.search(f"CN=Policies,CN=System,{self.domain_dn}", scope=ldb.SCOPE_BASE,
                                     attrs=["nTSecurityDescriptor"],
                                     controls=["sd_flags:1:4"])[0]
        sddl = ndr_unpack(security.descriptor, policies["nTSecurityDescriptor"][0]).as_sddl(self.domain_sid)
        groups = self._token_sids()
        res["can_create_gpo"] = _grants(sddl, "CC", SCHEMA_GPC, groups)
        root = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"],
                                 controls=["sd_flags:1:4"])[0]
        rsddl = ndr_unpack(security.descriptor, root["nTSecurityDescriptor"][0]).as_sddl(self.domain_sid)
        res["can_link_domain"] = _grants(rsddl, "WP", ATTR_GPLINK, groups)
        res["sysvol"] = bool(self.smb.chkpath(f"{self.dns_domain}\\Policies"))
        return res

    def _token_sids(self):
        res = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                expression=f"(sAMAccountName={ldb.binary_encode(os.environ['GPO_USER'])})",
                                attrs=["dn"])
        # tokenGroups is only available with a base search on the object
        dn = res[0].dn
        tg = self.samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["tokenGroups", "objectSid"])[0]
        sids = {str(ndr_unpack(security.dom_sid, v)) for v in tg.get("tokenGroups", [])}
        sids.add(str(ndr_unpack(security.dom_sid, tg["objectSid"][0])))
        sids.update({"S-1-1-0", "S-1-5-11"})  # Everyone, Authenticated Users
        return sids

    def list(self, guids):
        out = []
        for guid in guids:
            _check_guid(guid)
            try:
                m = self.samdb.search(self.gpo_dn(guid), scope=ldb.SCOPE_BASE,
                                      attrs=["displayName", "versionNumber", "gPCMachineExtensionNames", "flags"])[0]
            except ldb.LdbError:
                out.append({"guid": guid, "exists": False})
                continue
            out.append({
                "guid": guid, "exists": True,
                "display_name": str(m.get("displayName", [b""])[0]),
                "version": int(str(m.get("versionNumber", [b"0"])[0])),
                "machine_extensions": str(m.get("gPCMachineExtensionNames", [b""])[0]),
                "flags": int(str(m.get("flags", [b"0"])[0])),
                "links": self._links_of(guid),
            })
        return out

    def _links_of(self, guid):
        res = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                expression=f"(gPLink=*{ldb.binary_encode(guid)}*)", attrs=["gPLink"])
        return [str(r.dn) for r in res]

    def create(self, display_name):
        if not display_name or len(display_name) > 200 or any(c in display_name for c in "\r\n\0"):
            raise GpoError("invalid display name")
        guid = "{" + str(uuid.uuid4()).upper() + "}"
        dn = self.gpo_dn(guid)
        sid = self.account_sid()
        created_ldap = created_dir = False
        try:
            # All attributes in the add itself: no GPO object without a name.
            self.samdb.add({
                "dn": dn,
                "objectClass": "groupPolicyContainer",
                "displayName": display_name,
                "gPCFileSysPath": self.unc_path(guid),
                "versionNumber": "0",
                "flags": "0",
                "gPCFunctionalityVersion": "2",
            })
            created_ldap = True
            for sub in ("User", "Machine"):
                self.samdb.add({"dn": f"CN={sub},{dn}", "objectClass": "container"})
            path = self.share_path(guid)
            self.smb.mkdir(path)
            created_dir = True
            # Same rights as a GPO made by the Group Policy editor, plus the
            # service account (owner) with full control.
            sddl = (f"O:{sid}G:DUD:P(A;OICI;FA;;;DA)(A;OICI;FA;;;EA)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;CO)"
                    f"(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;AU)(A;OICI;0x1200a9;;;ED)")
            sd = security.descriptor.from_sddl(sddl, self.domain_sid)
            self.smb.set_acl(path, sd, security.SECINFO_DACL | security.SECINFO_PROTECTED_DACL)
            self.smb.mkdir(path + "\\Machine")
            self.smb.mkdir(path + "\\User")
            self.write_file(path + "\\GPT.INI", gpogen.build_gpt_ini(0, display_name).encode("utf-8"))
        except Exception:
            log(f"create {guid} failed, rolling back")
            if created_dir:
                _quiet(lambda: self.remove_tree(self.share_path(guid)))
            if created_ldap:
                _quiet(lambda: self.samdb.delete(dn, ["tree_delete:1"]))
            raise
        log(f"created GPO {guid} {display_name!r}")
        return {"guid": guid}

    def apply(self, guid, files, backup_dir=None, add_cse=True):
        """files: {relative path: base64 content or null to delete}."""
        _check_guid(guid)
        for rel in files:
            if not ALLOWED_FILE_RE.match(rel):
                raise GpoError(f"path not allowed: {rel}")
        dn = self.gpo_dn(guid)
        m = self.samdb.search(dn, scope=ldb.SCOPE_BASE,
                              attrs=["versionNumber", "gPCMachineExtensionNames", "displayName"])[0]
        old_version = str(m.get("versionNumber", [b"0"])[0])
        old_ext = str(m["gPCMachineExtensionNames"][0]) if "gPCMachineExtensionNames" in m else None
        display_name = str(m.get("displayName", [b""])[0])

        # 1. keep the previous state of every touched file (and GPT.INI)
        previous = {}
        for rel in list(files) + ["GPT.INI"]:
            previous[rel] = self.read_file(self.share_path(guid, rel))
        if backup_dir:
            _save_backup(backup_dir, guid, previous, old_version, old_ext)

        new_version = gpogen.bump_machine_version(int(old_version))
        new_ext = gpogen.add_scheduled_tasks_extension(old_ext or "") if add_cse else old_ext
        written = []
        try:
            # 2. files first: clients act on the version change only
            for rel, content in files.items():
                target = self.share_path(guid, rel)
                if content is None:
                    if previous[rel] is not None:
                        self.smb.unlink(target)
                        written.append(rel)
                    continue
                self.mkdirs(target.rsplit("\\", 1)[0])
                self.write_file(target, base64.b64decode(content))
                written.append(rel)
            # 3. LDAP: replace versionNumber only if nobody changed it meanwhile
            msg = ldb.Message(ldb.Dn(self.samdb, dn))
            msg["v_del"] = ldb.MessageElement(old_version, ldb.FLAG_MOD_DELETE, "versionNumber")
            msg["v_add"] = ldb.MessageElement(str(new_version), ldb.FLAG_MOD_ADD, "versionNumber")
            if new_ext != old_ext:
                msg["e"] = ldb.MessageElement(new_ext, ldb.FLAG_MOD_REPLACE, "gPCMachineExtensionNames")
            self.samdb.modify(msg)
        except Exception:
            log(f"apply {guid} failed, restoring the previous files")
            for rel in written:
                target = self.share_path(guid, rel)
                if previous[rel] is None:
                    _quiet(lambda: self.smb.unlink(target))
                else:
                    _quiet(lambda: self.write_file(target, previous[rel]))
            raise
        # 4. GPT.INI last, same number as LDAP
        self.write_file(self.share_path(guid, "GPT.INI"),
                        gpogen.build_gpt_ini(new_version, display_name or None).encode("utf-8"))
        log(f"applied {len(files)} file(s) to {guid}, version {old_version} -> {new_version}")
        return {"guid": guid, "version": new_version, "machine_extensions": new_ext}

    def _gplink(self, target_dn):
        m = self.samdb.search(target_dn, scope=ldb.SCOPE_BASE, attrs=["gPLink"])[0]
        return str(m["gPLink"][0]) if "gPLink" in m else None

    def _set_gplink(self, target_dn, old, new):
        msg = ldb.Message(ldb.Dn(self.samdb, target_dn))
        if old is None:
            msg["a"] = ldb.MessageElement(new, ldb.FLAG_MOD_ADD, "gPLink")
        elif not new:
            msg["d"] = ldb.MessageElement(old, ldb.FLAG_MOD_DELETE, "gPLink")
        else:
            # delete old value + add new = compare-and-swap
            msg["d"] = ldb.MessageElement(old, ldb.FLAG_MOD_DELETE, "gPLink")
            msg["a"] = ldb.MessageElement(new, ldb.FLAG_MOD_ADD, "gPLink")
        self.samdb.modify(msg)

    def link(self, guid, target_dn):
        _check_guid(guid)
        old = self._gplink(target_dn)
        entry = f"[LDAP://{self.gpo_dn(guid)};0]"
        if old and guid.lower() in old.lower():
            return {"linked": True, "changed": False}
        # Appended entries have the lowest precedence, like "Link an
        # existing GPO" in the editor.
        self._set_gplink(target_dn, old, (old or "") + entry)
        return {"linked": True, "changed": True}

    def unlink(self, guid, target_dn):
        _check_guid(guid)
        old = self._gplink(target_dn)
        if not old or guid.lower() not in old.lower():
            return {"linked": False, "changed": False}
        entries = re.findall(r"\[[^\]]*\]", old)
        keep = "".join(e for e in entries if guid.lower() not in e.lower())
        self._set_gplink(target_dn, old, keep)
        return {"linked": False, "changed": True}

    def targets(self):
        out = [{"dn": self.domain_dn, "name": self.realm.lower(), "kind": "domain"}]
        res = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                expression="(objectClass=organizationalUnit)", attrs=["name"])
        dcs = f"ou=domain controllers,{self.domain_dn}".lower()
        for r in sorted(res, key=lambda r: str(r.dn).lower()):
            # No software for domain controllers (on NS8 they are Samba
            # servers, not Windows computers).
            if str(r.dn).lower() == dcs:
                continue
            out.append({"dn": str(r.dn), "name": str(r.get("name", [b""])[0]), "kind": "ou"})
        return out

    def provision(self, username, password, link_targets):
        """Runs bound as a domain admin."""
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,20}", username):
            raise GpoError("invalid service account name")
        steps = []
        found = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                  expression=f"(sAMAccountName={ldb.binary_encode(username)})", attrs=["dn"])
        if found:
            self.samdb.setpassword(f"(sAMAccountName={ldb.binary_encode(username)})", password)
            steps.append("password_reset")
        else:
            self.samdb.newuser(username, password,
                               description="Service account of the NethServer module windeploy (GPO software deployment)")
            steps.append("account_created")
        self.samdb.setexpiry(f"(sAMAccountName={ldb.binary_encode(username)})", 0, no_expiry_req=True)
        group = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                  expression="(objectSid=%s-520)" % self._domain_sid_str(), attrs=["sAMAccountName", "member"])[0]
        user_dn = str(self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                        expression=f"(sAMAccountName={ldb.binary_encode(username)})", attrs=["dn"])[0].dn)
        if user_dn.lower() not in [str(m).lower() for m in group.get("member", [])]:
            self.samdb.add_remove_group_members(str(group["sAMAccountName"][0]), [username], add_members_operation=True)
            steps.append("group_added")
        sid = str(ndr_unpack(security.dom_sid, self.samdb.search(user_dn, scope=ldb.SCOPE_BASE, attrs=["objectSid"])[0]["objectSid"][0]))
        aces = [(f"CN=Policies,CN=System,{self.domain_dn}", f"(OA;;CC;{SCHEMA_GPC};;{sid})")]
        for dn in (link_targets or [self.domain_dn]):
            aces.append((dn, f"(OA;;RPWP;{ATTR_GPLINK};;{sid})"))
            aces.append((dn, f"(OA;;RPWP;{ATTR_GPOPTIONS};;{sid})"))
        # Linking to organizational units, also ones created later: inherited
        # to OU objects only (what the "manage Group Policy links" delegation
        # of the Windows tools sets).
        aces.append((self.domain_dn, f"(OA;CIIO;RPWP;{ATTR_GPLINK};{CLASS_OU};{sid})"))
        aces.append((self.domain_dn, f"(OA;CIIO;RPWP;{ATTR_GPOPTIONS};{CLASS_OU};{sid})"))
        for dn, ace in aces:
            if self._add_ace(dn, ace):
                steps.append(f"ace:{dn}")
        return {"username": username, "sid": sid, "steps": steps}

    def _domain_sid_str(self):
        return str(self.domain_sid)

    def _add_ace(self, dn, ace):
        """Add an ACE to the DACL of dn unless it is already there."""
        res = self.samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"], controls=["sd_flags:1:4"])
        desc = ndr_unpack(security.descriptor, res[0]["nTSecurityDescriptor"][0])
        if ace.lower() in desc.as_sddl(self.domain_sid).lower():
            return False
        new = security.descriptor.from_sddl("D:" + ace, self.domain_sid)
        for a in new.dacl.aces:
            desc.dacl_add(a)
        msg = ldb.Message(ldb.Dn(self.samdb, dn))
        msg["nTSecurityDescriptor"] = ldb.MessageElement(ndr_pack(desc), ldb.FLAG_MOD_REPLACE, "nTSecurityDescriptor")
        self.samdb.modify(msg, controls=["sd_flags:1:4"])
        return True

    def delete(self, guid):
        _check_guid(guid)
        links = self._links_of(guid)
        if links:
            raise GpoError(f"GPO {guid} is still linked to: {', '.join(links)}")
        path = self.share_path(guid)
        if self.smb.chkpath(path):
            self.remove_tree(path)
        try:
            self.samdb.delete(self.gpo_dn(guid), ["tree_delete:1"])
        except ldb.LdbError as ex:
            if ex.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                raise
        return {"deleted": True}


def _grants(sddl, right, object_guid, sids):
    """Rough check whether an allow ACE in sddl gives right (e.g. CC or WP)
    for object_guid (or for everything) to one of sids. Deny ACEs are not
    evaluated: this is a diagnostic, the DC decides."""
    for ace in re.findall(r"\(([^)]*)\)", sddl.split("S:")[0]):
        f = ace.split(";")
        if len(f) < 6 or f[0] not in ("A", "OA"):
            continue
        rights, obj, trustee = f[2], f[3].lower(), f[5]
        trustee_sid = _alias_sid(trustee, sids)
        if trustee_sid not in sids:
            continue
        if "IO" in f[1]:
            continue
        if (right in rights or "GA" in rights) and (not obj or obj == object_guid):
            return True
    return False


def _alias_sid(trustee, sids):
    aliases = {"AU": "S-1-5-11", "WD": "S-1-1-0", "SY": "S-1-5-18", "BA": "S-1-5-32-544"}
    if trustee in aliases:
        return aliases[trustee]
    if trustee.startswith("S-"):
        return trustee
    # domain relative aliases (DA, EA, PA ...): match by RID
    rids = {"DA": "512", "EA": "519", "PA": "520", "DU": "513"}
    rid = rids.get(trustee)
    if rid:
        for s in sids:
            if s.endswith("-" + rid):
                return s
    return trustee


def _check_guid(guid):
    if not isinstance(guid, str) or not GUID_RE.match(guid):
        raise GpoError(f"invalid GPO GUID {guid!r}")


def _quiet(fn):
    try:
        fn()
    except Exception as ex:
        log(f"rollback step failed: {ex}")


def _save_backup(backup_dir, guid, previous, version, ext):
    import datetime
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = os.path.join(backup_dir, guid, stamp)
    os.makedirs(target, mode=0o700, exist_ok=True)
    meta = {"version": version, "machine_extensions": ext, "files": {}}
    for rel, data in previous.items():
        meta["files"][rel] = data is not None
        if data is not None:
            dest = os.path.join(target, rel.replace("/", "__"))
            with open(dest, "wb") as f:
                f.write(data)
    with open(os.path.join(target, "meta.json"), "w") as f:
        json.dump(meta, f)
    log(f"backup of {guid} in {target}")


def main():
    request = json.load(sys.stdin)
    op = request.get("op")
    try:
        if op == "provision":
            admin = Session(user=request["admin_user"], password=request["admin_password"])
            result = admin.provision(request["username"], request["password"], request.get("link_targets"))
            json.dump({"ok": True, "result": result}, sys.stdout)
            return
        s = Session()
        if op == "check":
            result = s.check()
        elif op == "list":
            result = s.list(request.get("guids", []))
        elif op == "create":
            result = s.create(request["display_name"])
        elif op == "apply":
            result = s.apply(request["guid"], request.get("files", {}),
                             backup_dir=request.get("backup_dir"), add_cse=request.get("add_cse", True))
        elif op == "link":
            result = s.link(request["guid"], request["target_dn"])
        elif op == "unlink":
            result = s.unlink(request["guid"], request["target_dn"])
        elif op == "targets":
            result = s.targets()
        elif op == "delete":
            result = s.delete(request["guid"])
        else:
            raise GpoError(f"unknown op {op!r}")
        json.dump({"ok": True, "result": result}, sys.stdout)
    except (GpoError, ldb.LdbError) as ex:
        log(traceback.format_exc())
        json.dump({"ok": False, "error": str(ex)}, sys.stdout)
        sys.exit(2)
    except Exception as ex:  # SMB errors come as RuntimeError/NTSTATUSError
        log(traceback.format_exc())
        json.dump({"ok": False, "error": f"{type(ex).__name__}: {ex}"}, sys.stdout)
        sys.exit(2)


if __name__ == "__main__":
    main()
