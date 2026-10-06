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
  GPO_GROUP     group that holds the delegated rights and full control of
                the module's GPOs (default windeploy-admins): the service
                account can be replaced by any other member

Requests (field "op"):
  check   {guids}         bind, report the rights the account has, also
                          on the given (existing) GPOs of the module
  list    {guids}         attributes of the given GPOs
  create  {display_name}  new empty GPO, returns its GUID
  apply   {guid, files, add_cse, backup_dir, display_name,
           machine_extensions, user_extensions}
                          write files below the GPO folder, register the
                          scheduled task CSE, bump the version of the
                          computer and/or user part that changed;
                          a new display_name renames the GPO (LDAP and
                          GPT.INI)
  link    {guid, target_dn}      append the GPO to gPLink of target_dn
  unlink  {guid, target_dn}
  delete  {guid}          remove links are the caller's job; removes the
                          GPO object and its SYSVOL folder
  targets                 domain root and organizational units (link targets)
  principals {query}      users and groups by name prefix, with SIDs
  rights_on_path {target_dn}
                          GPO links from target_dn up to the domain root and
                          the GptTmpl.inf of each linked GPO
  create_ou {dn}          create an organizational unit below the domain root
                          or an existing OU (optional delegated right)
  provision {admin_user, admin_password, username, password, link_targets}
                          one-time setup with domain admin credentials (not
  provision {admin_user, admin_password, username, password, link_targets, guids}
                          one-time setup with domain admin credentials (not
                          stored): create or reset the service account, put
                          it into the module group, make the group a member
                          of Group Policy Creator Owners, delegate GPO
                          creation and linking to the group and give it the
                          existing GPOs of the module (guids)
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

GUID_IN_DN_RE = re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")
GUID_RE = re.compile(r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$")
# Relative paths the module may write below a GPO folder
ALLOWED_FILE_RE = re.compile(
    r"^(windeploy\.json"
    r"|Machine/(Preferences/ScheduledTasks/ScheduledTasks\.xml|Scripts/windeploy/[A-Za-z0-9._-]{1,120}\.ps1"
    r"|Registry\.pol|Microsoft/Windows NT/SecEdit/GptTmpl\.inf)"
    r"|User/Registry\.pol)$")

SCHEMA_GPC = "f30e3bc2-9ff0-11d1-b603-0000f80367c1"      # groupPolicyContainer
ATTR_GPLINK = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
ATTR_GPOPTIONS = "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
CLASS_OU = "bf967aa5-0de6-11d0-a285-00aa003049e2"            # organizationalUnit
DEFAULT_GROUP = "windeploy-admins"
# Full control on a directory object (what "Full Control" sets in ADUC)
DS_FULL = "RPWPCCDCLCLORCWOWDSDDTSW"
FILE_FULL = 0x1f01ff


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

    @property
    def group_name(self):
        name = os.environ.get("GPO_GROUP") or DEFAULT_GROUP
        if not re.fullmatch(r"[A-Za-z0-9._ -]{1,64}", name):
            raise GpoError("invalid group name")
        return name

    def group_sid(self):
        """SID of the module group, None while it does not exist (set up by
        hand without the group, or before provision ran)."""
        res = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(self.group_name)}))",
                                attrs=["objectSid"])
        if len(res) != 1:
            return None
        return str(ndr_unpack(security.dom_sid, res[0]["objectSid"][0]))

    def sysvol_sd(self, owner, extra_sids, directory=True, inherited=False):
        """ACL of a GPO folder (or of an entry below it): what the Group
        Policy editor sets, plus full control for extra_sids."""
        flags = "OICI" if directory else ""
        if inherited:
            flags += "ID"
        aces = [f"(A;{flags};FA;;;{t})" for t in ["DA", "EA", "BA"] + list(extra_sids) + ["SY"]]
        aces += [f"(A;{flags};0x1200a9;;;AU)", f"(A;{flags};0x1200a9;;;ED)"]
        if directory:
            aces.insert(3, "(A;OICIIO{};FA;;;CO)".format("ID" if inherited else ""))
        dacl = ("D:" if inherited else "D:P") + "".join(aces)
        return security.descriptor.from_sddl(f"O:{owner}G:DU{dacl}", self.domain_sid)

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
    def check(self, guids=None):
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
        res["can_link_ous"] = _grants_inherited(rsddl, "WP", ATTR_GPLINK, CLASS_OU, groups)
        res["can_create_ou"] = _grants(rsddl, "CC", CLASS_OU, groups)
        res["sysvol"] = bool(self.smb.chkpath(f"{self.dns_domain}\\Policies"))
        gsid = self.group_sid()
        res["group"] = self.group_name
        res["in_group"] = bool(gsid and gsid in groups)
        # GPOs of the module this account cannot change (another service
        # account made them): provision hands them over to the group.
        res["foreign_gpos"] = [g for g in (guids or []) if not self._can_manage(g, groups)]
        res["can_manage_gpos"] = not res["foreign_gpos"]
        return res

    def _can_manage(self, guid, sids):
        _check_guid(guid)
        try:
            m = self.samdb.search(self.gpo_dn(guid), scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"],
                                  controls=["sd_flags:1:4"])[0]
        except ldb.LdbError as ex:
            if ex.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return True  # nothing to manage, save-deployment recreates it
            raise
        sddl = ndr_unpack(security.descriptor, m["nTSecurityDescriptor"][0]).as_sddl(self.domain_sid)
        if not _grants(sddl, "WP", "", sids):
            return False
        path = self.share_path(guid)
        if not self.smb.chkpath(path):
            return True
        fsddl = self.smb.get_acl(path, security.SECINFO_DACL).as_sddl(self.domain_sid)
        return _grants(fsddl, "FA", "", sids)

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
                                      attrs=["displayName", "versionNumber", "gPCMachineExtensionNames",
                                             "gPCUserExtensionNames", "flags"])[0]
            except ldb.LdbError:
                out.append({"guid": guid, "exists": False})
                continue
            out.append({
                "guid": guid, "exists": True,
                "display_name": _attr(m, "displayName", ""),
                "version": int(_attr(m, "versionNumber", "0")),
                "machine_extensions": _attr(m, "gPCMachineExtensionNames", ""),
                "user_extensions": _attr(m, "gPCUserExtensionNames", ""),
                "flags": int(_attr(m, "flags", "0")),
                "links": self._links_of(guid),
            })
        return out

    def _links_of(self, guid):
        res = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                expression=f"(gPLink=*{ldb.binary_encode(guid)}*)", attrs=["gPLink"])
        return [str(r.dn) for r in res]

    def create(self, display_name):
        _check_display_name(display_name)
        guid = "{" + str(uuid.uuid4()).upper() + "}"
        dn = self.gpo_dn(guid)
        sid = self.account_sid()
        # Full control for the module group, not only for this account (the
        # owner): another member can take over when the account is replaced.
        # Samba lets only admins make a group the owner; provision does it.
        gsid = self.group_sid()
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
            if gsid:
                self._add_ace(dn, f"(A;CI;{DS_FULL};;;{gsid})")
            for sub in ("User", "Machine"):
                self.samdb.add({"dn": f"CN={sub},{dn}", "objectClass": "container"})
            path = self.share_path(guid)
            self.smb.mkdir(path)
            created_dir = True
            # Same rights as a GPO made by the Group Policy editor, plus the
            # module group and the service account with full control.
            sd = self.sysvol_sd(sid, [x for x in (gsid, sid) if x])
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

    def apply(self, guid, files, backup_dir=None, add_cse=True, machine_extensions=None, display_name=None,
              user_extensions=None):
        """files: {relative path: base64 content or null to delete}.
        machine_extensions replaces gPCMachineExtensionNames (policy GPOs:
        the module owns the whole GPO and knows which extensions it uses);
        without it the scheduled tasks extension is added (add_cse).
        display_name renames the GPO in the same LDAP change; without it
        the name stays as it is. user_extensions replaces
        gPCUserExtensionNames the same way.

        Only the part that changed gets a new version: files below User/ or
        new user extensions bump the user part (upper 16 bit), files below
        Machine/ or new machine extensions the computer part. A request
        that touches neither (only windeploy.json) bumps the computer part
        as before, so every apply is a new version."""
        _check_guid(guid)
        if display_name is not None:
            _check_display_name(display_name)
        for rel in files:
            if not ALLOWED_FILE_RE.match(rel):
                raise GpoError(f"path not allowed: {rel}")
        dn = self.gpo_dn(guid)
        m = self.samdb.search(dn, scope=ldb.SCOPE_BASE,
                              attrs=["versionNumber", "gPCMachineExtensionNames", "gPCUserExtensionNames",
                                     "displayName"])[0]
        old_version = _attr(m, "versionNumber", "0")
        old_ext = str(m["gPCMachineExtensionNames"][0]) if "gPCMachineExtensionNames" in m else None
        old_user_ext = str(m["gPCUserExtensionNames"][0]) if "gPCUserExtensionNames" in m else None
        old_name = _attr(m, "displayName", "")
        new_name = old_name if display_name is None else display_name

        # 1. keep the previous state of every touched file (and GPT.INI)
        previous = {}
        for rel in list(files) + ["GPT.INI"]:
            previous[rel] = self.read_file(self.share_path(guid, rel))
        if backup_dir:
            _save_backup(backup_dir, guid, previous, old_version, old_ext, old_user_ext)

        if machine_extensions is not None:
            # parsed and written again: only well-formed GUID groups, sorted
            new_ext = gpogen.format_extension_names(gpogen.parse_extension_names(machine_extensions)) or None
        else:
            new_ext = gpogen.add_scheduled_tasks_extension(old_ext or "") if add_cse else old_ext
        if user_extensions is not None:
            new_user_ext = gpogen.format_extension_names(gpogen.parse_extension_names(user_extensions)) or None
        else:
            new_user_ext = old_user_ext
        machine_changed, user_changed = gpogen.changed_parts(files)
        machine_changed = machine_changed or new_ext != old_ext
        user_changed = user_changed or new_user_ext != old_user_ext
        if not (machine_changed or user_changed):
            machine_changed = True
        new_version = gpogen.bump_version(int(old_version), machine=machine_changed, user=user_changed)
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
                # an empty list of values removes the attribute
                msg["e"] = ldb.MessageElement(new_ext or [], ldb.FLAG_MOD_REPLACE, "gPCMachineExtensionNames")
            if new_user_ext != old_user_ext:
                msg["u"] = ldb.MessageElement(new_user_ext or [], ldb.FLAG_MOD_REPLACE, "gPCUserExtensionNames")
            if new_name != old_name:
                msg["n"] = ldb.MessageElement(new_name, ldb.FLAG_MOD_REPLACE, "displayName")
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
                        gpogen.build_gpt_ini(new_version, new_name or None).encode("utf-8"))
        if new_name != old_name:
            log(f"renamed {guid} {old_name!r} -> {new_name!r}")
        log(f"applied {len(files)} file(s) to {guid}, version {old_version} -> {new_version}")
        return {"guid": guid, "version": new_version, "machine_extensions": new_ext, "user_extensions": new_user_ext}

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
        # Appended entries are applied last within the container, so they
        # win over the other links there ([MS-GPOL]; Samba's get_gpo_list
        # walks gPLink the same way). The editor puts a new link first.
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

    def principals(self, query):
        """Users and groups whose account name or common name starts with
        query (logon rights page), at most 30, with their SIDs."""
        if not isinstance(query, str) or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,64}", query):
            raise GpoError("invalid search text")
        q = ldb.binary_encode(query)
        res = self.samdb.search(
            self.domain_dn, scope=ldb.SCOPE_SUBTREE,
            expression=f"(&(|(objectClass=group)(&(objectClass=user)(!(objectClass=computer))))"
                       f"(|(sAMAccountName={q}*)(cn={q}*)))",
            attrs=["sAMAccountName", "objectSid", "objectClass"], controls=["paged_results:1:30"])
        out = []
        for r in res:
            if "objectSid" not in r:
                continue
            classes = [str(c).lower() for c in r["objectClass"]]
            out.append({"name": _attr(r, "sAMAccountName"),
                        "sid": str(ndr_unpack(security.dom_sid, r["objectSid"][0])),
                        "kind": "group" if "group" in classes else "user"})
        return sorted(out, key=lambda e: e["name"].lower())[:30]

    def rights_on_path(self, target_dn):
        """The GPO links on the way from target_dn up to the domain root,
        child first: {containers: [{dn, block, links: [{guid, enforced,
        disabled}]}], gpos: {guid: {name, template}}} with the text of each
        GPO's GptTmpl.inf, for the conflict check of logon rights."""
        dn = ldb.Dn(self.samdb, target_dn)
        root = ldb.Dn(self.samdb, self.domain_dn)
        containers, gpos = [], {}
        while True:
            m = self.samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["gPLink", "gPOptions"])[0]
            gplink = str(m["gPLink"][0]) if "gPLink" in m else ""
            options = int(str(m["gPOptions"][0])) if "gPOptions" in m else 0
            links = []
            for entry in re.findall(r"\[LDAP://([^;\]]*);(\d+)\]", gplink):
                found = GUID_IN_DN_RE.search(entry[0])
                if not found:
                    continue
                opts = int(entry[1])
                links.append({"guid": found.group(0).upper(), "disabled": bool(opts & 1), "enforced": bool(opts & 2)})
            containers.append({"dn": str(dn), "block": options & 1 == 1,
                               "links": links})
            if str(dn).lower() == str(root).lower():
                break
            dn = dn.parent()
            if dn is None or not str(dn).lower().endswith(str(root).lower()):
                break
        for c in containers:
            for link in c["links"]:
                guid = link["guid"]
                if guid in gpos:
                    continue
                try:
                    g = self.samdb.search(self.gpo_dn(guid), scope=ldb.SCOPE_BASE, attrs=["displayName"])[0]
                    name = str(g["displayName"][0]) if "displayName" in g else ""
                except ldb.LdbError:
                    name = ""
                data = self.read_file(self.share_path(guid, "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"))
                text = None
                if data:
                    text = data[2:].decode("utf-16-le", "replace") if data[:2] == b"\xff\xfe" else data.decode("utf-8", "replace")
                gpos[guid] = {"name": name, "template": text}
        return {"containers": containers, "gpos": gpos}

    def domain_info(self):
        """What the policy page shows about the domain, read only: the
        password and lockout policy of domain accounts (in a Samba domain
        it is set at the domain, not by a GPO) and whether the schema can
        hold BitLocker recovery keys."""
        attrs = ["minPwdLength", "pwdHistoryLength", "pwdProperties", "maxPwdAge",
                 "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"]
        m = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_BASE, attrs=attrs)[0]

        def number(name):
            return int(str(m[name][0])) if name in m else 0

        def minutes(name):
            # negative 100 ns intervals; the minimum value means "never"
            ticks = -number(name)
            return None if ticks <= 0 or ticks >= 2 ** 62 else ticks // 600000000

        schema = str(self.samdb.get_schema_basedn())
        fve = self.samdb.search(schema, scope=ldb.SCOPE_ONELEVEL,
                                expression="(lDAPDisplayName=msFVE-RecoveryInformation)", attrs=["cn"])
        max_age = minutes("maxPwdAge")
        return {
            "min_password_length": number("minPwdLength"),
            "password_history": number("pwdHistoryLength"),
            "password_complexity": bool(number("pwdProperties") & 1),
            "max_password_age_days": None if max_age is None else max_age // 1440,
            "lockout_threshold": number("lockoutThreshold"),
            "lockout_duration_minutes": minutes("lockoutDuration"),
            "lockout_window_minutes": minutes("lockOutObservationWindow"),
            "bitlocker_schema": len(fve) > 0,
        }

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
            out.append({"dn": str(r.dn), "name": _attr(r, "name"), "kind": "ou"})
        return out

    def provision(self, username, password, link_targets, guids=None):
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
        user_dn = str(self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                        expression=f"(sAMAccountName={ldb.binary_encode(username)})", attrs=["dn"])[0].dn)
        sid = str(ndr_unpack(security.dom_sid, self.samdb.search(user_dn, scope=ldb.SCOPE_BASE, attrs=["objectSid"])[0]["objectSid"][0]))
        # The rights go to a group, the account is only its member: a new
        # account (or a second admin tool) just needs the membership.
        group = self.group_name
        if self.group_sid() is None:
            self.samdb.newgroup(group, description="NethServer module windeploy: members manage its GPOs")
            steps.append("group_created")
        gsid = self.group_sid()
        pa = str(self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                   expression="(objectSid=%s-520)" % self._domain_sid_str(),
                                   attrs=["sAMAccountName"])[0]["sAMAccountName"][0])
        for grp, member in ((group, username), (pa, group)):
            if self._add_member(grp, member):
                steps.append(f"member:{member}>{grp}")
        aces = [(f"CN=Policies,CN=System,{self.domain_dn}", f"(OA;;CC;{SCHEMA_GPC};;{gsid})")]
        for dn in (link_targets or [self.domain_dn]):
            aces.append((dn, f"(OA;;RPWP;{ATTR_GPLINK};;{gsid})"))
            aces.append((dn, f"(OA;;RPWP;{ATTR_GPOPTIONS};;{gsid})"))
        # Linking to organizational units, also ones created later: inherited
        # to OU objects only (what the "manage Group Policy links" delegation
        # of the Windows tools sets).
        aces.append((self.domain_dn, f"(OA;CIIO;RPWP;{ATTR_GPLINK};{CLASS_OU};{gsid})"))
        aces.append((self.domain_dn, f"(OA;CIIO;RPWP;{ATTR_GPOPTIONS};{CLASS_OU};{gsid})"))
        # Create organizational units (only that object class) below the
        # domain root and inside OUs, for "add OU" in the deployment editor.
        aces.append((self.domain_dn, f"(OA;;CC;{CLASS_OU};;{gsid})"))
        aces.append((self.domain_dn, f"(OA;CIIO;CC;{CLASS_OU};{CLASS_OU};{gsid})"))
        for dn, ace in aces:
            if self._add_ace(dn, ace):
                steps.append(f"ace:{dn}")
        # GPOs created before (by an earlier service account, or before the
        # group existed): hand them over to the group.
        for guid in guids or []:
            if self.adopt(guid, gsid):
                steps.append(f"adopted:{guid}")
        return {"username": username, "sid": sid, "steps": steps}

    def _add_member(self, group, member):
        gdn = self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                expression=f"(sAMAccountName={ldb.binary_encode(group)})", attrs=["member"])[0]
        mdn = str(self.samdb.search(self.domain_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression=f"(sAMAccountName={ldb.binary_encode(member)})", attrs=["dn"])[0].dn)
        if mdn.lower() in [str(m).lower() for m in gdn.get("member", [])]:
            return False
        self.samdb.add_remove_group_members(group, [member], add_members_operation=True)
        return True

    def adopt(self, guid, gsid):
        """Give the group ownership and full control of an existing GPO,
        in LDAP and in SYSVOL (every entry: SMB does not propagate)."""
        _check_guid(guid)
        dn = self.gpo_dn(guid)
        try:
            self.samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["dn"])
        except ldb.LdbError as ex:
            if ex.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                log(f"adopt: {guid} does not exist, skipped")
                return False
            raise
        changed = self._set_owner_and_ace(dn, gsid, f"(A;CI;{DS_FULL};;;{gsid})")
        path = self.share_path(guid)
        if self.smb.chkpath(path):
            top = self.smb.get_acl(path, security.SECINFO_OWNER | security.SECINFO_DACL)
            if str(top.owner_sid) != gsid or gsid.lower() not in top.as_sddl(self.domain_sid).lower():
                self._sysvol_acl_tree(path, gsid)
                changed = True
        return changed

    def _sysvol_acl_tree(self, path, gsid):
        info = security.SECINFO_OWNER | security.SECINFO_DACL
        self.smb.set_acl(path, self.sysvol_sd(gsid, [gsid]), info | security.SECINFO_PROTECTED_DACL)
        self._sysvol_acl_children(path, gsid)

    def _sysvol_acl_children(self, path, gsid):
        info = security.SECINFO_OWNER | security.SECINFO_DACL | security.SECINFO_UNPROTECTED_DACL
        for entry in self.smb.list(path):
            child = path + "\\" + entry["name"]
            is_dir = bool(entry["attrib"] & 0x10)  # FILE_ATTRIBUTE_DIRECTORY
            self.smb.set_acl(child, self.sysvol_sd(gsid, [gsid], directory=is_dir, inherited=True), info)
            if is_dir:
                self._sysvol_acl_children(child, gsid)

    def _set_owner_and_ace(self, dn, owner_sid, ace):
        changed = self._add_ace(dn, ace)
        res = self.samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"], controls=["sd_flags:1:1"])
        desc = ndr_unpack(security.descriptor, res[0]["nTSecurityDescriptor"][0])
        if str(desc.owner_sid) == owner_sid:
            return changed
        try:
            desc.owner_sid = security.dom_sid(owner_sid)
            msg = ldb.Message(ldb.Dn(self.samdb, dn))
            msg["nTSecurityDescriptor"] = ldb.MessageElement(ndr_pack(desc), ldb.FLAG_MOD_REPLACE, "nTSecurityDescriptor")
            self.samdb.modify(msg, controls=["sd_flags:1:1"])
            return True
        except ldb.LdbError as ex:
            log(f"owner of {dn} not changed: {ex}")
            return changed

    def _domain_sid_str(self):
        return str(self.domain_sid)

    def _add_ace(self, dn, ace):
        """Add an ACE to the DACL of dn unless it is already there."""
        res = self.samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"], controls=["sd_flags:1:4"])
        desc = ndr_unpack(security.descriptor, res[0]["nTSecurityDescriptor"][0])
        new = security.descriptor.from_sddl("D:" + ace, self.domain_sid)
        # compare in Samba's spelling (order of the rights, SID aliases)
        if new.as_sddl(self.domain_sid)[2:].lower() in desc.as_sddl(self.domain_sid).lower():
            return False
        for a in new.dacl.aces:
            desc.dacl_add(a)
        msg = ldb.Message(ldb.Dn(self.samdb, dn))
        msg["nTSecurityDescriptor"] = ldb.MessageElement(ndr_pack(desc), ldb.FLAG_MOD_REPLACE, "nTSecurityDescriptor")
        self.samdb.modify(msg, controls=["sd_flags:1:4"])
        return True

    def _remove_ace(self, dn, ace):
        """Remove an ACE from the DACL of dn; False if it was not there."""
        res = self.samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"], controls=["sd_flags:1:4"])
        desc = ndr_unpack(security.descriptor, res[0]["nTSecurityDescriptor"][0])
        # in Samba's spelling, as _add_ace compares it
        gone = security.descriptor.from_sddl("D:" + ace, self.domain_sid).as_sddl(self.domain_sid)[2:]
        sddl = desc.as_sddl(self.domain_sid)
        at = sddl.lower().find(gone.lower())
        if at == -1:
            return False
        new = security.descriptor.from_sddl(sddl[:at] + sddl[at + len(gone):], self.domain_sid)
        msg = ldb.Message(ldb.Dn(self.samdb, dn))
        msg["nTSecurityDescriptor"] = ldb.MessageElement(ndr_pack(new), ldb.FLAG_MOD_REPLACE, "nTSecurityDescriptor")
        self.samdb.modify(msg, controls=["sd_flags:1:4"])
        return True

    def create_ou(self, dn):
        m = re.fullmatch(r"OU=([^,=+\\\"<>;#]{1,64})((?:,OU=[^,=+\\\"<>;#]{1,64})*),(DC=.+)", dn, re.I)
        if not m or m.group(3).lower() != self.domain_dn.lower():
            raise GpoError(f"not an OU DN of this domain: {dn}")
        parent = dn.split(",", 1)[1]
        try:
            self.samdb.search(parent, scope=ldb.SCOPE_BASE, attrs=["dn"])
        except ldb.LdbError:
            raise GpoError(f"the parent {parent} does not exist")
        try:
            self.samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["dn"])
            return {"dn": dn, "created": False}
        except ldb.LdbError:
            pass
        self.samdb.add({"dn": dn, "objectClass": "organizationalUnit",
                        "description": "Created by the NethServer module windeploy"})
        log(f"created {dn}")
        return {"dn": dn, "created": True}

    def delete(self, guid, unlink_all=False):
        _check_guid(guid)
        links = self._links_of(guid)
        if unlink_all:
            # links an admin added by hand, next to the module's own
            for dn in links:
                self.unlink(guid, dn)
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


def _grants_inherited(sddl, right, object_guid, inherited_class, sids):
    """Allow ACE that is inherited to objects of inherited_class (e.g. OUs)
    and grants right on object_guid to one of sids."""
    for ace in re.findall(r"\(([^)]*)\)", sddl.split("S:")[0]):
        f = ace.split(";")
        if len(f) < 6 or f[0] != "OA" or "CI" not in f[1]:
            continue
        if _alias_sid(f[5], sids) not in sids:
            continue
        if right in f[2] and f[3].lower() == object_guid and f[4].lower() == inherited_class:
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


def _attr(msg, name, default=""):
    """First value of an LDAP attribute as text, default when it is missing
    (str() of a missing value's bytes default would give "b''")."""
    return str(msg[name][0]) if name in msg else default


def _check_display_name(name):
    if not isinstance(name, str) or not name or len(name) > 200 or any(c in name for c in "\r\n\0"):
        raise GpoError("invalid display name")


def _quiet(fn):
    try:
        fn()
    except Exception as ex:
        log(f"rollback step failed: {ex}")


def _save_backup(backup_dir, guid, previous, version, ext, user_ext=None):
    import datetime
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = os.path.join(backup_dir, guid, stamp)
    os.makedirs(target, mode=0o700, exist_ok=True)
    meta = {"version": version, "machine_extensions": ext, "user_extensions": user_ext, "files": {}}
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
            result = admin.provision(request["username"], request["password"], request.get("link_targets"),
                                     request.get("guids"))
            json.dump({"ok": True, "result": result}, sys.stdout)
            return
        if op in ("dns_delegate", "dns_create_zone", "dns_delete_zone"):
            # zones and the rights on them are changed by a domain admin, used for this request only
            import dnswrite
            admin = Session(user=request["admin_user"], password=request["admin_password"])
            json.dump({"ok": True, "result": dnswrite.run(admin, request)}, sys.stdout)
            return
        s = Session()
        if op.startswith("dns_"):
            import dnswrite
            json.dump({"ok": True, "result": dnswrite.run(s, request)}, sys.stdout)
            return
        if op == "check":
            result = s.check(request.get("guids"))
        elif op == "list":
            result = s.list(request.get("guids", []))
        elif op == "create":
            result = s.create(request["display_name"])
        elif op == "apply":
            result = s.apply(request["guid"], request.get("files", {}),
                             backup_dir=request.get("backup_dir"), add_cse=request.get("add_cse", True),
                             machine_extensions=request.get("machine_extensions"),
                             display_name=request.get("display_name"),
                             user_extensions=request.get("user_extensions"))
        elif op == "domain_info":
            result = s.domain_info()
        elif op == "link":
            result = s.link(request["guid"], request["target_dn"])
        elif op == "unlink":
            result = s.unlink(request["guid"], request["target_dn"])
        elif op == "create_ou":
            result = s.create_ou(request["dn"])
        elif op == "principals":
            result = s.principals(request.get("query", ""))
        elif op == "rights_on_path":
            result = s.rights_on_path(request["target_dn"])
        elif op == "targets":
            result = s.targets()
        elif op == "delete":
            result = s.delete(request["guid"], unlink_all=request.get("unlink_all", False))
        else:
            raise GpoError(f"unknown op {op!r}")
        json.dump({"ok": True, "result": result}, sys.stdout)
    except (GpoError, ldb.LdbError) as ex:
        reason = _bind_reason(ex)
        if reason:
            # a refused login is no program error: one line, no traceback
            log(f"login refused by the domain controller (AD reason {reason})")
            json.dump({"ok": False, "error": "login refused", "ad_reason": reason, **_error_code(ex)}, sys.stdout)
            sys.exit(2)
        log(traceback.format_exc())
        json.dump({"ok": False, "error": str(ex), **_error_code(ex)}, sys.stdout)
        sys.exit(2)
    except Exception as ex:  # SMB errors come as RuntimeError/NTSTATUSError
        log(traceback.format_exc())
        json.dump({"ok": False, "error": f"{type(ex).__name__}: {ex}", **_error_code(ex)}, sys.stdout)
        sys.exit(2)


def _error_code(ex):
    code = getattr(ex, "code", None)
    if isinstance(code, str):
        return {"code": code}
    werr = ex.args[0] if type(ex).__name__ == "WERRORError" and ex.args else None
    if werr == 5:
        return {"code": "access_denied"}
    return _result_code(ex)


LDAP_INVALID_CREDENTIALS = 49
# "AcceptSecurityContext error, data 533, v..." in the message of LDAP 49
BIND_REASON_RE = re.compile(r"\bdata ([0-9a-fA-F]{1,8})\b")


def _bind_reason(ex):
    """The AD sub-code of a refused LDAP login ("52e", "533", ...), "" when
    the error is something else or carries no sub-code ("49")."""
    if not (isinstance(ex, ldb.LdbError) and ex.args and ex.args[0] == LDAP_INVALID_CREDENTIALS):
        return ""
    m = BIND_REASON_RE.search(str(ex.args[1]) if len(ex.args) > 1 else "")
    return m.group(1).lower() if m else "49"


def _result_code(ex):
    """Result code of a failed request, for the caller to tell a bad
    password from an unreachable DC without parsing the message: the LDAP
    result code of an LdbError, the NTSTATUS of an SMB error."""
    if isinstance(ex, ldb.LdbError) and ex.args and isinstance(ex.args[0], int):
        return {"ldap_code": ex.args[0]}
    if type(ex).__name__ == "NTSTATUSError" and ex.args and isinstance(ex.args[0], int):
        return {"ntstatus": ex.args[0] & 0xFFFFFFFF}
    return {}


if __name__ == "__main__":
    main()
