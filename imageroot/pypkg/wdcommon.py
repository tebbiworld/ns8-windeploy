#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Shared helpers of the windeploy actions.

Settings (non-secret) live in state/environment, the service account
password in state/passwords.env (modsecrets), the deployments in
state/deployments.json. AD writes go through the windeploy-samba image
(bin: gpowrite.py), started with podman for each request.
"""

import base64
import contextlib
import datetime
import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

import agent
import gpogen
import modsecrets
import policygen
import wingetindex

DEPLOYMENTS = "deployments.json"
POLICIES = "policies.json"
POLICY_LOG = "policy-log.jsonl"
DNS_LOG = "dns-log.jsonl"
DNS_BACKUP_DIR = "dns-backups"
DNS_BACKUPS_KEPT = 20
BACKUP_DIR = "gpo-backups"
SAMBA_IMAGE_ENV = "WINDEPLOY_SAMBA_IMAGE"


def state_dir():
    return os.environ.get("AGENT_STATE_DIR") or os.path.expanduser("~/.config/state")


def log(msg, level=None):
    print((level or agent.SD_INFO) + msg, file=sys.stderr, flush=True)


# ------------------------------------------------------------- domains ---

def ns8_domains():
    """Active Directory user domains of the cluster with their DC addresses.

    Internal domains are announced by their provider modules
    (module/<id>/srv/tcp/ldap); external ones are configured under
    cluster/user_domain/ldap/<name>/conf and need the DC entered by hand.
    Only the fields needed here are read (not the bind password).
    """
    rdb = agent.redis_connect()
    domains = {}
    for pkey in rdb.scan_iter("module/*/srv/tcp/ldap"):
        domain, schema, host = rdb.hmget(pkey, "domain", "schema", "host")
        if schema != "ad" or not domain:
            continue
        module_id = pkey.split("/")[1]
        hostname, realm, workgroup = rdb.hmget(f"module/{module_id}/environment", "HOSTNAME", "REALM", "NBDOMAIN")
        d = domains.setdefault(domain, {"name": domain, "location": "internal", "providers": []})
        d["providers"].append({
            "module_id": module_id,
            "ip": host or "",
            "hostname": hostname or "",
            "realm": realm or domain.upper(),
            "workgroup": workgroup or "",
        })
    for key in rdb.scan_iter("cluster/user_domain/ldap/*/conf"):
        name = key.split("/")[3]
        if name not in domains and rdb.hget(key, "schema") == "ad":
            domains[name] = {"name": name, "location": "external", "providers": []}
    return sorted(domains.values(), key=lambda d: d["name"])


def connection_settings(env=None):
    """DC connection from state/environment, filled from the NS8 domain when
    the admin picked one and left the DC fields empty."""
    env = env if env is not None else os.environ
    s = {
        "domain": env.get("GPO_DOMAIN", ""),
        "dc_host": env.get("GPO_DC_HOST", ""),
        "dc_ip": env.get("GPO_DC_IP", ""),
        "realm": env.get("GPO_REALM", ""),
        "workgroup": env.get("GPO_WORKGROUP", ""),
        "user": env.get("GPO_USER", ""),
    }
    if s["domain"] and not (s["dc_host"] and s["dc_ip"]):
        for d in ns8_domains():
            if d["name"] == s["domain"] and d["providers"]:
                p = d["providers"][0]
                s["dc_host"] = s["dc_host"] or p["hostname"]
                s["dc_ip"] = s["dc_ip"] or p["ip"]
                s["realm"] = s["realm"] or p["realm"]
                s["workgroup"] = s["workgroup"] or p["workgroup"]
                break
    s["realm"] = (s["realm"] or s["domain"]).upper()
    return s


def validate_connection(s):
    missing = [k for k in ("dc_host", "dc_ip", "realm", "workgroup", "user") if not s.get(k)]
    if missing:
        raise ValueError("missing connection settings: " + ", ".join(missing))
    ipaddress.ip_address(s["dc_ip"])
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", s["dc_host"]):
        raise ValueError("invalid DC host name")


# -------------------------------------------------------- samba runner ---

def run_tool(request, settings=None, timeout=300, password=None):
    """Run one gpowrite request in the windeploy-samba image. The provision
    request carries its own (admin) credentials in the request body.
    password replaces the stored one (a new password is tested before it
    is stored)."""
    s = settings or connection_settings()
    admin = request.get("op") in ADMIN_OPS
    if admin:
        s = dict(s, user=s.get("user") or "none")
    validate_connection(s)
    password = password or modsecrets.get("GPO_PASSWORD")
    if admin:
        password = password or "unused"
    if not password:
        raise ValueError("the service account password is not set")
    image = os.environ.get(SAMBA_IMAGE_ENV)
    if not image:
        raise RuntimeError(f"{SAMBA_IMAGE_ENV} is not set")
    backup = os.path.join(state_dir(), BACKUP_DIR)
    os.makedirs(backup, mode=0o700, exist_ok=True)
    cmd = [
        "podman", "run", "--rm", "-i", "--network=host", "--log-driver=none",
        # The LAN DNS may resolve the realm to another domain: pin the DC.
        f"--add-host={s['dc_host']}:{s['dc_ip']}",
        "--env=PASSWD",
        f"--env=GPO_DC_HOST={s['dc_host']}",
        f"--env=GPO_DC_IP={s['dc_ip']}",
        f"--env=GPO_REALM={s['realm']}",
        f"--env=GPO_WORKGROUP={s['workgroup']}",
        f"--env=GPO_USER={s['user']}",
        "--userns=keep-id:uid=1001,gid=1001",
        f"--volume={backup}:/backup:Z",
        image,
    ]
    env = dict(os.environ, PASSWD=password)
    proc = subprocess.run(cmd, input=json.dumps(request), capture_output=True, text=True,
                          env=env, timeout=timeout)
    for line in proc.stderr.splitlines():
        if "setproctitle" in line:
            continue
        print(agent.SD_DEBUG + "gpowrite: " + line, file=sys.stderr)
    try:
        response = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        response = {}
    if not response.get("ok"):
        raise ToolError(response.get("error") or f"gpowrite exited with {proc.returncode}",
                        ldap_code=response.get("ldap_code"), ntstatus=response.get("ntstatus"),
                        code=response.get("code"))
    return response["result"]


# LDAP result codes and NTSTATUS values gpowrite reports
LDAP_INVALID_CREDENTIALS = 49
LDAP_INSUFFICIENT_ACCESS = 50
NT_STATUS_ACCESS_DENIED = 0xC0000022
NT_STATUS_WRONG_PASSWORD = 0xC000006A
NT_STATUS_LOGON_FAILURE = 0xC000006D


# requests that carry the credentials of a domain admin in their body
ADMIN_OPS = ("provision", "dns_delegate", "dns_create_zone", "dns_delete_zone")


class ToolError(Exception):
    def __init__(self, message, ldap_code=None, ntstatus=None, code=None):
        super().__init__(message)
        self.ldap_code = ldap_code
        self.ntstatus = ntstatus
        # a key of the UI translations, for errors the admin can act on
        self.code = code

    @property
    def bad_credentials(self):
        return (self.ldap_code == LDAP_INVALID_CREDENTIALS
                or self.ntstatus in (NT_STATUS_WRONG_PASSWORD, NT_STATUS_LOGON_FAILURE))

    @property
    def access_denied(self):
        return self.ldap_code == LDAP_INSUFFICIENT_ACCESS or self.ntstatus == NT_STATUS_ACCESS_DENIED


# ---------------------------------------------------------- deployments ---

@contextlib.contextmanager
def _locked(name, read):
    path = os.path.join(state_dir(), name)
    lock = os.open(path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = read()
        yield data
        fd, tmp = tempfile.mkstemp(dir=state_dir(), prefix="." + name + "-")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, path)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def deployments_locked():
    """Read-modify-write of state/deployments.json under an exclusive lock."""
    return _locked(DEPLOYMENTS, read_deployments)


def policies_locked():
    """Read-modify-write of state/policies.json under an exclusive lock."""
    return _locked(POLICIES, read_policies)


def read_policies():
    try:
        with open(os.path.join(state_dir(), POLICIES)) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"profiles": []}


def log_policy_change(profile, change, reason, before, after):
    """One line per change of a policy profile: what was set before and
    after, and why. Shown on the policy page."""
    entry = {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "profile": profile, "change": change, "reason": reason,
        "before": before, "after": after,
    }
    with open(os.path.join(state_dir(), POLICY_LOG), "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def read_policy_log(limit=50):
    try:
        with open(os.path.join(state_dir(), POLICY_LOG)) as f:
            lines = f.readlines()[-limit:]
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in reversed(lines) if line.strip()]


def log_dns_change(change, zone, before, after, pointer=""):
    """One line per change of a DNS record, with the record before and
    after. Shown on the DNS page."""
    entry = {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "change": change, "zone": zone, "before": before, "after": after, "pointer": pointer,
    }
    with open(os.path.join(state_dir(), DNS_LOG), "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def read_dns_log(limit=50):
    try:
        with open(os.path.join(state_dir(), DNS_LOG)) as f:
            lines = f.readlines()[-limit:]
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in reversed(lines) if line.strip()]


def prune_dns_backups(keep=DNS_BACKUPS_KEPT):
    """Keep the records of the zones deleted last."""
    folder = os.path.join(state_dir(), DNS_BACKUP_DIR)
    try:
        # the names end with a time stamp that sorts
        files = sorted(os.listdir(folder), key=lambda n: n.rsplit("-", 1)[-1])
    except FileNotFoundError:
        return
    for name in files[:-keep]:
        os.remove(os.path.join(folder, name))


def dns_failed(ex, field="data"):
    """End an action after a failed DNS request: errors the admin can act
    on become a validation error with their code, others fail the task."""
    import agent as _agent
    print(_agent.SD_ERR + "DNS request failed: " + str(ex), file=sys.stderr)
    code = getattr(ex, "code", None)
    if code or getattr(ex, "bad_credentials", False):
        _agent.set_status("validation-failed")
        json.dump([{"field": field, "parameter": field, "value": "", "error": code or "admin_bind_failed"}], fp=sys.stdout)
        sys.exit(3)
    sys.exit(1)


def build_policy_files(profile):
    """Files of a policy profile, base64 encoded for gpowrite (None
    deletes a file), and the machine extension names of the GPO."""
    profile.setdefault("task_uid", gpogen.new_uid())
    files, extensions = policygen.build_files(profile["settings"], task_uid=profile["task_uid"])
    out = {rel: None if data is None else base64.b64encode(data).decode() for rel, data in files.items()}
    description = json.dumps({
        "generator": "NethServer module windeploy",
        "module_uuid": os.environ.get("MODULE_UUID", ""),
        "kind": "policy",
        "name": profile["name"],
        "settings": profile["settings"],
    }, indent=1) + "\n"
    out[DESCRIPTION_FILE] = base64.b64encode(description.encode("utf-8")).decode()
    return out, extensions


BACKUPS_KEPT = 10


def prune_backups(guid, keep=BACKUPS_KEPT):
    """Keep the newest copies of a GPO's previous files (gpowrite writes
    one per change into gpo-backups/<GUID>/<timestamp>)."""
    folder = os.path.join(state_dir(), BACKUP_DIR, guid)
    try:
        stamps = sorted(os.listdir(folder))
    except FileNotFoundError:
        return
    for stamp in stamps[:-keep] if keep else stamps:
        shutil.rmtree(os.path.join(folder, stamp), ignore_errors=True)


def remove_backups(guid):
    """Drop the copies of a deleted GPO."""
    shutil.rmtree(os.path.join(state_dir(), BACKUP_DIR, guid), ignore_errors=True)


def delete_gpo(guid, link_targets, settings=None):
    """Unlink and delete a GPO of this module and drop its backups. Links
    the module does not know about (set by hand) are removed as well:
    gpowrite refuses to delete a GPO that is still linked."""
    for dn in link_targets:
        run_tool({"op": "unlink", "guid": guid, "target_dn": dn}, settings=settings)
    run_tool({"op": "delete", "guid": guid, "unlink_all": True}, settings=settings)
    remove_backups(guid)


def read_deployments():
    try:
        with open(os.path.join(state_dir(), DEPLOYMENTS)) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"deployments": []}


def gpo_guids():
    """GUIDs of the GPOs this module instance made."""
    return ([d["gpo_guid"] for d in read_deployments()["deployments"] if d.get("gpo_guid")]
            + [p["gpo_guid"] for p in read_policies()["profiles"] if p.get("gpo_guid")])


def update_scopes(deployment):
    """Installer scope of every package from its current manifest (kept
    as it was when the index cannot be read). The tasks run as SYSTEM, so
    "machine" makes the script ask winget for the machine-wide installer.
    Returns the ids of packages that only install per user."""
    for pkg in deployment["packages"]:
        try:
            pkg["scope"] = wingetindex.details(state_dir(), pkg["id"])["scope"]
        except Exception as ex:
            log(f"installer scope of {pkg['id']} unknown, kept {pkg.get('scope', '')!r}: {ex}", agent.SD_WARNING)
    return [p["id"] for p in deployment["packages"] if p.get("scope") == "user"]


def new_id():
    return uuid.uuid4().hex[:12]


def build_files(deployment, settings):
    """Script and ScheduledTasks.xml files for a deployment, base64 encoded
    for gpowrite. Scripts of removed packages are deleted (value None)."""
    guid = deployment["gpo_guid"]
    realm_dns = settings["realm"].lower()
    files = {}
    tasks = []
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    keep = set()
    delivery = deployment.get("delivery", "sysvol")
    run_now = []
    for pkg in deployment["packages"]:
        rel = f"Machine/Scripts/windeploy/{gpogen.safe_file_part(pkg['id'])}.ps1"
        keep.add(rel)
        options = dict(mode=pkg.get("mode", "upgrade"), scope="machine" if pkg.get("scope") == "machine" else "",
                       schedule=deployment["schedule"])
        script = gpogen.build_script(pkg["id"], **options)
        if delivery == "sysvol":
            files[rel] = base64.b64encode(gpogen.script_bytes(script)).decode()
            unc = f"\\\\{realm_dns}\\SysVol\\{realm_dns}\\Policies\\{guid}\\" + rel.replace("/", "\\")
            args = gpogen.task_arguments("sysvol", script_unc=unc)
            run_now.append(gpogen.task_arguments("sysvol", script_unc=unc, run_now=True))
        else:
            args = gpogen.task_arguments("embedded", script_text=script)
            run_now.append(gpogen.task_arguments(
                "embedded", script_text=gpogen.build_script(pkg["id"], run_now=True, **options)))
        pkg.setdefault("task_uid", gpogen.new_uid())
        tasks.append({
            "name": f"windeploy {pkg['id']}"[:100],
            "uid": pkg["task_uid"],
            "changed": now,
            "author": "windeploy",
            "description": f"winget {pkg.get('mode', 'upgrade')} {pkg['id']} (NethServer module windeploy)",
            "arguments": args,
            "schedule": deployment["schedule"],
            # the computers delete the task when the GPO no longer applies
            "remove_policy": True,
        })
    for rel in deployment.get("_scripts", []):
        if rel not in keep:
            files[rel] = None
    deployment["_scripts"] = sorted(keep) if deployment.get("delivery", "sysvol") == "sysvol" else []
    if deployment.get("delivery") != "sysvol":
        for rel in keep:
            files[rel] = None
    immediate = []
    # "Run now": one run-once immediate task per package that was in the
    # deployment when it was triggered. Each needs its own run-once id:
    # Windows remembers the id after the first item and skips any later
    # item with the same id. A new id makes every computer run it again.
    for pkg, task, args in zip(deployment["packages"], tasks, run_now):
        if not pkg.get("now_run_id"):
            continue
        pkg.setdefault("now_uid", gpogen.new_uid())
        immediate.append(dict(task, name=("windeploy now " + pkg["id"])[:100], uid=pkg["now_uid"],
                              run_once_id=pkg["now_run_id"], arguments=args))
    xml = gpogen.build_scheduled_tasks_xml(tasks, immediate)
    files["Machine/Preferences/ScheduledTasks/ScheduledTasks.xml"] = base64.b64encode(xml.encode("utf-8")).decode()
    files[DESCRIPTION_FILE] = base64.b64encode(describe(deployment).encode("utf-8")).decode()
    return files


# Next to GPT.INI: marks the GPO as made by windeploy and describes the
# deployment, so that it can be recognised (and taken over) without the
# module's state. Windows ignores the file.
DESCRIPTION_FILE = "windeploy.json"


def describe(deployment):
    return json.dumps({
        "generator": "NethServer module windeploy",
        "module_uuid": os.environ.get("MODULE_UUID", ""),
        "name": deployment["name"],
        "delivery": deployment.get("delivery", "sysvol"),
        "schedule": deployment["schedule"],
        "packages": [{"id": p["id"], "mode": p.get("mode", "upgrade")} for p in deployment["packages"]],
    }, indent=1) + "\n"
