#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Removal of deployments and policy profiles with a waiting period, and
retiring of foreign GPOs the same way (see the end of the file).

1. start: the GPO stays linked and is changed so that the computers
   remove what it left on them - the tasks of a deployment get the action
   "delete", a policy profile writes the Windows defaults for the settings
   Windows does not remove by itself and drops the others. The item gets
   a pending_delete record (since, until, days, reason).
2. waiting period: computers that are rarely connected see the change.
   cancel writes the GPO as it was before.
3. purge: when the period is over (timer windeploy-purge or the admin),
   the GPO is unlinked and deleted.

The callers hold the lock of the state file (deployments_locked or
policies_locked) and pass the item and the list it belongs to. Errors of
gpowrite propagate: the caller does not store a half done step.
"""

import base64
import copy
import datetime

import gpogen
import policygen
import wdcommon


class RemovalError(Exception):
    """A step that does not fit the state of the item; code is a key of
    the UI translations."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# ---------------------------------------------------------- deployments ---

def _write_deployment(deployment, settings):
    files = wdcommon.build_files(deployment, settings)
    res = wdcommon.run_tool({"op": "apply", "guid": deployment["gpo_guid"], "files": files,
                             "backup_dir": "/backup"}, settings=settings)
    deployment["version"] = res["version"]
    wdcommon.prune_backups(deployment["gpo_guid"])


def outdated(deployment):
    """GPO written with another script or task format (an earlier
    version, e.g. one starting the script from SYSVOL), with removed
    packages whose waiting period is over, or such a rewrite that failed
    before."""
    return bool(deployment.get("gpo_guid")) and (
        deployment.get("generator") != gpogen.generator_id() or deployment.get("delivery") != wdcommon.DELIVERY
        or deployment.get("rewrite_pending") or bool(wdcommon.removed_due(deployment)))


def rewrite_outdated(data, settings=None):
    """Write the GPOs of outdated deployments again (module update and
    the daily timer); removed packages whose waiting period is over are
    dropped. A deployment that fails (DC down) keeps the mark
    rewrite_pending and is tried again. Returns (rewritten, failed) names."""
    done, failed = [], []
    todo = [d for d in data["deployments"] if outdated(d)]
    if not todo:
        return done, failed
    settings = settings or wdcommon.connection_settings()
    for deployment in todo:
        new = copy.deepcopy(deployment)
        new.pop("rewrite_pending", None)
        embedding = new.get("delivery") != wdcommon.DELIVERY
        script_changed = embedding or new.get("generator") != gpogen.generator_id()
        due = wdcommon.removed_due(new)
        new["removed_packages"] = [r for r in new.get("removed_packages", []) if r not in due]
        try:
            _write_deployment(new, settings)
        except Exception as ex:
            deployment["rewrite_pending"] = True
            failed.append((deployment["name"], str(ex)))
            continue
        deployment.clear()
        deployment.update(new)
        if script_changed:
            wdcommon.log_deployment_change(deployment["name"], "rewritten",
                                           "script embedded in the task" if embedding else "script of the new version")
        done.append(deployment["name"])
    return done, failed


def start_deployment(deployment, reason, days=None, settings=None):
    if deployment.get("pending_delete"):
        raise RemovalError("removal_pending")
    settings = settings or wdcommon.connection_settings()
    pending = wdcommon.new_pending(reason, days)
    if deployment.get("gpo_guid"):
        deployment["pending_delete"] = pending
        try:
            _write_deployment(deployment, settings)
        except Exception:
            del deployment["pending_delete"]
            raise
    else:
        deployment["pending_delete"] = pending
    wdcommon.log_deployment_change(deployment["name"], "removal_started", reason, pending)
    return pending


def cancel_deployment(deployment, reason, settings=None):
    pending = deployment.get("pending_delete")
    if not pending:
        raise RemovalError("removal_not_pending")
    settings = settings or wdcommon.connection_settings()
    del deployment["pending_delete"]
    if deployment.get("gpo_guid"):
        try:
            _write_deployment(deployment, settings)
        except Exception:
            deployment["pending_delete"] = pending
            raise
    wdcommon.log_deployment_change(deployment["name"], "removal_cancelled", reason)


def purge_deployment(data, deployment, reason, by="admin", settings=None):
    """Delete the GPO of a deployment whose waiting period is over and drop
    the deployment from data."""
    if not wdcommon.pending_due(deployment):
        raise RemovalError("removal_not_due")
    if deployment.get("gpo_guid"):
        wdcommon.delete_gpo(deployment["gpo_guid"], deployment.get("link_targets", []), settings=settings)
    data["deployments"] = [d for d in data["deployments"] if d["id"] != deployment["id"]]
    wdcommon.log_deployment_change(deployment["name"], "deleted" if by == "admin" else "deleted_by_timer", reason)


# ------------------------------------------------------ policy profiles ---

def _write_profile(profile, settings):
    files, extensions, user = wdcommon.build_policy_files(profile)
    res = wdcommon.run_tool({"op": "apply", "guid": profile["gpo_guid"], "files": files, "backup_dir": "/backup",
                             "machine_extensions": extensions, "user_extensions": user}, settings=settings)
    profile["version"] = res["version"]
    wdcommon.prune_backups(profile["gpo_guid"])


def start_profile(profile, reason, days=None, settings=None):
    if profile.get("pending_delete"):
        raise RemovalError("removal_pending")
    settings = settings or wdcommon.connection_settings()
    before = copy.deepcopy(profile["settings"])
    on = [sid for sid, entry in before.items() if entry["state"] == "on"]
    pending = wdcommon.new_pending(reason, days)
    pending["previous_settings"] = before
    pending["previous_state"] = profile.get("state", "active")
    profile["settings"] = policygen.after_removal(before, on)
    profile["pending_delete"] = pending
    profile["state"] = "pending_delete"
    try:
        if profile.get("gpo_guid"):
            _write_profile(profile, settings)
    except Exception:
        profile["settings"] = before
        profile["state"] = pending["previous_state"]
        del profile["pending_delete"]
        raise
    profile["changed"] = _now().isoformat(timespec="seconds")
    wdcommon.log_policy_change(profile["name"], "removal_started", reason, before, profile["settings"])
    return pending


def cancel_profile(profile, reason, settings=None):
    pending = profile.get("pending_delete")
    if not pending:
        raise RemovalError("removal_not_pending")
    settings = settings or wdcommon.connection_settings()
    current = profile["settings"]
    profile["settings"] = copy.deepcopy(pending["previous_settings"])
    profile["state"] = pending.get("previous_state", "active")
    del profile["pending_delete"]
    try:
        if profile.get("gpo_guid"):
            _write_profile(profile, settings)
    except Exception:
        profile["settings"] = current
        profile["state"] = "pending_delete"
        profile["pending_delete"] = pending
        raise
    profile["changed"] = _now().isoformat(timespec="seconds")
    wdcommon.log_policy_change(profile["name"], "removal_cancelled", reason, current, profile["settings"])


def purge_profile(data, profile, reason, by="admin", settings=None):
    """Delete the GPO of a profile whose waiting period is over. The
    computers had the period to write the Windows defaults; what Windows
    removes by itself goes with the GPO."""
    if not wdcommon.pending_due(profile):
        raise RemovalError("removal_not_due")
    if profile.get("gpo_guid"):
        wdcommon.delete_gpo(profile["gpo_guid"], profile.get("link_targets", []), settings=settings)
    data["profiles"] = [p for p in data["profiles"] if p["id"] != profile["id"]]
    wdcommon.log_policy_change(profile["name"], "deleted" if by == "admin" else "deleted_by_timer", reason,
                               profile["settings"], {})


# ---------------------------------------------------------- logon rules ---

def _write_logon(rule, settings):
    files, extensions = wdcommon.build_logon_files(rule)
    res = wdcommon.run_tool({"op": "apply", "guid": rule["gpo_guid"], "files": files, "backup_dir": "/backup",
                             "machine_extensions": extensions}, settings=settings)
    rule["version"] = res["version"]
    wdcommon.prune_backups(rule["gpo_guid"])


def start_logon(rule, reason, days=None, settings=None):
    """The GPO stops setting the rights; Windows restores the rights of
    before on each computer that applies the change."""
    if rule.get("pending_delete"):
        raise RemovalError("removal_pending")
    settings = settings or wdcommon.connection_settings()
    pending = wdcommon.new_pending(reason, days)
    rule["pending_delete"] = pending
    try:
        if rule.get("gpo_guid"):
            _write_logon(rule, settings)
    except Exception:
        del rule["pending_delete"]
        raise
    rule["changed"] = _now().isoformat(timespec="seconds")
    wdcommon.log_policy_change(rule["name"], "removal_started", reason, rule["rights"], {}, log=wdcommon.LOGON_LOG)
    return pending


def cancel_logon(rule, reason, settings=None):
    pending = rule.get("pending_delete")
    if not pending:
        raise RemovalError("removal_not_pending")
    settings = settings or wdcommon.connection_settings()
    del rule["pending_delete"]
    try:
        if rule.get("gpo_guid"):
            _write_logon(rule, settings)
    except Exception:
        rule["pending_delete"] = pending
        raise
    rule["changed"] = _now().isoformat(timespec="seconds")
    wdcommon.log_policy_change(rule["name"], "removal_cancelled", reason, {}, rule["rights"], log=wdcommon.LOGON_LOG)


def purge_logon(data, rule, reason, by="admin", settings=None):
    if not wdcommon.pending_due(rule):
        raise RemovalError("removal_not_due")
    if rule.get("gpo_guid"):
        wdcommon.delete_gpo(rule["gpo_guid"], rule.get("link_targets", []), settings=settings)
    data["rules"] = [r for r in data["rules"] if r["id"] != rule["id"]]
    wdcommon.log_policy_change(rule["name"], "deleted" if by == "admin" else "deleted_by_timer", reason,
                               {}, {}, log=wdcommon.LOGON_LOG)


# ---------------------------------------------------------- script sets ---

def write_scripts(item, settings):
    files, machine, user = wdcommon.build_script_files(item)
    res = wdcommon.run_tool({"op": "apply", "guid": item["gpo_guid"], "files": files, "backup_dir": "/backup",
                             "machine_extensions": machine, "user_extensions": user}, settings=settings)
    item["version"] = res["version"]
    wdcommon.prune_backups(item["gpo_guid"])


def start_scripts(item, reason, days=None, settings=None):
    """The cleanup scripts run instead of the scripts; a part without
    cleanup script stops running."""
    import scriptgen
    if item.get("pending_delete"):
        raise RemovalError("removal_pending")
    settings = settings or wdcommon.connection_settings()
    pending = wdcommon.new_pending(reason, days)
    item["pending_delete"] = pending
    try:
        if item.get("gpo_guid"):
            write_scripts(item, settings)
    except Exception:
        del item["pending_delete"]
        raise
    item["changed"] = _now().isoformat(timespec="seconds")
    wdcommon.log_policy_change(item["name"], "removal_started", reason, scriptgen.summary(item["parts"]), {},
                               log=wdcommon.SCRIPTS_LOG)
    return pending


def cancel_scripts(item, reason, settings=None):
    import scriptgen
    pending = item.get("pending_delete")
    if not pending:
        raise RemovalError("removal_not_pending")
    settings = settings or wdcommon.connection_settings()
    del item["pending_delete"]
    try:
        if item.get("gpo_guid"):
            write_scripts(item, settings)
    except Exception:
        item["pending_delete"] = pending
        raise
    item["changed"] = _now().isoformat(timespec="seconds")
    wdcommon.log_policy_change(item["name"], "removal_cancelled", reason, {}, scriptgen.summary(item["parts"]),
                               log=wdcommon.SCRIPTS_LOG)


def purge_scripts(data, item, reason, by="admin", settings=None):
    if not wdcommon.pending_due(item):
        raise RemovalError("removal_not_due")
    if item.get("gpo_guid"):
        wdcommon.delete_gpo(item["gpo_guid"], item.get("link_targets", []), settings=settings)
    data["sets"] = [s for s in data["sets"] if s["id"] != item["id"]]
    wdcommon.log_policy_change(item["name"], "deleted" if by == "admin" else "deleted_by_timer", reason,
                               {}, {}, log=wdcommon.SCRIPTS_LOG)


# ----------------------------------------------------- foreign GPOs ---

def _stamp(now=None):
    return (now or _now()).strftime("%Y%m%dT%H%M%SZ")


def start_retire(data, guid, reason, admin_user, admin_password, confirmed=(), confirm_audit=False,
                 days=None, settings=None):
    """Start retiring a foreign GPO (pypkg/retire.py): a domain admin,
    once and not stored, lets gpowrite keep a full copy, give the module
    group the rights on this one GPO and write the Preferences that take
    back what the computers would keep. data: state/retired.json."""
    import retire
    guid = guid.upper()
    if any(g["guid"] == guid for g in data["gpos"]):
        raise RemovalError("removal_pending")
    inventory = wdcommon.read_gpo_inventory() or {"gpos": []}
    entry = retire.check_selectable(next((g for g in inventory["gpos"] if g["guid"] == guid), None))
    if retire.needs_audit_confirmation(entry["items"]) and not confirm_audit:
        raise RemovalError("audit_confirm_required")
    settings = settings or wdcommon.connection_settings()
    raw = wdcommon.run_tool({"op": "inventory", "guids": [guid]}, settings=settings, timeout=300)["gpos"]
    if not raw or not raw[0].get("readable"):
        raise RemovalError("gpo_unreadable")
    raw = raw[0]
    if any(",cn=sites,cn=configuration," in link["dn"].lower() for link in raw.get("links", [])):
        # the module has no right to change the links of sites
        raise RemovalError("site_links")
    files, changes = retire.plan(raw, set(confirmed))
    pending = wdcommon.new_pending(reason, days)
    stamp = _stamp()
    res = wdcommon.run_tool({"op": "retire_start", "guid": guid, "stamp": stamp,
                             "files": {p: base64.b64encode(d).decode() for p, d in files.items()},
                             "admin_user": admin_user, "admin_password": admin_password},
                            settings=settings, timeout=600)
    record = {"guid": guid, "name": raw.get("display_name", ""), "stamp": stamp, "pending_delete": pending,
              "changes": changes, "links": [link["dn"] for link in res.get("links", [])],
              "audit_confirmed": bool(confirm_audit), "admin_user": admin_user,
              "version": res.get("version")}
    data["gpos"].append(record)
    wdcommon.log_retire_change(guid, record["name"], "removal_started", reason,
                               {"changes": len(changes), "backup": stamp, "until": pending["until"]})
    wdcommon.prune_retired_backups(protect=[(g["guid"], g["stamp"]) for g in data["gpos"]])
    return record


def _retiring(data, guid):
    found = next((g for g in data["gpos"] if g["guid"] == guid.upper()), None)
    if found is None:
        raise RemovalError("removal_not_pending")
    return found


def cancel_retire(data, guid, reason, admin_user, admin_password, settings=None):
    """Put the GPO back as it was: files, SYSVOL ACLs, security
    descriptor (gpowrite retire_cancel, from the copy). A domain admin is
    needed again: only a member of Domain Admins may give the ownership
    back. A failed cancel may have put some of it back already, so the
    GPO is no longer deleted until a cancel succeeds."""
    record = _retiring(data, guid)
    try:
        wdcommon.run_tool({"op": "retire_cancel", "guid": record["guid"], "stamp": record["stamp"],
                           "admin_user": admin_user, "admin_password": admin_password},
                          settings=settings, timeout=600)
    except wdcommon.ToolError as ex:
        if not (ex.bad_credentials or ex.access_denied):
            record["cancel_incomplete"] = _now().isoformat(timespec="seconds")
        raise
    data["gpos"].remove(record)
    wdcommon.log_retire_change(record["guid"], record["name"], "removal_cancelled", reason)


def purge_retire(data, guid, reason, by="admin", settings=None):
    """Delete a retired GPO whose waiting period is over: links, object
    and SYSVOL folder on the DC of the settings. The copy stays."""
    record = _retiring(data, guid)
    if record.get("cancel_incomplete"):
        raise RemovalError("cancel_incomplete")
    if not wdcommon.pending_due(record):
        raise RemovalError("removal_not_due")
    res = wdcommon.run_tool({"op": "retire_delete", "guid": record["guid"]}, settings=settings, timeout=600)
    data["gpos"].remove(record)
    data.setdefault("history", []).insert(0, {
        "guid": record["guid"], "name": record["name"], "stamp": record["stamp"],
        "deleted": _now().isoformat(timespec="seconds"), "reason": record["pending_delete"]["reason"],
        "by": by, "links": res.get("unlinked", []), "changes": len(record.get("changes", []))})
    del data["history"][50:]
    wdcommon.log_retire_change(record["guid"], record["name"], "deleted" if by == "admin" else "deleted_by_timer",
                               reason)
