#
# Copyright (C) 2026 tebbi
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Removal of deployments and policy profiles with a waiting period.

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

import copy
import datetime

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
    files, extensions = wdcommon.build_policy_files(profile)
    res = wdcommon.run_tool({"op": "apply", "guid": profile["gpo_guid"], "files": files, "backup_dir": "/backup",
                             "machine_extensions": extensions}, settings=settings)
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
