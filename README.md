# ns8-windeploy

**GPO based Software Deployment for Windows** — a NethServer 8 module that
searches the [winget community repository](https://github.com/microsoft/winget-pkgs)
and rolls out Windows software through Group Policy scheduled tasks in a
Samba (or Windows) Active Directory.

> Status: alpha. Pre-releases are published as testing versions in the
> [tebbiworld repository](https://github.com/tebbiworld/ns8-repo); not for
> production yet.

## How it works

- The module downloads the pre-indexed winget source (`source2.msix` from the
  winget CDN) and searches it with SQLite; package details are verified along
  the SHA-256 chain of the index. No Windows machine and no GitHub API needed.
- A *deployment* is one GPO with one scheduled task per package, running
  `winget install|upgrade` as `NT AUTHORITY\System` on a weekly or daily
  schedule, optionally "run now" (run-once immediate task).
- The GPO is written by a delegated service account (not a domain admin)
  over LDAP (sign and seal) and SMB, from a separate Samba runtime image
  (`tool/`). The account can be created from the UI with domain admin
  credentials that are used once and not stored.
- The rights belong to the group `windeploy-admins`, the account is its
  member: every GPO of the module gives the group full control, so another
  member can take over when the service account is replaced. The setup from
  the UI also hands GPOs of an earlier account over to the group.
- The GPO is linked to the domain root or to organizational units; missing
  OUs can be created (empty) from the deployment editor.

## Lifecycle of the GPOs

A rule applies exactly as long as it exists:

- The scheduled tasks carry "remove this item when it is no longer
  applied" (`removePolicy`). A computer deletes a task at its next policy
  refresh (start-up, about every 90 minutes, `gpupdate`) when the package
  leaves the deployment, the GPO is deleted or unlinked, or the computer
  moves to an OU the GPO does not apply to - also when it is switched on
  only months later. Installed software is never uninstalled.
- Windows creates such a task again at every policy refresh and forgets
  its history, so a missed start would be lost (measured on Windows 11
  25H2, also with the action "update"). The task therefore starts after
  each refresh as well, and the script runs winget only when a scheduled
  time has passed since its last run, kept in the registry under
  `HKLM\SOFTWARE\windeploy`. A computer that was switched off catches up
  after its next start. On a computer that sees a deployment for the
  first time the script waits for the next scheduled time.
- Removing a deployment deletes its GPO.
- Removing the module deletes the GPOs of all its deployments (the UI
  says so on the Status page). A DC that cannot be reached does not block
  the removal; the GPOs left behind are listed in the module log.
- Moving the module to another node keeps the GPOs: the new instance has
  the same module UUID and manages them. A clone (copy) starts without
  deployments, so that two instances never manage the same GPO.
- A restore brings the deployments back without contacting the DC; the
  rights are checked at the next save.
- Every GPO holds a `windeploy.json` next to `GPT.INI` that names the
  deployment and its packages; Windows ignores it.
- The module keeps the last 10 versions of each GPO's files in
  `state/gpo-backups` (part of the module backup).

Tested end to end with Windows 11 25H2 clients in a Samba 4.19 domain
(NS8 samba module): GPO → scheduled task as SYSTEM → winget installs.

## Layout

| Path | What |
|---|---|
| `imageroot/pypkg/wingetindex.py` | winget index download, search, package details |
| `imageroot/pypkg/gpogen.py` | generator: PowerShell script, ScheduledTasks.xml, GPT.INI, versions (pure, unit tested) |
| `imageroot/pypkg/wdcommon.py` | shared helpers of the actions (domains, deployments, runtime) |
| `tool/gpowrite.py`, `tool/Containerfile` | Samba runtime: create/fill/link/delete GPOs, service account setup |
| `imageroot/actions/` | NS8 actions |
| `ui/` | Vue 2 UI: Status, Guide, Settings, Deployments (en, de, it, fr) |
| `tests/unit/` | offline tests of the generator against a working reference GPO |

## Install

Add the tebbiworld repository to the cluster with testing versions
enabled and install the module from the Software Center, or:

```
add-module ghcr.io/tebbiworld/windeploy:<version> 1
```

## Build

```
bash build-images.sh
```

builds `windeploy` and `windeploy-samba`; the module image pins
`windeploy-samba` with the same tag. The workflow "Publish images" builds
and pushes both for every branch and tag. Unit tests:
`python3 -m unittest discover -s tests/unit`.

## Requirements on the clients

Windows 10/11 in the domain with App Installer (winget) 1.2x or newer from
the Microsoft Store or github.com/microsoft/winget-cli, internet access to
the vendor downloads. See the Guide page of the module for the details.
