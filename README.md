# ns8-windeploy

**GPO based Software Deployment for Windows** — a NethServer 8 module that
searches the [winget community repository](https://github.com/microsoft/winget-pkgs)
and rolls out Windows software through Group Policy scheduled tasks in a
Samba (or Windows) Active Directory.

> Status: internal development version, not published in a catalog.

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

## Build and install

```
bash build-images.sh
buildah push ghcr.io/tebbiworld/windeploy-samba docker://ghcr.io/tebbiworld/windeploy-samba:<tag>
buildah push ghcr.io/tebbiworld/windeploy docker://ghcr.io/tebbiworld/windeploy:<tag>
add-module ghcr.io/tebbiworld/windeploy:<tag> 1
```

The module image pins `windeploy-samba` with the same tag. Unit tests:
`python3 -m unittest tests/unit/test_gpogen.py`.

## Requirements on the clients

Windows 10/11 in the domain with App Installer (winget) 1.2x or newer from
the Microsoft Store or github.com/microsoft/winget-cli, internet access to
the vendor downloads. See the Guide page of the module for the details.
