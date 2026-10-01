# ns8-windeploy

**GPO based Software Deployment for Windows** — a NethServer 8 module that
searches the [winget community repository](https://github.com/microsoft/winget-pkgs)
and rolls out Windows software through Group Policy scheduled tasks in a
Samba (or Windows) Active Directory.

> Status: beta. The 0.x versions are regular releases in the
> [tebbiworld repository](https://github.com/tebbiworld/ns8-repo) and can
> be installed from the Software Center without enabling testing versions.
> Try it on a test domain first.

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

## Policy profiles

The page "Policies" rolls out security settings for the computers: a
*policy profile* is one GPO with settings picked from a catalog
(`imageroot/pypkg/policygen.py`), linked like a deployment. Computer
side only; 20 settings in six groups: lock idle sessions, logon notice,
removable media, BitLocker recovery keys into the directory, time
source, who may set the clock, Defender, firewall, print spooler,
OneDrive, NTLMv2, auditing, event log sizes, PowerShell logging.

Three kinds of files are written: `Machine/Registry.pol` (most
settings), `GptTmpl.inf` (user rights) and a scheduled task that sets
the audit subcategories with `auditpol`. What a computer does when the
GPO is gone was measured with Windows 11 25H2:

| Kind of setting | When the GPO no longer applies |
| --- | --- |
| Registry values below the policy keys | removed by Windows |
| User rights | back to what they were before |
| Registry values elsewhere (NTLMv2) | stay as set |
| Audit settings | stay as set |

Settings that stay have a *reset* state: switching them off, or
removing the profile, first changes the GPO to write the Windows
default. The GPO is deleted in a second step, when the computers have
applied it. The advanced audit policy file (`audit.csv`) is not used on
purpose: when such a GPO is removed, Windows clears all auditing, also
what a fresh installation audits.

Every change of a profile needs a reason and is kept in a list of
changes with the settings before and after. The page also shows the
password and lockout policy of the domain accounts (read only: in a
Samba domain it is set at the domain, not by a GPO) and whether the
directory can store BitLocker recovery keys.

Not part of the module yet: user side settings (wallpaper, screen
saver), switching BitLocker on, reading recovery keys, Windows LAPS.

## DNS

The page "DNS" shows the internal DNS zones of the domain and changes
their records: A, AAAA, CNAME, MX, SRV, TXT, and PTR in reverse zones.
For an address the reverse record can be kept along.

- Read and written through the DNS management RPC of the domain
  controller, the interface `samba-tool dns` uses (`tool/dnswrite.py`).
- Reading works with the service account as it is. For writing, the
  group `windeploy-admins` gets the rights on a zone from a domain
  admin, once, from the page; the credentials are not stored. The
  rights can be taken away there as well. No membership in DnsAdmins.
- These rights also cover the records Active Directory needs
  (measured: the service account could change the record of the domain
  controller). The module therefore refuses to change the zone itself
  (SOA, NS), `_msdcs`, `_sites`, the AD services below `_tcp` and
  `_udp`, `DomainDnsZones`, `ForestDnsZones`, `gc` and the domain
  controllers. The rules are in `imageroot/pypkg/dnsrules.py`.
- Records a computer registers itself are shown, not changed: the
  computer would overwrite the change.
- Every change is kept in a list with the record before and after.
- Zones are created and deleted by a domain admin from the page, with
  credentials used for that request only. A forward zone by its name, a
  reverse zone from its network (192.168.1.0/24 gives
  1.168.192.in-addr.arpa). New zones are stored in the directory like
  the zone of the domain and take secure updates only.
- The zone of the domain and `_msdcs` are never deleted. Deleting a
  zone needs its name typed again; its records are written to
  `state/dns-backups` before (the last 20 files are kept, nothing is
  restored automatically). PTR records in other zones that point to
  names of a deleted zone stay.
- Removing the module leaves the zones, the records and the rights on
  the zones as they are.

- **Compare with the public DNS**: an internal zone answers for its whole
  name, so a record changed at the DNS provider keeps its old value for
  everybody who asks the domain controller. The comparison lists the
  records the module may change next to what the public DNS says: equal,
  different, or only internal. For a record that differs the internal
  side can take the public value or be deleted. The public side is
  asked over DNS over HTTPS (Cloudflare, then Google), because routers
  often redirect plain DNS to the internal server; the names of the
  zone are sent to that resolver. Wildcards and zones the public DNS
  does not know are not compared.
- If the cluster has a [dnshelper](https://github.com/danb35/ns8-dnshelper)
  instance, the comparison points to it: that module changes the public
  side at the DNS provider.

Not part of the module yet: import and export of zones, changing the
public side through dnshelper.

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
- Removing the module deletes the GPOs of all its deployments and policy
  profiles; settings in the table above that stay are not reset then (the UI
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

Add the tebbiworld repository to the cluster and install the module from
the Software Center, or:

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
