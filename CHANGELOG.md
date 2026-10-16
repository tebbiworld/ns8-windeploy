# Changelog

## 0.5.0 — unreleased

### Added

- **Retire foreign GPOs** (page "GPO inventory", "Retire"): a domain admin signs in once (not stored). The module keeps a full copy of the GPO (SYSVOL folder, GPO object, ACLs, links; the last 20 copies stay in the module and its backup), gives `windeploy-admins` the rights on this one GPO and rewrites its preferences for the waiting period: tasks, drive maps, shortcuts and environment variables get the action "delete", added members of local groups are removed, registry preferences are deleted only when confirmed one by one. A GPO with an advanced audit policy needs an explicit confirmation. "Cancel" (again with a domain admin, the only one who may give the ownership back) puts files, ACLs, owner and permissions back from the copy; a cancel that fails half way keeps the GPO from being deleted until it succeeds; after the waiting period the daily timer or "Delete now" removes the links, the object and the SYSVOL folder. Only the DC of the settings is changed; GPOs linked to a site are refused. The guide (section 10) explains copies on other DCs and how to restore a deleted GPO by hand.
- **Page "GPO inventory"** (read only): the GPOs of the domain that are not the module's, with links, versions of the computer and user part, last change, presence of the SYSVOL folder on each DC, and every setting with what the computers keep when the GPO is deleted (removed by Windows, rights restored, stays, all advanced auditing cleared, scripts, preferences that retiring takes back, not analysed). The default policies and GPOs of other windeploy instances are marked and never offered for retiring.
- **Policy option "No Thumbs.db on network drives"** (group "Network"): Explorer no longer writes hidden `Thumbs.db` thumbnail files into shared folders, where they disturb sync clients. It is the first setting on the user side: the profile writes `User/Registry.pol` and raises the user part of the GPO version only when that file changes. It applies to the user accounts below the linked targets. `Thumbs.db` files already on the shares stay. Windows 11 25H2 wrote no `Thumbs.db` to a Samba share in the test even without the policy; the option guards against older clients.

### Fixed

- The version of a GPO is raised in the right part also for folders spelled `MACHINE/` and `USER/` (GPOs of other tools).

### Security

- The DNS page no longer changes the reverse (PTR) records of the domain controllers' addresses, neither directly nor along with an address record. All other protected names (zone, AD services, `_msdcs`, `_sites`, the DC records) were refused already, also in other case, with a trailing dot or as full name (tested against the actions).
- Input checks use whole-string matching. A trailing line break passed the patterns of package ids, task names, SIDs, account names, DNS names and file paths before; none of them could be exploited (a package id has to be in the winget index, quotes stay excluded), but a line break could reach the security template of a logon rule.

## 0.4.2 — 2026-10-16

### Added

- **Check of the domain controllers** (status page): every DC with its addresses, whether it answers on SMB, and which GPOs of the module lack their SYSVOL folder there (Samba does not replicate SYSVOL). Warns as well about addresses of the domain name that belong to no reachable DC. Runs daily and with "Check now".
- **New computers install at once:** a computer that has not run a deployment before installs a missing package with the action "install" right away instead of on the next scheduled day; updates keep to the schedule.
- **Guide and README:** several domain controllers, SYSVOL without replication, address records of the domain name, first installation of new computers.

### Fixed

- **Tasks left on computers.** A package taken out of a deployment now keeps a task item with the action "delete" for the waiting period, so computers that were away delete its task too. A run of any deployment deletes tasks of windeploy whose GPO is gone (missing in SYSVOL and in the directory, checked only when SYSVOL answers); before, such tasks failed at every start. The list of removed deployments says that computers offline for the whole waiting period may keep tasks.

## 0.4.1 — 2026-10-16

### Fixed

- **Scheduled tasks could hang and pile up.** Started with `-File` from the SYSVOL share of the domain (`\\<domain>\SysVol\…`), `powershell.exe` could hang before the first line of the script, measured on Windows 11 computers in a domain with a Samba DC. Because the GPO creates the task again at every policy refresh and the task starts once registered, every refresh added a hung run; nothing was installed, and on one computer the desktop heap of session 0 ran out until a service of another program failed.
  - Every task now carries its script in its command line (`-EncodedCommand`). The choice "script delivery" is gone; existing deployments are written again when the module is updated, and so is every deployment whenever a later version changes the script (a GPO that cannot be written then, e.g. with the DC down, is written by the daily timer). Script files of older versions are deleted from the GPO folder.
  - One run per package: a start while a run of the same package is going ends at once.
  - A run records its process id and start time; the next start stops a run of the same package that is older than the task time limit (2 hours). Hung starts of the SYSVOL script of earlier versions are stopped as well. Both are noted in the package log.
  - The tasks allow the time limit to stop a run (`AllowHardTerminate`); before, a hung run stayed "running" for ever and the task skipped every later start.

## 0.4.0 — 2026-10-08

### Added

- **Screen lock also during remote control sessions.** Two policy options next to "Lock the session when idle", both needing it:
  - *Lock also when programs keep the screen on*: Windows ignores the display requests of every program (power setting `ALLOWDISPLAY` = 0, written as a policy value, removed by Windows with the GPO). Also locks video calls and presentations without input.
  - *Lock also when these programs keep the screen on*: free lists of programs and services (preset AnyDesk.exe, RustDesk.exe, TeamViewer.exe; known names of VNC servers, TeamViewer, RDP and others to pick). A scheduled task sets `powercfg /requestsoverride … DISPLAY` for them at every policy refresh; SYSTEM requests are not touched. Names taken out of the list, or all of them when the setting is switched off or the profile removed, are removed again on the computers; the profile shows them as "removing" until the admin confirms.
  - Names are checked against a strict allowlist on the server and in the UI.
- **Guide:** an overview of all pages and new sections on policy profiles, screen lock and remote control (how to find the program that keeps the screen on and switch it off), logon rules, scripts (how to write one, cleanup script, checking) and DNS.

## 0.3.0 — 2026-10-06

### Added

- **Logon rules** (new page *Logon*): who may log on to the computers of an OU, locally, through Remote Desktop, or denied. One GPO per rule with user rights by SID. The local Administrators are always kept in the rights that grant a logon, Administrators and Domain Admins can never be denied. Before saving, the page lists other GPOs on the path that set the same rights and tells which one wins (computed like Windows applies GPOs); saving then needs a confirmation, and so does a link to the whole domain.
- **Scripts** (new page *Scripts*): PowerShell logon scripts for users and startup scripts for computers, stored in the GPO folder. A warning for lines that look like a password (SYSVOL is readable by every domain user). Each script can have a cleanup script that runs while the set is being removed.
- **Removal with a waiting period** for deployments, policy profiles, logon rules and script sets. Starting the removal keeps the GPO linked and makes the computers remove what it left (tasks are deleted, policy settings go back to the Windows defaults, rights are restored, cleanup scripts run). The removal can be cancelled; after the period (default 14 days, set in the settings and per removal) a daily timer deletes the GPO, or the admin does it on the page. Every step needs a reason and is logged.
- **Policy option "allow convenience PIN sign-in"**, with a caution: Windows keeps the domain password on the computer for it.
- GPOs can carry a user part with its own version (needed by logon scripts).

### Changed

- **Refused logins** of the domain admin or the service account show one neutral message in the UI; the task log says why in one plain line (e.g. account disabled, AD code 533) instead of a traceback.
- The domain admin fields explain which account is expected (a member of Domain Admins, or the account chosen when the domain was set up).
- Policy profiles left half removed by the two-step removal of 0.2.0 are taken over by the waiting period on update.

### Fixed

- Renaming a policy profile or a deployment renamed only the entry in the module, not its GPO (`displayName` in the directory and in `GPT.INI`).
- The GPO version was raised also for a delete of a file that does not exist.
- Missing LDAP attributes were reported as the text `b''`.

## 0.2.0 — 2026-10-01

First version without a pre-release suffix: installable from the Software Center without "testing" versions.

### Added

- DNS: compare an internal zone with the public DNS (DNS over HTTPS) and take over or delete records that differ.

## 0.1.0-alpha.5 — 2026-09-29

- DNS: create and delete zones (reverse zones from their network).

## 0.1.0-alpha.4 — 2026-09-29

- Page *DNS*: show the internal zones, add, change and delete records, automatic PTR records.

## 0.1.0-alpha.3 — 2026-09-29

- Page *Policies*: security settings for the computers as policy profiles (20 settings in six groups), change list with reasons. (alpha.2 was withdrawn: the page did not work.)

## 0.1.0-alpha.1 — 2026-09-29

- First public version: search the winget community repository, deployments as GPOs with one scheduled task per package, run now, service account setup from the UI.
