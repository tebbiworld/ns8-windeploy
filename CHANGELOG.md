# Changelog

## 0.4.0 — unreleased

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
