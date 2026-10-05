Hello everyone,

I would like to show a new community module and ask for testers: **windeploy** brings Windows software, security settings and internal DNS records to the computers of a Samba AD domain, from the cluster admin UI. No Windows machine with RSAT is needed and no domain admin account is stored.

It is an early version (0.2.0). Please try it on a test domain first.

## What it does

**Software deployment**
- Search the winget community repository and pick packages.
- A deployment is one GPO with one scheduled task per package. The task runs winget as SYSTEM, daily or weekly, or once with "run now".
- Link it to the whole domain or to organizational units.

**Policies**
- Security settings for the computers, rolled out as GPOs: lock idle sessions, logon notice, removable media, BitLocker recovery keys into the directory, time source, Defender, firewall, NTLMv2, auditing, PowerShell logging. 20 settings in six groups.
- Every change needs a reason and is kept in a list of changes.

**DNS**
- Show the internal DNS zones and add, change and delete records. Create and delete zones.
- Records that Active Directory needs are shown, not changed.

## How it works

- GPOs are written by a delegated service account over LDAP and SMB, from a separate Samba runtime image. The rights belong to a group, `windeploy-admins`.
- The account can be set up from the UI with domain admin credentials that are used once and not stored. The Guide page has the same steps to do by hand.
- The module is rootless and needs no route and no port.

## A rule applies as long as it exists

This took most of the testing. With a Windows 11 25H2 client I measured what happens when a GPO no longer applies:

- Scheduled tasks are removed by the client at its next policy refresh. Installed software stays.
- With "remove this item when it is no longer applied" Windows creates the task again at every refresh, so a start missed while the computer was off would be lost. The module makes up for it after the next start.
- Removing a GPO with an advanced audit policy file clears **all** auditing on the client, also what a fresh Windows audits. The module sets the audit settings with a task instead.
- Removing a deployment deletes its GPO. Removing the module deletes its GPOs; moving it to another node keeps them.

## Install

Install "GPO based Software Deployment for Windows" from the Software Center. Or:

```
add-module ghcr.io/tebbiworld/windeploy:0.2.0 1
```

If you do not have the repository yet:

```
api-cli run add-repository --data '{"name":"tebbiworld","url":"https://raw.githubusercontent.com/tebbiworld/ns8-repo/main/ns8/updates/","status":true,"testing":false}'
```

## What I would like to know

- Does the setup of the service account work in your domain?
- Which winget packages fail when installed as SYSTEM?
- Windows 10 and Windows Pro clients: I could only test Windows 11 Enterprise.
- Which policy settings are missing for you?

## Not tested yet

Windows 10, Windows Pro, a Windows domain controller, more than one domain controller, removable media and BitLocker with real hardware.

Source, issues and README: https://github.com/tebbiworld/ns8-windeploy

Thanks to @stephdl for the review of the first version; all ten points went in.
