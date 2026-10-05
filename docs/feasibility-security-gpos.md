# Sicherheitsrichtlinien per GPO im NS8-Modul windeploy

Stand: 2026-09-28 · Grundlage: dieses Repository (Arbeitsbaum auf Zweig `fix/review-stephdl`, gleicher Stand wie `feat/initial-module` plus lokale Änderungen; nichts geändert), Dev-Domäne AD.EXAMPLE.TEST (samba1), Testclient testclient (nur lesend).

Kennzeichnung: **[Beleg]** = selbst geprüft (Befehl/Ausgabe) oder Primärquelle; **[Quelle]** = Doku verlinkt, nicht selbst getestet; **[Annahme]** = Fachwissen/Erfahrung, vor Umsetzung testen.

---

## 0. Stand nach Version 0.2.0

Dieser Bericht entstand am 28.09.2026 vor dem Bau. Stufe 1 ist seit Version 0.1.0-alpha.3 als Seite „Richtlinien“ im Modul enthalten und in 0.2.0 unverändert. Die folgenden Punkte halten fest, was gebaut ist und wo die Messung am Windows-11-Client den Bericht korrigiert hat. Die Abschnitte 1 bis 9 sind der ursprüngliche Bericht; korrigierte Stellen sind dort als **gemessen** markiert.

### Was gebaut ist

- **Richtlinienprofile:** Ein Profil ist eine GPO mit Einstellungen aus einem Katalog, verknüpft mit der Domäne oder mit OUs. Nur Computer-Einstellungen.
- **20 der 37 Einstellungen** aus Abschnitt 5 sind umgesetzt, dazu die Anzeige der Kennwort- und Sperrrichtlinie der Domäne. Die Spalte „Stand 0.2.0“ im Katalog zeigt, welche.
- **Änderungsliste:** Jede Änderung verlangt einen Grund und wird mit den Einstellungen vorher und nachher festgehalten.
- **Zweistufiges Entfernen:** Für Einstellungen, die auf den Rechnern stehen bleiben, schreibt das Profil zuerst die Windows-Standardwerte und wird danach gelöscht.

### Wo die Messung den Bericht korrigiert hat

| Thema | Annahme im Bericht | Gemessen mit Windows 11 25H2 | Folge im Modul |
|---|---|---|---|
| Erweiterte Überwachung (`audit.csv`) | bleibt nach dem Entfernen der GPO stehen | Windows löscht die **gesamte** Überwachung, alle 60 Unterkategorien, auch den Windows-Standard | `audit.csv` wird nicht verwendet; eine geplante Aufgabe setzt die Unterkategorien mit `auditpol`, das Zurücksetzen stellt die Standardwerte her |
| Sicherheitsoptionen über `GptTmpl.inf` | bleiben stehen, Gegenwert setzen genügt | der Wert sprang nach „zurücksetzen, dann GPO löschen“ wieder auf den Richtlinienwert | NTLMv2 und ähnliche Werte stehen in `Registry.pol`; das Zurücksetzen löscht den Wert |
| Benutzerrechte über `GptTmpl.inf` | bleiben stehen | Windows stellt den Stand von vor der GPO wieder her | kein Zurücksetzen nötig |
| Sitzungssperre, Anmeldehinweis und ähnliche Optionen | über `GptTmpl.inf` | wirken auch als `Registry.pol`-Wert unter `…\Policies\System` und werden dann von Windows entfernt | diese Einstellungen stehen in `Registry.pol` |
| Schreibschutz für Sticks ohne BitLocker | Wert außerhalb der Richtlinien-Schlüssel, bleibt stehen | Windows entfernt auch Werte unter `System\CurrentControlSet\Policies` | kein Zurücksetzen nötig |

### Was offen ist

- **Stufe 2:** Benutzer-Einstellungen mit Loopback (Bildschirmschoner, Hintergrundbild je OU), BitLocker einschalten per Skript, Anzeige der Wiederherstellungsschlüssel, Windows Update, Remotedesktop, Energie, Kamera, Telemetrie, Anzeige von Konflikten mit fremden GPOs.
- **Stufe 3:** ASR-Regeln, SMB/NetBIOS/LLMNR, LSA-Schutz und Credential Guard, lokale Administratoren, Windows LAPS.
- **Nicht getestet:** die USB-Sperre und BitLocker mit echter Hardware, Windows 10, Windows Pro.

Die DNS-Verwaltung des Moduls hat einen eigenen Bericht und ist nicht Teil dieser Seite.

## 1. Kurzfazit

**Machbar: ja, weitgehend.** Rund 28 der 37 vorgeschlagenen Einstellungen (Abschnitt 5) lassen sich rein über Dateien im SYSVOL (Registry.pol, GptTmpl.inf, audit.csv, GPP-XML) umsetzen – Samba-AD ist dafür nur Ablage und Verteiler, die Auswertung macht der Windows-Client selbst. Samba 4.19 (DC) bzw. 4.22 (Werkzeug-Container) bringt sogar fertige Python-Parser für alle nötigen Formate mit. **Teilweise machbar** sind: BitLocker *einschalten* (nur per Skript, die GPO allein verschlüsselt nicht), Hintergrundbild je OU auf Windows Pro (nur über Loopback + Benutzerrichtlinie), Credential Guard/Telemetrie-Stufe 0/Store-Sperre (nur Enterprise/Education). **Nicht ohne Weiteres**: Windows LAPS (Schema-Erweiterung fehlt in der Dev-Domäne, irreversibel, nur unverschlüsselte Ablage mit Samba), Kontosperre/Kennwortrichtlinie für Domänenkonten (wirkt bei Samba nicht über GPO, sondern über `samba-tool domain passwordsettings` bzw. die NS8-Oberfläche).

**Grober Aufwand** (eine Person, inkl. Tests auf testclient):

| Block | Aufwand |
|---|---|
| Schreibseite verallgemeinern (User-Version, gPCUserExtensionNames, Pfad-Whitelist, CSE-Registrierung/-Entfernung, Registry.pol/GptTmpl/audit.csv-Erzeuger) | 4–6 PT |
| Richtlinienkatalog (≈30 Einträge als Daten: Schlüssel, Typ, Parameter, Edition, Risiko) + Unit-Tests | 3–4 PT |
| UI-Seite „Richtlinien" (Profile, Gruppen, Ziel-OUs, Ist-Zustand, Konfliktanzeige) + Actions | 5–7 PT |
| BitLocker-Aktivierungsskript + Schlüssel-Anzeige (Admin-Aktion) | 2–3 PT |
| Test/Abnahme je Einstellung auf Pro und Enterprise, Rückbau-Tests | 4–6 PT |
| **Summe Stufe 1–3** | **≈ 18–26 PT**; Stufe 1 allein ≈ 7–9 PT |

**Größte Risiken:** (1) Aussperren/Betriebsstörung durch zu harte Einstellungen (USB-Sperre trifft auch Messgeräte-Exporte, Standby/Sperre trifft Prozessrechner/Leitstand, NetBIOS/SMB-Änderungen treffen Altgeräte); (2) „Tattooing" – GptTmpl-Werte (Rechte, Sicherheitsoptionen, Audit) und GPP-Registry bleiben beim Entfernen der GPO stehen, Rückbau muss aktiv Gegenwerte setzen; (3) Konflikte mit GPOs anderer Admins (Rangfolge LSDOU, letzte gewinnt) – das Modul kann nur anzeigen, nicht verhindern; (4) Nachvollziehbarkeit: In geregelten Umgebungen (z. B. ISO 27001 A.8.32, GMP Annex 11 §10) ist jede Richtlinienänderung eine Änderung im Sinne von Change Control – das Modul muss Änderungen protokollieren/versionieren.

---

## 2. Heutiger Stand der Schreibseite (Beleg: Code gelesen)

- `tool/gpowrite.py` (python3-samba, LDAP + SMB, Kerberos als Dienstkonto):
  - `create()` legt `groupPolicyContainer` mit `CN=User`/`CN=Machine`, SYSVOL-Ordner `Machine`/`User`, `GPT.INI` an.
  - `apply()` akzeptiert nur Pfade nach `ALLOWED_FILE_RE = ^Machine/(Preferences/ScheduledTasks/ScheduledTasks\.xml|Scripts/windeploy/…\.ps1)$`.
  - Versionszähler: `gpogen.bump_machine_version()` erhöht **nur die unteren 16 Bit** (Computer-Teil); User-Teil (obere 16 Bit) bleibt unberührt. Atomarer Vergleich per LDAP delete/add auf `versionNumber` – gut, wiederverwendbar.
  - Erweiterungsnamen: nur `gPCMachineExtensionNames`, und nur **hinzufügen** (`add_scheduled_tasks_extension`: `[{00000000-…}{CAB54552-…}][{AADCED64-…}{CAB54552-…}]`). `gPCUserExtensionNames` wird weder gelesen noch geschrieben; Entfernen einer CSE gibt es nicht.
  - Rückfall: vorherige Dateien + Version werden gesichert und bei Fehler zurückgeschrieben.
- `imageroot/pypkg/gpogen.py`: erzeugt ScheduledTasks.xml (TaskV2/ImmediateTaskV2, SYSTEM/S4U/HighestAvailable) und PowerShell-Skripte; Hilfen für Extension-Names und GPT.INI (CRLF).
- UI: Seiten Status, Verteilungen, Anleitung, Einstellungen, Info (Vue 2 / Carbon). Modell „eine GPO je Verteilung, verknüpft mit n Zielen".

**Was für Richtlinien fehlt:** User-Versionszähler, `gPCUserExtensionNames`, weitere erlaubte Pfade, Erzeuger für Registry.pol/GptTmpl.inf/audit.csv/Registry.xml/Files.xml/Groups.xml, CSE-Registrierung *und* -Deregistrierung, Lesen des Ist-Zustands fremder GPOs (für die Konfliktanzeige; Lesen darf jeder authentifizierte Benutzer).

**Guter Befund [Beleg]:** Das Werkzeug-Image `windeploy-samba` (Debian 13, python3-samba **4.22.11**) enthält bereits `samba.gp_parse.gp_pol` (Registry.pol), `gp_inf` (GptTmpl.inf), `gp_csv` (audit.csv), `samba.policies.RegistryGroupPolicies` (inkl. `increment_gpt_ini(machine_changed, user_changed)`, `register_extension_name`/`unregister_extension_name`) sowie das NDR-Format `samba.dcerpc.preg`. Probe im Container: ein PReg mit einem DWORD wird korrekt erzeugt (`82 Bytes, Kopf b'PReg\x01\x00\x00\x00'`). Auf dem DC gibt es zusätzlich `samba-tool gpo load/remove` (JSON → Registry.pol, pflegt Version und Extension-Names). Es muss also **kein Binärformat selbst geschrieben werden**; man kann entweder `samba.policies` direkt nutzen oder – wegen der eigenen, sauberen Versions-/Rollback-Logik – nur die Parser verwenden und die bestehende `apply()`-Transaktion erweitern (Empfehlung).

---

## 3. Technische Mechanismen, die zusätzlich nötig sind

CSE = Client Side Extension (erste GUID einer Gruppe in `gPC*ExtensionNames`), Tool = Snap-in-GUID (weitere GUIDs der Gruppe). Die Gruppen müssen sortiert sein; das Modul macht das bereits (`format_extension_names`).

| Mechanismus | Datei im GPO-Ordner | CSE-GUID + Tool-GUID | Computer/Benutzer | Aufwand | Anpassung Schreibseite |
|---|---|---|---|---|---|
| **Administrative Vorlagen (Registry.pol, PReg)** | `Machine/Registry.pol`, `User/Registry.pol` | `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` + Machine-Tool `{D02B1F72-3407-48AE-BA88-E8213C6761F1}` bzw. User-Tool `{D02B1F73-3407-48AE-BA88-E8213C6761F1}` | beides | mittel (1–1,5 PT; Parser vorhanden, Merge/Löschlogik `**del.`-Einträge bauen) | User-Version + `gPCUserExtensionNames` **zwingend** für User-Teil |
| **Sicherheitsvorlage (GptTmpl.inf)**: Kennwort-/Sperrrichtlinie (lokale Konten), `[Privilege Rights]` (z. B. SeSystemtimePrivilege), `[Registry Values]` (Sicherheitsoptionen wie InactivityTimeoutSecs, LegalNoticeText), `[Group Membership]` (Eingeschränkte Gruppen), `[Service General Setting]` | `Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf` (UTF-16LE mit BOM, `[Unicode] Unicode=yes`, `[Version] signature="$CHICAGO$" Revision=1`) | `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` + `{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}` | nur Computer | mittel (1 PT) | Pfad freigeben, CSE registrieren; nur Machine-Version |
| **Erweiterte Überwachungsrichtlinie** | `Machine/Microsoft/Windows NT/Audit/audit.csv` | `{F3CCC681-B74C-4060-9F26-CD84525DCA2A}` + `{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}` | Computer | klein (0,5 PT; `gp_csv` vorhanden). Zusätzlich in GptTmpl `MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1` | Pfad + CSE |
| **GPP Registrierung** (Registry.xml) | `Machine|User/Preferences/Registry/Registry.xml` | `{B087BE9D-ED37-454F-AF9C-04291E351182}` + `{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}` (Tool zusätzlich unter Null-GUID, wie heute bei Scheduled Tasks) | beides | klein (0,5 PT; Aufbau wie ScheduledTasks.xml) | Pfad + CSE (+ User) |
| **GPP Dateien** (Files.xml) – z. B. Hintergrundbild lokal kopieren | `Machine/Preferences/Files/Files.xml` | `{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}` + `{3BAE7E51-E3F4-41D0-853D-9BB9FD47605F}` | beides | klein | Pfad + CSE; Quelle = Datei im SYSVOL/NETLOGON (Upload nötig) |
| **GPP Ordner** (Folders.xml) | `Machine/Preferences/Folders/Folders.xml` | `{6232C319-91AC-4931-9385-E70C2B099F0E}` + `{3EC4E9D3-714D-471F-88DC-4DD4471AAB47}` | beides | klein | wie oben |
| **GPP Lokale Benutzer und Gruppen** (Groups.xml) – lokale Admins | `Machine/Preferences/Groups/Groups.xml` | `{17D89FEC-5C44-4972-B12D-241CAEF74509}` + `{79F92669-4224-476C-9C5C-6EFB4D87DF4A}` | Computer | klein–mittel | wie oben |
| **Geplante Aufgaben + Skripte** | vorhanden | `{AADCED64-746C-4633-A97C-D61349046527}` + `{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}` | Computer | vorhanden | – (für BitLocker-Aktivierung wiederverwenden) |
| **Windows-Firewall mit erw. Sicherheit** | steckt in `Machine/Registry.pol` (`Software\Policies\Microsoft\WindowsFirewall\…`) | Registry-CSE `{35378EAC-…}` + Firewall-Tool `{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}` [Annahme: GUID aus GPMC-erzeugten GPOs] | Computer | klein | nur weitere Tool-GUID |
| **Loopback-Verarbeitung** | Registry.pol-Wert `HKLM\Software\Policies\Microsoft\Windows\System\UserPolicyMode` = 1 (Zusammenführen) / 2 (Ersetzen) | Registry-CSE | Computer-Wert, bewirkt, dass der **User-Teil** von GPOs an der Computer-OU für jeden Benutzer an diesem Rechner gilt | klein | setzt voraus: User-Teil schreibbar (s. o.) |
| **WMI-Filter** | LDAP-Objekt `msWMI-Som` unter `CN=SOM,CN=WMIPolicy,CN=System,…` + Attribut `gPCWQLFilter` an der GPO | – | – | mittel (1 PT) + Rechte: Dienstkonto braucht Schreibrecht auf `CN=SOM` | Container existiert in der Dev-Domäne [Beleg], 0 Filter vorhanden. **Nicht empfohlen**: WMI-Filter verlangsamen die Anmeldung; Edition/OS lieber im Skript bzw. per GPP-Item-Level-Targeting prüfen |
| **ADMX-Central-Store** | `Policies/PolicyDefinitions` im SYSVOL | – | – | 0 für das Modul | **Nicht nötig** – der Client wertet Registry.pol ohne ADMX aus; ADMX braucht nur, wer die GPO später in der GPMC ansehen/bearbeiten will. Dev-Domäne hat keinen Central Store [Beleg]. Optional: `samba-tool gpo admxload` oder Windows-ADMX-Paket kopieren |

**Änderungen an der Schreibseite im Einzelnen:**
1. `bump_user_version()` analog zu `bump_machine_version()` (obere 16 Bit, Umbruch auf 1); `apply()` bekommt `machine_changed`/`user_changed` aus den geänderten Pfaden.
2. `gPCUserExtensionNames` lesen/sichern/schreiben (Backup + Rollback erweitern).
3. `ALLOWED_FILE_RE` durch eine Whitelist je Mechanismus ersetzen (Machine/User Registry.pol, SecEdit/GptTmpl.inf, Audit/audit.csv, Preferences/{Registry,Files,Folders,Groups}/*.xml, Dateiablage für Bilder).
4. CSE-Tabelle statt einer fest verdrahteten CSE; **Deregistrierung**, wenn eine Datei gelöscht wird (sonst Ereignis-/Leistungsballast, aber kein Fehler).
5. Große Dateien (Hintergrundbilder) per SMB schreiben – vorhanden; Größenlimit und Bildformatprüfung in der Action.
6. Richtlinien-GPOs **getrennt** von Verteilungs-GPOs halten (eine GPO je Richtlinienprofil), damit Rückbau/Verknüpfung unabhängig bleiben.
7. Rechte: Das Dienstkonto ist Ersteller/Besitzer seiner GPOs (Gruppe in „Richtlinien-Ersteller-Besitzer") – reicht für alle obigen Dateien. Für WMI-Filter und für BitLocker-Schlüssel **lesen** reicht es nicht (s. 4.4).

---

## 3a. Domänen-Kennwortrichtlinie: Sonderfall Samba [Beleg]

- Die Default Domain Policy der Dev-Domäne besteht im SYSVOL **nur aus GPT.INI** (Version 0); es gibt keine GptTmpl.inf. Die Extension-Names sind trotzdem eingetragen (Samba-Provisionierung).
- Wirksam für Domänenkonten sind die Attribute am Domänenobjekt: `samba-tool domain passwordsettings show` →
  Komplexität an, Historie 24, Mindestlänge 7, Höchstalter 180 Tage, **Sperrschwelle 0 (= keine Kontosperre!)**, Sperrdauer 30 min.
- Samba wendet GptTmpl `[System Access]` nur an, wenn `apply group policies = yes` und `samba-gpupdate` auf dem DC läuft ([samba-gpupdate(8)](https://www.mankier.com/8/samba-gpupdate), [Group Policy on Linux – Password and Kerberos Policies](https://dmulder.github.io/group-policy-book/sec.html)); in NS8 ist das nicht gesetzt [Beleg: `testparm -s`].
- **Konsequenz:** Kennwort-/Sperrrichtlinie für Domänenkonten gehört **nicht** in die GPO-Seite, sondern in die NS8-Samba-Verwaltung bzw. `samba-tool domain passwordsettings set` (feiner: PSOs via `samba-tool domain passwordsettings pso`). Die windeploy-Seite kann den Ist-Wert **anzeigen** und warnen („keine Kontosperre"). In GptTmpl an einer OU wirkt `[System Access]` nur auf **lokale** Konten der Rechner.

---

## 4. Pflicht-Detailprüfungen

### 4.1 Desktopsperre nach 3 Minuten

| Variante | Mechanismus | Wirkung |
|---|---|---|
| **A – Computerrichtlinie** „Interaktive Anmeldung: Inaktivitätsgrenze des Computers" | GptTmpl `[Registry Values]`: `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,180` | Sperrt jede interaktive Sitzung nach 180 s ohne Maus-/Tastatureingabe, unabhängig vom Benutzer. Gültig 0–599940 s ([Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit)) |
| **B – Benutzerrichtlinie** Bildschirmschoner | User-Registry.pol `HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop`: `ScreenSaveActive="1"`, `ScreenSaverIsSecure="1"`, `ScreenSaveTimeOut="180"` (REG_SZ), optional `SCRNSAVE.EXE="scrnsave.scr"` | Wirkt nur für Benutzer, auf deren GPO-Pfad die Richtlinie liegt: GPO an der **Benutzer-OU** oder an der Computer-OU **mit Loopback** |

**Was greift ohne Loopback wirklich?** Wird die GPO – wie bei windeploy üblich – an eine **Computer-OU** gehängt, wirkt nur Variante A. Der User-Teil einer an der Computer-OU verknüpften GPO wird ohne Loopback ignoriert. **Empfehlung:** Variante A als Standard (einfach, OU-genau, gilt auch für lokale Konten); Variante B nur zusätzlich, wenn Benutzer die Sperre nicht per Einstellungen umgehen sollen (A ist nicht umgehbar, B verhindert zusätzlich das Abschalten des Bildschirmschoners).
**Stolpersteine [Annahme, testen]:** Anwendungen, die Anzeige-Wachhalten anfordern (Videos, Präsentationen, manche Leitstand-/SCADA-Software) können die Sperre verzögern; für Prozess-/Visualisierungsrechner (Leitstand, Messplätze) eigene OU mit längerem oder ohne Timeout. 3 min ist für viele Arbeitsplätze streng; Regelwerke verlangen in der Regel eine angemessene, dokumentierte Frist (z. B. ISO 27001 A.7.7, GMP Annex 11 §12).

### 4.2 USB-Sticks: sperren oder nur BitLocker-verschlüsselt

| Variante | Registry (Computer) | Ergebnis |
|---|---|---|
| **Sperren** | `HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Deny_All=1` (alle Wechselmedien-Klassen) oder feiner `…\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\Deny_Read=1 / Deny_Write=1` (Klasse „Wechseldatenträger") | Kein Lesen/Schreiben; betrifft **auch** BitLocker-Sticks. Tastatur/Maus/Scanner sind **nicht** betroffen (keine Massenspeicherklasse). WPD-Geräte (Handys, Kameras) haben eigene Klassen-GUIDs |
| **Nur BitLocker beschreibbar** | `HKLM\System\CurrentControlSet\Policies\Microsoft\FVE\RDVDenyWriteAccess=1`; optional `HKLM\Software\Policies\Microsoft\FVE\RDVDenyCrossOrg=1` + `IdentificationField=1`, `IdentificationFieldString="<Firmenkennung>"` | Unverschlüsselte Sticks: **nur lesen** (Windows bietet an, den Stick zu verschlüsseln). Mit `RDVDenyCrossOrg` nur Sticks mit eigener Organisationskennung beschreibbar ([Microsoft Learn – Configure BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure), [windows-security.org](https://www.windows-security.org/cac6047f7ef8d778d49993f1e1a9165c/deny-write-access-to-removable-drives-not-protected-by-bitlocker)) |

**„Nur zulassen, wenn BitLocker-verschlüsselt" im strengen Sinn (auch kein Lesen unverschlüsselter Sticks) ist mit Bordmitteln per GPO nicht möglich** – das könnte nur Defender Device Control (Defender for Endpoint/Intune-Lizenz). Machbar ist: **Lesen erlaubt, Schreiben nur auf (eigene) BitLocker-Sticks**. Beide Varianten zu kombinieren ist widersprüchlich (Deny_All sperrt auch die BitLocker-Sticks); sinnvoll sind zwei OU-Profile: „USB gesperrt" (Reinraum/Labor-PC) und „USB nur verschlüsselt schreiben" (Büro/Laptop).
Zusatz: `RDVConfigureBDE=1`, `RDVAllowBDE=1` (Benutzer darf Sticks verschlüsseln), `RDVEncryptionType`, `EncryptionMethodWithXtsRdv=4` (AES-CBC 128, damit Sticks an älteren Rechnern lesbar bleiben). Audit „Wechselmedien" (audit.csv) als Nachweis.
**Stolperstein:** Messgeräte/Waagen, die Daten per USB-Stick exportieren, und Datenlogger (z. B. Klima-/Temperatur-Logger) – vor Einführung inventarisieren. Änderungen an RemovableStorageDevices wirken erst beim nächsten Einstecken, teils erst nach Neustart [Annahme].

### 4.3 BitLocker aktivieren

- **GPO allein verschlüsselt nicht [Quelle]:** Die Einstellung „Require device encryption" gibt es nur als CSP (`./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption`), bei GPO steht ausdrücklich „Not available" ([Configure BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure)). Ohne MDM braucht es ein Skript.
- **Weg über den vorhandenen Mechanismus:** geplante Aufgabe (SYSTEM, beim Start + täglich) mit PowerShell:
  1. `Get-Tpm` → `TpmPresent`, `TpmReady`; sonst abbrechen und protokollieren (kein Passwort-/USB-Schlüssel-Fallback ohne Absprache).
  2. `Get-BitLockerVolume -MountPoint $env:SystemDrive` → bereits verschlüsselt/läuft? dann nur Schutz- und AD-Sicherung prüfen.
  3. `Add-BitLockerKeyProtector -RecoveryPasswordProtector` → `Backup-BitLockerKeyProtector -KeyProtectorId …` (bzw. automatisch durch Richtlinie `OSRequireActiveDirectoryBackup`).
  4. `Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -TpmProtector -UsedSpaceOnly -SkipHardwareTest` (Hardware-Test erzwingt sonst Neustart vor Beginn).
  5. Ergebnis ins Ereignisprotokoll/Logdatei, damit die Statusseite es zeigen kann.
- **Dazu die Richtlinien (Registry.pol, `HKLM\Software\Policies\Microsoft\FVE`):** `EncryptionMethodWithXtsOs=7` (XTS-AES 256), `OSRecovery=1`, `OSRecoveryPassword=2`, `OSRecoveryKey=2`, `OSActiveDirectoryBackup=1`, `OSActiveDirectoryInfoToStore=1` (Kennwort + Schlüsselpaket), `OSRequireActiveDirectoryBackup=1` („erst aktivieren, wenn im AD gesichert"), analog `FDV…` für Datenlaufwerke; `UseAdvancedStartup=1`, `UseTPM=2`, `EnableBDEWithNoTPM=0` [Annahme: Werte aus VolumeEncryption.admx, im Test verifizieren].
- **Pro vs. Enterprise [Quelle]:** BitLocker-Verwaltung wird laut Microsoft auf Pro, Enterprise, Pro Education, Education unterstützt ([Configure BitLocker – Edition requirements](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure)). Die Lizenz-Tabelle dort nennt „Pro: No" nur für die *Management-Lizenzberechtigung* (MDM/MBAM-Szenarien); GPO + Skript funktioniert auf Pro. Home kennt nur „Geräteverschlüsselung".
- **Risiken:** Firmware/TPM-Updates und BIOS-Änderungen führen zur Wiederherstellungsabfrage → Schlüssel muss vorher im AD liegen (daher `OSRequireActiveDirectoryBackup`). VMs ohne vTPM werden übersprungen (testclient hat ein vTPM [Beleg]). Windows 11 24H2+ verschlüsselt oft schon selbst mit ausgesetztem Schutz (testclient: `FullyEncrypted`, Schutz `Off`, XTS-AES 128 [Beleg]) – das Skript muss diesen Zustand übernehmen statt neu zu verschlüsseln.

### 4.4 BitLocker-Wiederherstellung im AD (Samba) [Beleg]

- **Schema:** Dev-Domäne hat `objectVersion: 88` (Schema-Stand Windows Server 2019), Funktionsebene 2008 R2. Vorhanden: `msFVE-RecoveryInformation` (Klasse, `systemPossSuperiors: computer`), `msFVE-RecoveryPassword`, `msFVE-RecoveryGuid`, `msFVE-VolumeGuid`, `msFVE-KeyPackage`, `msTPM-OwnerInformation`, `msTPM-InformationObject`, `msTPM-InformationObjectsContainer` u. a.
- **Vertraulichkeit:** `msFVE-RecoveryPassword`, `msFVE-KeyPackage`, `msTPM-OwnerInformation` haben `searchFlags: 664` = 0x298 → enthält 0x80 **CONFIDENTIAL** (+ RODC-gefiltert). Lesen nur mit Control-Access (Domänen-Admins). Samba hatte hier Lücken (CVE-2018-10919, [CVE-2023-0614](https://www.samba.org/samba/security/CVE-2023-0614.html), behoben ab 4.16.10/4.17.7/4.18.1); DC läuft 4.19.5 → behoben.
- **ACL – darf der Computer das Kindobjekt anlegen?** Ja. Die Klasse `computer` hat im `defaultSecurityDescriptor` `(A;;CCDC;;;PS)` = SELF darf beliebige Kindobjekte anlegen/löschen; am Objekt `CN=TESTCLIENT,OU=Testrechner` ist dieses ACE tatsächlich vorhanden. `msFVE-RecoveryInformation` erbt dann `(A;;GA;;;DA)(A;;GA;;;SY)` aus seinem Default-SD. Das entspricht dem Windows-Standard; **keine Delegation nötig**. (Nur die alte TPM-Owner-Sicherung ins Computerobjekt brauchte früher ein Zusatz-ACE; seit Windows 10 1607 wird der TPM-Owner-Hash nicht mehr gesichert.)
- **Ist-Zustand:** TESTCLIENT hat noch **keine** Kindobjekte (kein Schlüssel im AD).
- **Schlüssel später lesen:**
  - auf dem DC: `runagent -m samba1 podman exec samba-dc ldbsearch -H /var/lib/samba/private/sam.ldb -b "CN=<PC>,OU=…" "(objectClass=msFVE-RecoveryInformation)" msFVE-RecoveryPassword whenCreated` (lokaler sam.ldb-Zugriff = System, umgeht ACL).
  - von Windows: RSAT „BitLocker-Wiederherstellungskennwort-Viewer" in ADUC (als Domänen-Admin) funktioniert mit Samba [Annahme, verbreitete Praxis].
  - **Im Modul:** Das windeploy-Dienstkonto darf die Attribute absichtlich **nicht** lesen. Eine Anzeige in der Modul-UI braucht entweder eine NS8-Action, die im samba-Modul per `ldbsearch` liest (Cluster-Admin-Recht, jeder Abruf protokolliert), oder eine gezielte Delegation (Control Access auf `msFVE-RecoveryPassword` für eine Helpdesk-Gruppe). Empfehlung: Suchfeld „Schlüssel-ID (erste 8 Zeichen) → Kennwort" als protokollierte Admin-Aktion, Stufe 2.

### 4.5 NTP / Zeitquelle [Beleg]

- Im Container `samba-dc` läuft **chronyd** (`chronyd -d -x`, setzt die Uhr nicht selbst) mit `local stratum 2`, `allow` und `ntpsigndsocket /var/lib/samba/ntp_signd`; Samba-Task `ntp_signd` läuft; UDP 123 lauscht auf dem Knoten (Container-chronyd). Die Zeit kommt vom Host-chronyd (Stratum 3, synchron, Abweichung < 0,1 ms).
- Damit liefert der DC **signierte NTP-Antworten (MS-SNTP)**, die Windows-Domänenmitglieder im Standardmodus **NT5DS (Domänenhierarchie)** verlangen. **Es braucht grundsätzlich keine GPO**: Domänenmitglieder synchronisieren sich per Standard mit dem DC.
- **Nicht** empfohlen: `Type=NTP` + `NtpServer=dc1…,0x8` – dann unsignierte Anfragen und bei mehreren DCs keine automatische Umschaltung.
- Sinnvoll als Absicherung (Registry.pol, `HKLM\Software\Policies\Microsoft\W32Time\Parameters`): `Type="NT5DS"` erzwingen, `…\TimeProviders\NtpClient\Enabled=1`, `SpecialPollInterval` (z. B. 3600 s), `…\W32Time\Config\MaxPosPhaseCorrection`/`MaxNegPhaseCorrection` (z. B. 3600 s, damit große Sprünge protokolliert statt still korrigiert werden) [Annahme: Werte aus W32Time.admx]. Nutzen: Eine lokale Änderung durch Admins wird zurückgestellt; Nachweis zuverlässiger Zeitstempel (z. B. ISO 27001 A.8.17, GMP Annex 11).
- Ergebnis auf testclient [Beleg]: Quelle `dc1.ad.example.test`, Typ NT5DS, synchron – siehe Abschnitt 7.

### 4.6 Uhrzeit-Änderung verbieten

- GptTmpl `[Privilege Rights]`:
  `SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19` (Administratoren, LOKALER DIENST)
  `SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19` (Standard enthält zusätzlich *S-1-5-32-545 Benutzer)
- **Befund [Quelle]:** Standardbenutzer haben `SeSystemtimePrivilege` auf Clients **bereits nicht** (Standard: Administratoren + LOKALER DIENST). Die Richtlinie ist also vor allem Absicherung/Nachweis und wirkt gegen lokale Admins **nicht** (Admins können sich Rechte zurückholen). Die Zeitzone darf standardmäßig jeder Benutzer ändern – das berührt die UTC-Zeit und Audit-Zeitstempel nicht, aber die Anzeige.
- **Stolperstein:** User-Rights-Zuweisung **ersetzt** die Liste (kein Ergänzen). Laptops auf Reisen brauchen ggf. die Zeitzonenwahl (dann nur SeSystemtimePrivilege setzen). Werte bleiben nach Entfernen der GPO stehen (Tattoo, s. 6.3).

### 4.7 Hintergrundbild je OU

| Weg | Edition | Details |
|---|---|---|
| **Loopback + Benutzerrichtlinie „Desktophintergrund"** | alle (Pro, Enterprise) | GPO an Computer-OU: Machine `UserPolicyMode=1`; User-Registry.pol `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\Wallpaper="C:\ProgramData\windeploy\wallpaper.jpg"`, `WallpaperStyle="4"` (Füllen) [Annahme Stilwerte]. Bild per **GPP Dateien** (Computer) aus `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\Machine\windeploy\wallpaper.jpg` lokal kopieren – ein UNC-Pfad direkt als Wallpaper führt bei Offline-Laptops zu Schwarz |
| **PersonalizationCSP** (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP`: `DesktopImagePath`, `DesktopImageUrl`, `DesktopImageStatus=1`) per GPP Registry | **nur Enterprise/Education** (Pro nur im SharedPC-/Education-Modus) [Quelle: [Personalization CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/personalization-csp)] | reine Computereinstellung, kein Loopback; auf Pro ohne Wirkung |
| Sperrbildschirm (`Software\Policies\Microsoft\Windows\Personalization\LockScreenImage`) | Enterprise/Education | optional |

**Empfehlung:** Loopback-Weg als Standard, weil er auf Pro und Enterprise funktioniert; OU-Abhängigkeit ergibt sich aus der Verknüpfung (je OU ein Profil mit eigenem Bild). Loopback **Zusammenführen** (1), nie Ersetzen (2), sonst fallen Benutzer-GPOs anderer Admins weg. Voraussetzung: Schreibseite mit User-Teil (Abschnitt 3). Upload-Feld für JPG/PNG (Größenlimit ~5 MB).

### 4.8 Windows LAPS mit Samba-AD [Beleg + Quelle]

- **Schema der Dev-Domäne:** weder `ms-LAPS-*` (Windows LAPS) noch `ms-Mcs-AdmPwd` (Legacy LAPS) vorhanden [Beleg: ldbsearch im Schema, 0 Treffer].
- **Unterstützt? – ja, mit Einschränkungen [Quelle: [Tranquil IT – Windows LAPS für Samba-AD](https://samba.tranquil.it/doc/en/samba_advanced_methods-samba_configure_laps.html)]:** Schema per LDIF (ldbadd/ldbmodify mit `dsdb:schema update allowed = true`) auf dem Schema-Master erweitern bzw. `Update-LapsADSchema` gegen Samba (ab 4.19 mit gesetzter Option), danach `Set-LapsADComputerSelfPermission` / `Set-LapsADReadPasswordPermission` von einem Windows-Rechner mit RSAT.
- **Einschränkungen:** (1) **Keine Passwortverschlüsselung** mit Samba (`ADPasswordEncryptionEnabled=0` zwingend); Microsoft verlangt dafür ohnehin Domänenfunktionsebene 2016 ([LAPS-Architektur](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)) – die Dev-Domäne ist 2008 R2. Damit auch **kein Passwortverlauf**. (2) Schema-Erweiterung ist **nicht rückbaubar**. (3) Rollback-Erkennung (`msLAPS-CurrentPasswordVersion`) gibt es nur mit Server-2025-Schema.
- **Client-Richtlinie** (Registry.pol, `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS`): `BackupDirectory=2`, `PasswordComplexity=4`, `PasswordLength=16`, `PasswordAgeDays=30`, `PostAuthenticationActions=3`, `PostAuthenticationResetDelay=8`, optional `AdministratorAccountName`. Clients: Windows 10 22H2 ab April-2023-Update, Windows 11 alle.
- **Bewertung: gelb/rot.** Nutzen hoch (keine gleichen lokalen Admin-Kennwörter), aber Schema-Eingriff im Produktiv-AD, Klartextablage (nur ACL-geschützt) und Lesen nur über RSAT/ldbsearch. Empfehlung: **Stufe 3**, eigener Auftrag mit Test auf Dev (Schema-Änderung dort zuerst), nicht Teil der Richtlinienseite v1. Das Modul könnte später nur die Client-Richtlinie setzen, wenn es das Schema erkennt.

---

## 5. Einstellungskatalog (37 Einträge)

Legende Machbarkeit: 🟩 grün = rein über SYSVOL-Dateien, Samba-neutral, geringes Risiko · 🟨 gelb = machbar mit Einschränkungen (Edition, Loopback, Nebenwirkungen, Skript) · 🟥 rot = nicht über GPO/Samba oder nur mit AD-Eingriff.
C = Computer, U = Benutzer (an Computer-OU nur mit Loopback). Aufwand je Eintrag bei fertiger Mechanik: S (< 2 h), M (½–1 T), L (> 1 T).
Das Modul ist auf kein Regelwerk zugeschnitten; die Bezüge sind Beispiele dafür, wo solche Einstellungen verlangt werden. **ISO** = ISO/IEC 27001:2022 Anhang A; **A11** = EU-GMP Leitfaden Anhang 11 (§7 Datenspeicherung, §9 Audit-Trail, §10 Änderungsmanagement, §12 Sicherheit, §16 Business Continuity); **P11** = 21 CFR Part 11 (11.10(c) Schutz der Aufzeichnungen, (d) Zugriffsbeschränkung, (e) Audit-Trail mit Zeitstempel, (g) Berechtigungsprüfung, 11.300 Kennwortkontrollen). Die Zuordnung ist fachliche Einschätzung, keine Rechtsberatung.

| # | Einstellung | Stand 0.2.0 | Zweck / Regelwerk (Beispiele) | Mechanismus (Pfad / Wert) | C/U | Machbarkeit | Aufwand | Besonderheiten / Stolpersteine |
|---|---|---|---|---|---|---|---|---|
| 1 | **Automatische Sitzungssperre 3 min** | umgesetzt | Sicherheit; A11 §12, P11 11.10(d); ISO A.7.7, A.8.1 | GptTmpl `[Registry Values]` `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,180` | C | 🟩 | S | Wert je OU einstellbar; Prozessrechner/Leitstand ausnehmen; s. 4.1 |
| 2 | Bildschirmschoner mit Kennwort (Erzwingen) | offen | ergänzt #1; A11 §12; ISO A.7.7 | User-Registry.pol `HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop` `ScreenSaveActive="1"`, `ScreenSaverIsSecure="1"`, `ScreenSaveTimeOut="180"` | U | 🟨 | S | nur mit Loopback (#3) oder GPO an Benutzer-OU |
| 3 | Loopback-Verarbeitung (Zusammenführen) | offen | Technik für OU-abhängige Benutzereinstellungen | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\System\UserPolicyMode=1` | C | 🟩 | S | nur Modus 1; nie automatisch für ganze Domäne; verlängert Anmeldung minimal |
| 4 | **USB-Massenspeicher sperren** | umgesetzt | Datenabfluss/Malware; A11 §7, §12; ISO A.7.10, A.8.12 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Deny_All=1` (oder Klasse `{53f5630d-…}` `Deny_Read`/`Deny_Write`) | C | 🟩 | S | sperrt auch BitLocker-Sticks; Messgeräte-Exporte prüfen; HID nicht betroffen |
| 5 | **Schreiben nur auf BitLocker-Sticks** | umgesetzt | Datenintegrität/-vertraulichkeit; A11 §7; ISO A.7.10, A.8.24 | Registry.pol `HKLM\System\CurrentControlSet\Policies\Microsoft\FVE\RDVDenyWriteAccess=1`; opt. `HKLM\Software\Policies\Microsoft\FVE\RDVDenyCrossOrg=1`, `IdentificationField=1`, `IdentificationFieldString` | C | 🟩 | S | Lesen unverschlüsselter Sticks bleibt erlaubt (strenger nur mit Defender for Endpoint); nicht mit #4 kombinieren |
| 6 | BitLocker-Richtlinie (Verfahren, Wiederherstellung, **AD-Sicherung erzwingen**) | umgesetzt | Schutz bei Diebstahl; A11 §7, §16; ISO A.8.24 | Registry.pol `HKLM\Software\Policies\Microsoft\FVE`: `EncryptionMethodWithXtsOs=7`, `OSRecovery=1`, `OSActiveDirectoryBackup=1`, `OSActiveDirectoryInfoToStore=1`, `OSRequireActiveDirectoryBackup=1`, FDV-Pendants | C | 🟩 | M | Schema + SELF-CCDC in Samba vorhanden [Beleg]; Schlüssel nur als Admin lesbar |
| 7 | **BitLocker aktivieren** (Skript) | offen | wie #6; ISO A.8.24 | vorhandene geplante Aufgabe + PS-Skript (`Get-Tpm`, `Enable-BitLocker -TpmProtector -UsedSpaceOnly`, Recovery-Password + AD-Backup) | C | 🟨 | M | GPO allein verschlüsselt nicht (CSP-only); TPM nötig; Pro/Enterprise ok; Status-Rückmeldung in UI |
| 8 | Zeitsynchronisation Domänenhierarchie erzwingen | umgesetzt | Zeitstempel; P11 11.10(e), A11 §9; ISO A.8.17 | Registry.pol `HKLM\Software\Policies\Microsoft\W32Time\Parameters\Type="NT5DS"`, `…\TimeProviders\NtpClient\Enabled=1`, `SpecialPollInterval` | C | 🟩 | S | Standard ist schon NT5DS; DC liefert signiertes NTP [Beleg]; kein `Type=NTP` |
| 9 | **Systemzeit ändern nur Admins** | umgesetzt | Zeitstempel-Integrität; P11 11.10(e); ISO A.8.17 | GptTmpl `[Privilege Rights] SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19` | C | 🟩 | S | Standardbenutzer haben das Recht ohnehin nicht; Tattoo |
| 10 | Zeitzone ändern nur Admins | umgesetzt | Anzeigekonsistenz; ISO A.8.17 | GptTmpl `SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19` | C | 🟩 | S | Reise-Laptops ausnehmen |
| 11 | **Hintergrundbild je OU** | offen | Kennzeichnung Rechner je Bereich, Corporate | Loopback (#3) + User-Registry.pol `…\Policies\System\Wallpaper`, `WallpaperStyle`; Bild per GPP Files lokal | U (+C) | 🟨 | M | Pro nur so; Enterprise alternativ PersonalizationCSP; Upload-Funktion nötig |
| 12 | Domänen-Kennwortrichtlinie + **Kontosperre** | Anzeige | P11 11.300, A11 §12; ISO A.5.17, A.8.5 | **nicht GPO**: `samba-tool domain passwordsettings set --account-lockout-threshold=10 …` bzw. NS8-UI; PSOs für Gruppen | – | 🟥 (für GPO) / 🟩 (Samba) | S | Dev: Sperrschwelle **0** [Beleg]; Modul zeigt nur an/warnt |
| 13 | Kontosperre für lokale Konten | offen | lokale Brute-Force; ISO A.8.5 | GptTmpl `[System Access] LockoutBadCount=10, ResetLockoutCount=15, LockoutDuration=15` | C | 🟩 | S | wirkt an OU nur auf lokale SAM-Konten; Win 11 22H2+ hat 10/10 schon als Standard |
| 14 | Anmeldebanner (Rechtshinweis) | umgesetzt | Nutzungsbedingungen, Hinweis auf geltende Regeln; ISO A.5.10 | GptTmpl `…\Policies\System\LegalNoticeCaption=1,"…"`, `LegalNoticeText=7,…` | C | 🟩 | S | verzögert Auto-Logon/Kiosk; Text in UI pflegbar |
| 15 | Letzten Benutzernamen nicht anzeigen | umgesetzt | Sicherheit, Shared-PC; ISO A.8.5 | GptTmpl `…\Policies\System\DontDisplayLastUserName=4,1` | C | 🟩 | S | an Schicht-PCs evtl. unpraktisch |
| 16 | Strg+Alt+Entf erforderlich; Sperrbildschirm zeigt Benutzer | umgesetzt | A11 §12 (Zuordnung der Sitzung); ISO A.8.5 | GptTmpl `DisableCAD=4,0`, `DontDisplayLockedUserId=4,1` (Name anzeigen) | C | 🟩 | S | Angezeigter Sitzungsinhaber hilft bei geteilten PCs |
| 17 | Microsoft-Konten blockieren | umgesetzt | keine privaten Konten/Cloud-Anmeldung; ISO A.5.23 | GptTmpl `…\Policies\System\NoConnectedUser=4,3` | C | 🟩 | S | betrifft auch Store-Apps mit MS-Konto |
| 18 | Windows Update steuern (Zeitfenster, Aufschub, Zielversion) | offen | A11 §10 Änderungsmanagement, Sicherheit; ISO A.8.8, A.8.32 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU` `NoAutoUpdate=0`, `AUOptions=4`, `ScheduledInstallTime=3`, `NoAutoRebootWithLoggedOnUsers=1`; `…\WindowsUpdate\TargetReleaseVersion=1`, `ProductVersion="Windows 11"`, `TargetReleaseVersionInfo="24H2"`, `DeferQualityUpdatesPeriodInDays` | C | 🟩 | M | Validierte Systeme: eigenes OU-Profil mit Aufschub/Freigabe; kein WSUS vorhanden |
| 19 | Defender Echtzeitschutz/PUA erzwingen | umgesetzt | Malware; A11 §12; ISO A.8.7 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows Defender\PUAProtection=1`, `…\Real-Time Protection\DisableRealtimeMonitoring=0`, `…\Spynet\SpynetReporting` | C | 🟩 | S | `DisableAntiSpyware` ist wirkungslos; Manipulationsschutz nicht per GPO; Fremd-AV beachten |
| 20 | Defender ASR-Regeln (Office-Makros, Credential-Diebstahl aus LSASS …) | offen | Härtung; ISO A.8.7 | Registry.pol `…\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules=1`, `…\ASR\Rules\<GUID>="1"` (erst `"2"` = Audit) | C | 🟨 | M | zuerst Audit-Modus; Fach- und Laborsoftware kann blockiert werden; Berichte ohne E5 nur im Ereignisprotokoll |
| 21 | Firewall für alle Profile erzwingen | umgesetzt | Netzsegmentierung; ISO A.8.20 | Registry.pol `HKLM\Software\Policies\Microsoft\WindowsFirewall\{Domain,Private,Public}Profile\EnableFirewall=1`, `DefaultInboundAction=1`, Logging | C | 🟩 | S | eigene Regeln (RDP, winrm, SSH für testclient!) mitliefern, sonst Fernwartung weg |
| 22 | SMBv1 aus, SMB-Signatur erzwingen | offen | Härtung (WannaCry etc.); ISO A.8.9, A.8.20 | Registry.pol/GPP: `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start=4`; GptTmpl `MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1` | C | 🟨 | S | SMBv1 ist unter Win 11 meist nicht installiert; alte NAS/Scanner/Messgeräte mit SMB1 brechen; Samba-DC signiert |
| 23 | LLMNR aus, NetBIOS aus | offen | Namensvergiftung (Responder); ISO A.8.20 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0`; NetBIOS: `…\DNSClient\EnableNetbios=0` (nur Win 11 22H2+ ADMX) [Annahme] | C | 🟨 | S | Geräte, die nur per NetBIOS-Name erreichbar sind; Win 10: NetBIOS nur per Skript je Adapter |
| 24 | NTLMv1/LM verbieten | umgesetzt | Härtung; ISO A.8.5 | GptTmpl `MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5` | C | 🟩 | S | Samba-DC kann NTLMv2; Alt-Geräte prüfen |
| 25 | LSA-Schutz (RunAsPPL) | offen | Schutz der Anmeldedaten; ISO A.8.5 | Registry.pol `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL=1` (bzw. ADMX „LSASS als geschützter Prozess", Win 11 22H2+) | C | 🟨 | S | Treiber/Smartcard-Middleware; Neustart nötig; Pro ok |
| 26 | Credential Guard | offen | Pass-the-Hash; ISO A.8.5 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity=1`, `LsaCfgFlags=2` | C | 🟥 (Pro) / 🟨 (Ent) | S | **nur Enterprise/Education**; auf Pro wirkungslos; `LsaCfgFlags=1` (UEFI-Sperre) nicht rückbaubar per GPO |
| 27 | **Erweiterte Überwachung** (Anmeldung, Kontosperrung, Gruppen-/Kontoverwaltung, Richtlinienänderung, Prozesserstellung inkl. Befehlszeile, Wechselmedien) | umgesetzt | Audit-Trail; A11 §9, P11 11.10(e); ISO A.8.15, A.8.16 | `audit.csv` + GptTmpl `SCENoApplyLegacyAuditPolicy=4,1` + Registry.pol `…\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=1` | C | 🟩 | M | Volumen beachten; Tattoo; zentrale Sammlung fehlt (kein WEF-Kollektor unter Linux) |
| 28 | Ereignisprotokollgrößen | umgesetzt | Audit-Trail-Aufbewahrung; A11 §9, §17; ISO A.8.15 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize=196608` (KB), `Application`/`System` 32768 | C | 🟩 | S | ersetzt keine Archivierung; fachliche Audit-Trails liegen meist in der Anwendung |
| 29 | PowerShell-Protokollierung (Script Block, optional Transkript) | umgesetzt | Nachvollziehbarkeit, Angriffserkennung; ISO A.8.15 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=1`; `…\Transcription\EnableTranscripting=1`, `OutputDirectory` | C | 🟩 | S | windeploy-Skripte landen selbst im Protokoll (keine Geheimnisse hineinschreiben) |
| 30 | Autorun/AutoPlay aus | umgesetzt | Malware über Medien; ISO A.8.7 | Registry.pol `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun=255`, `NoAutorun=1`; `HKLM\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume=1` | C | 🟩 | S | risikolos |
| 31 | Lokale Administratoren festlegen | offen | Rechtetrennung; A11 §12, P11 11.10(g); ISO A.8.2 | GPP Groups.xml (Aktion „Aktualisieren": Gruppe `<DOM>\PC-Admins` hinzufügen, `Domain Users` entfernen) statt GptTmpl `[Group Membership]` (ersetzt komplett) | C | 🟨 | M | falsch konfiguriert = Aussperren/lokale Admins weg; LAPS fehlt als Ausweg |
| 32 | Remotedesktop: aus oder nur mit NLA + Leerlauftrennung | offen | Fernzugriff kontrollieren (Fernwartung durch Dienstleister); ISO A.8.20 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections=1` bzw. `=0` + `UserAuthentication=1`, `MinEncryptionLevel=3`, `MaxIdleTime` | C | 🟩 | S | Firewallregel passend (#21); Dienstleisterzugang als eigenes Profil |
| 33 | Energie: Kennwort beim Aufwachen, Standby-Zeiten je OU | offen | #1 absichern; Prozessrechner wach halten; ISO A.7.7 | Registry.pol `HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex=1/DCSettingIndex=1`; Standby `…\29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA\ACSettingIndex=<s>` | C | 🟩 | S | Datenerfassungs-PCs (Klima, Bewässerung) **nie** in Standby |
| 34 | OneDrive/Cloud-Sync unterbinden oder auf Firmentenant beschränken | umgesetzt | Datenintegrität/-ablage; A11 §7; ISO A.5.23, A.8.12 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC=1` (bzw. `…\Microsoft\OneDrive\AllowTenantList`) | C | 🟩 | S | Nextcloud-Client bleibt erlaubt |
| 35 | Kamera/Mikrofon für Apps sperren | offen | Reinraum/Datenschutz; ISO A.5.34 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsAccessCamera=2`, `LetAppsAccessMicrophone=2`; `…\Microsoft\Camera\AllowCamera=0` | C | 🟩 | S | Videokonferenz-Arbeitsplätze ausnehmen; Desktop-Apps teilweise nicht erfasst |
| 36 | Telemetrie minimieren | offen | Datenschutz; ISO A.5.34 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry=1` (Pro-Minimum) / `0` (nur Enterprise) | C | 🟨 | S | Wert 0 auf Pro = wie 1 |
| 37 | Druckspooler-Härtung (Point-and-Print nur Admins, keine eingehenden Spooler-Verbindungen) | umgesetzt | PrintNightmare; ISO A.8.8, A.8.9 | Registry.pol `HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators=1`; `…\Printers\RegisterSpoolerRemoteRpcEndPoint=2` | C | 🟩 | S | Druckertreiber dann per windeploy/winget oder Admin verteilen |

(Mehr als 30, weil 2/3, 9/10 und 12/13 zusammengehören; #26 und #36 sind für Pro nur eingeschränkt sinnvoll. Nicht aufgenommen: WMI-Filter, AppLocker/WDAC (zu hohes Aussperr-Risiko für v1, AppLocker-Erzwingung nur Enterprise), Store-Sperre (`RemoveWindowsStore` nur Enterprise und stört winget-Quellen), Windows Hello for Business (braucht PKI/Entra).)

---

## 6. Risiken

### 6.1 Aussperren / Betriebsunterbrechung
- **Kontosperre** (Domäne): Dienstkonten mit altem Kennwort (Scanner, NAS-Freigaben, Fachanwendungen) sperren Konten wiederholt. Vor Einführung `badPwdCount` beobachten; Schwelle 10, Dauer 15 min. Die Modul-Seite setzt die Domänenrichtlinie ohnehin nicht (3a).
- **USB-Sperre**: nur Massenspeicher; Tastatur/Maus/Barcode-Scanner (HID) bleiben – aber USB-Dongles für Lizenzen (Massenspeicher-Modus!), Messgeräte, Datenlogger können betroffen sein.
- **Firewall/RDP/SMB/NetBIOS/NTLM**: Fernwartung (SSH/RDP), Altgeräte. Profil erst an OU=Testrechner, dann schrittweise.
- **Lokale Admins (Groups.xml)**: falsche SID → niemand mehr lokal Admin. Immer „Aktualisieren", nie „Alle Mitglieder löschen".
- **Sitzungssperre/Standby** an Prozessrechnern: Visualisierung dunkel oder gesperrt; eigene OU.
- **BitLocker**: Wiederherstellungsabfrage nach BIOS-Update ohne gesicherten Schlüssel = Datenverlust → `OSRequireActiveDirectoryBackup` Pflicht, Test der Schlüssel-Lesbarkeit vor Rollout.

### 6.2 Konflikte mit bestehenden GPOs anderer Admins
- Rangfolge Lokal → Standort → Domäne → OU (tiefere OU gewinnt, innerhalb derselben Ebene die höhere Linkreihenfolge; „Erzwungen" schlägt alles). Das Modul kann fremde GPOs **lesen** (Authenticated Users haben Leserecht) und sollte für jede Einstellung anzeigen: „wird auch gesetzt von GPO X (Wert Y) an Ziel Z". Registry.pol und GptTmpl.inf fremder GPOs lassen sich mit den Samba-Parsern auswerten.
- User-Rights (GptTmpl `[Privilege Rights]`) **ersetzen** sich gegenseitig vollständig – die gewinnende GPO bestimmt die ganze Liste.
- Loopback im Modus Ersetzen würde fremde Benutzerrichtlinien ausschalten – nicht anbieten.
- Das Modul verknüpft seine GPOs heute ans Ende der gPLink-Liste [Annahme aus Code]; für Richtlinien sollte die Reihenfolge sichtbar und wählbar sein.

### 6.3 Rückbau („Tattooing")
| Mechanismus | Beim Entfernen/Entknüpfen der GPO |
|---|---|
| Registry.pol unter `Software\Policies`, `…\CurrentVersion\Policies`, `System\CurrentControlSet\Policies` | wird entfernt (sauber) |
| Registry.pol außerhalb dieser Zweige (z. B. `mrxsmb10\Start`, `Lsa\RunAsPPL`, `PersonalizationCSP`) | **bleibt** stehen |
| GptTmpl.inf, Benutzerrechte | **gemessen:** Windows stellt den Stand von vor der GPO wieder her |
| GptTmpl.inf, Sicherheitsoptionen als Registry-Wert | **gemessen:** bleibt stehen und sprang nach einer zurücksetzenden GPO wieder auf den Richtlinienwert; das Modul schreibt solche Werte deshalb als Registry.pol und löscht sie beim Zurücksetzen |
| audit.csv | **gemessen:** Windows löscht beim Entfernen der GPO die gesamte Überwachung, auch den Windows-Standard; das Modul verwendet audit.csv deshalb nicht |
| GPP (Registry.xml, Files.xml, Groups.xml) | bleibt, **außer** Element hat „Entfernen, wenn nicht mehr angewendet" (`removePolicy="1"`, Aktion Ersetzen) – das nutzt windeploy schon für Aufgaben |
| BitLocker-Verschlüsselung | bleibt (gewollt) |

Folge: Das Modul braucht für jede tattooing-Einstellung eine **„Zurücksetzen"-Variante**, die den Windows-Standardwert aktiv schreibt (z. B. `SeTimeZonePrivilege` inkl. Benutzer, `InactivityTimeoutSecs=0`, Audit „Keine Überwachung"), und erst danach das Profil löscht. Das ist im Katalog je Eintrag als `default`-Wert zu hinterlegen.

### 6.4 Testbarkeit
- testclient (Win 11, OU=Testrechner) reicht für die meisten Punkte: `gpresult /h`, `rsop`, Registry lesen, `auditpol /get /category:*`, `secedit /export`, `w32tm /query /status`, `manage-bde -status`.
- Nicht testbar ohne weitere Clients: Enterprise-only-Punkte (#26, PersonalizationCSP), Windows 10, physisches TPM/BitLocker auf echter Hardware (VM braucht vTPM), USB-Verhalten (USB-Durchreichung in Proxmox möglich).
- Automatisierbar: Unit-Tests für Erzeuger (Registry.pol byte-genau gegen GPMC-Referenz, wie schon für ScheduledTasks gemacht), QEMU-/Integrationstest „GPO schreiben → Dateien + versionNumber + ExtensionNames prüfen".
- Nachweis: pro Profil ein kurzer Test-/Freigabenachweis, Export der wirksamen Einstellungen (`gpresult /h`) als Nachweis; Modul sollte Änderungen mit Zeit, Benutzer, alt/neu protokollieren (z. B. ISO 27001 A.8.32).

---

## 7. Befunde auf testclient (nur lesend)

Abfrage am 2026-09-28 um 23:25 Ortszeit per SSH, ausschließlich lesende Befehle (`w32tm /query`, `Get-Tpm`, `Get-BitLockerVolume`, `Get-ItemProperty`, `Get-Command`, `gpresult /r`, `auditpol /get`). Keine Änderung, kein gpupdate. [Beleg]

| Prüfpunkt | Ergebnis | Bedeutung |
|---|---|---|
| Betriebssystem | **Windows 11 Enterprise Evaluation**, 10.0.26200 (25H2) | Enterprise-only-Punkte testbar, **Pro-Verhalten nicht** – für Pro einen zweiten Testclient einplanen |
| Zeitquelle | `w32tm /query /source` → `dc1.ad.example.test`; Referenz 192.0.2.10, Stratum 3, letzte Sync 23:20:33; `Type: NT5DS`, `SpecialPollInterval 3600`, `MaxPos/NegPhaseCorrection 4294967295` (unbegrenzt) | Domänenhierarchie mit signiertem NTP funktioniert **ohne GPO**. Einzige sinnvolle GPO-Ergänzung: Phasenkorrektur begrenzen (#8). Auffällig: „Stammabweichung 8,67 s" (Root Dispersion) – chrony im Container meldet sich als `local stratum 2`; beobachten, bei strengen Anforderungen an Zeitstempel ggf. chrony im Container auf echte Quelle/Host-Referenz umstellen [Annahme zur Ursache] |
| TPM | `TpmPresent/Ready/Enabled = True` (vTPM) | BitLocker-Skript testbar |
| BitLocker C: | `FullyEncrypted`, **`ProtectionStatus Off`**, `XtsAes128` | Windows 11 24H2+ verschlüsselt automatisch („Geräteverschlüsselung", Klarschlüssel wartet auf Schlüsselsicherung). Das Aktivierungsskript muss diesen Zustand erkennen: TPM- und Wiederherstellungs-Schutz hinzufügen, ins AD sichern, dann `Resume-BitLocker`; ein Wechsel auf XTS-AES 256 geht nur durch Entschlüsseln/Neuverschlüsseln → Richtlinie #6 vor der Installation bzw. 128 Bit akzeptieren |
| Schlüssel im AD | TESTCLIENT hat keine `msFVE-RecoveryInformation`-Kinder [Beleg DC] | konsistent mit „Schutz aus" |
| Sicherheitsoptionen | `InactivityTimeoutSecs` nicht gesetzt, `DontDisplayLastUserName=0`, kein Anmeldebanner, `NoConnectedUser` nicht gesetzt | Ausgangszustand sauber für Tests #1, 14–17 |
| Windows LAPS | Modul `LAPS` vorhanden (u. a. `Update-LapsADSchema`, `Set-LapsADComputerSelfPermission`, `Get-LapsADPassword`); keine LAPS-Richtlinie | Client-Seite bereit; Schema fehlt (4.8) |
| SMBv1 | Server `EnableSMB1Protocol = False`, Dienst `mrxsmb10` nicht vorhanden | #22 für Win 11 nur Absicherung |
| Credential Guard / LSA | `VirtualizationBasedSecurityStatus 2` (läuft), `SecurityServicesRunning {1}` = Credential Guard aktiv; `RunAsPPL = 2` | Enterprise 22H2+ aktiviert beides standardmäßig; auf Pro nicht – #25/#26 vor allem für Pro-/Altgeräte bzw. zum Festschreiben |
| LmCompatibilityLevel | nicht gesetzt (Standard 3) | #24 sinnvoll |
| Wechselmedien / PersonalizationCSP | keine Schlüssel vorhanden | sauberer Ausgangszustand |
| Audit | „Anmelden: Erfolg und Fehler" (Windows-Standard) | #27 erweitert gezielt |
| GPOs | angewendet: 7 windeploy-GPOs; **„Default Domain Policy" herausgefiltert** (leer: Version 0, nur GPT.INI) | bestätigt 3a: Domänenrichtlinie kommt bei Samba nicht aus der GPO |


---

## 8. Vorschlag UI-Seite „Richtlinien"

**Aufbau (neue Route `/policies`, Menü zwischen „Verteilungen" und „Anleitung"):**
1. **Kopf – Domänen-Ist-Zustand** (nur lesen): Kennwortrichtlinie/Kontosperre der Domäne (Warnung „keine Kontosperre"), Zeitquelle des DC (chrony/ntp_signd ok), BitLocker-Schema vorhanden, LAPS-Schema vorhanden ja/nein, Central Store ja/nein.
2. **Profile** (Karten/Liste wie Verteilungen): ein Profil = eine GPO „windeploy-Richtlinie: <Name>", verknüpft mit 1..n Zielen (Domänenwurzel/OUs, dieselbe Auswahl wie bei Verteilungen). Vorlagen: „Basis-Sicherheit (alle PCs)", „Arbeitsplatz mit erhöhten Anforderungen", „Prozess-/Leitstandsrechner", „Laptop".
3. **Profil bearbeiten** – Einstellungen in Gruppen (Akkordeon), je Eintrag Schalter + ggf. Parameter (Minuten, Text, Bild, Gruppenname) + Symbol für Edition (Pro/Ent), Tattoo-Hinweis und Risiko-Stufe:
   - Anmeldung & Sperre (#1–3, 14–17, 33)
   - Wechselmedien & BitLocker (#4–7)
   - Zeit (#8–10)
   - Darstellung (#11)
   - Updates & Schutz (#18–21, 30, 37)
   - Netzwerk & Protokolle (#22–24, 32)
   - Konten & Rechte (#13, 25–26, 31)
   - Protokollierung / Audit-Trail (#27–29)
   - Datenschutz & Cloud (#34–36)
4. **Vorschau/Diff vor dem Speichern**: welche Dateien/Werte sich ändern, alte → neue Version; Pflichtfeld „Änderungsgrund" (Änderungsnachweis, im Modul-Log gespeichert).
5. **Wirksamkeit & Konflikte** je Ziel: Liste aller an diesem Ziel und darüber verknüpften GPOs; je Einstellung „gewinnt"/„überschrieben von X". Optional Rückmeldung der Clients (Skript schreibt Ergebnis in eine Datei/Freigabe – später).
6. **Deaktivieren/Entfernen** zweistufig: „Auf Windows-Standard zurücksetzen" (schreibt Gegenwerte, Version+1) → nach Ablauf eines Aktualisierungszyklus „Profil löschen".
7. **BitLocker-Schlüssel suchen** (Stufe 2): Rechnername oder Schlüssel-ID → Wiederherstellungskennwort, nur für Cluster-Admins, jeder Abruf im Log.

**Datenmodell:** Katalog als JSON/Python-Daten im Modul (id, gruppe, mechanismus, ziel C/U, pfad, wertname, typ, parameter-schema, default-rückbau, edition, risiko, beschreibung de/en, quelle). Actions: `list-policy-catalog`, `list-policy-profiles`, `save-policy-profile`, `remove-policy-profile`, `get-policy-effective <target>`, (Stufe 2) `get-bitlocker-key`.

**Stufen:**
- **Stufe 1 (schnell, risikoarm, ≈ 7–9 PT):** Schreibseite für Machine-Registry.pol + GptTmpl.inf + audit.csv; Profile/Verknüpfung; Einstellungen #1, 4 oder 5, 6, 8, 9, 10, 14, 15, 16, 17, 19, 21 (nur Erzwingen + Regeln für RDP/SSH), 24, 27, 28, 29, 30, 34, 37; Anzeige Domänen-Kennwortrichtlinie.
- **Stufe 2 (≈ 6–9 PT):** User-Teil + Loopback (#2, 3, 11 mit Bild-Upload/GPP Files), BitLocker aktivieren (#7) mit Status, BitLocker-Schlüssel-Anzeige, Windows Update (#18), RDP (#32), Energie (#33), Kamera (#35), Telemetrie (#36), Konfliktanzeige für fremde GPOs, Rückbau-Automatik.
- **Stufe 3 (≈ 5–8 PT + AD-Eingriff):** ASR (#20), SMB/NetBIOS/LLMNR (#22, 23), LSA-Schutz/Credential Guard (#25, 26), lokale Admins (#31), Windows LAPS (eigener Auftrag, Schema), ggf. WMI-/Editionsfilter.

---

## 9. Quellen

- Microsoft Learn: [Interactive logon: Machine inactivity limit](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit)
- Microsoft Learn: [Configure BitLocker (Richtlinien, Editionen, RequireDeviceEncryption nur CSP)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure)
- Microsoft Learn: [Personalization CSP (Editionen)](https://learn.microsoft.com/en-us/windows/client-management/mdm/personalization-csp), [Configure desktop and lock screen backgrounds](https://learn.microsoft.com/en-us/windows/configuration/background/)
- Microsoft Learn: [Windows LAPS architecture (DFL 2016 für Verschlüsselung, Rollback-Attribut nur Server-2025-Schema)](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview), [LAPS technical reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- Microsoft Learn: [LocalPoliciesSecurityOptions CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions)
- RDVDenyWriteAccess/RDVDenyCrossOrg: [windows-security.org](https://www.windows-security.org/cac6047f7ef8d778d49993f1e1a9165c/deny-write-access-to-removable-drives-not-protected-by-bitlocker), [Microsoft New-CMRDVDenyWriteAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/configurationmanager/new-cmrdvdenywriteaccesspolicy?view=sccm-ps)
- Samba: [samba-gpupdate(8)](https://www.mankier.com/8/samba-gpupdate), [SambaWiki Group Policy](https://wiki.samba.org/index.php/Group_Policy), [Group Policy on Linux – Password and Kerberos Policies](https://dmulder.github.io/group-policy-book/sec.html), [CVE-2023-0614 (vertrauliche Attribute/BitLocker)](https://www.samba.org/samba/security/CVE-2023-0614.html), [Samba 4.8.4 (CVE-2018-10919)](https://www.samba.org/samba/history/samba-4.8.4.html)
- LAPS mit Samba: [Tranquil IT – Configuring LAPS for Samba-AD](https://samba.tranquil.it/doc/en/samba_advanced_methods-samba_configure_laps.html), [samba-Mailingliste LAPS support (2023)](https://lists.samba.org/archive/samba/2023-April/244920.html)
- Eigene Prüfungen (Dev-Domäne, 2026-09-28): `samba --version` (4.19.5), Schema-`objectVersion` 88, DFL 2008 R2, `ldbsearch` auf msFVE/msTPM/msLAPS, computer-`defaultSecurityDescriptor` und SD von CN=TESTCLIENT, `samba-tool domain passwordsettings show`, `testparm -s`, chrony-Konfiguration im Container samba-dc, python3-samba 4.22.11 im Werkzeug-Image mit PReg-Probe.
