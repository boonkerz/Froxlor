# Mail-SNI für froxlor 2.3.16

Postfix und Dovecot liefern pro Mail-Hostname (z.B. `mail.example.de`) das passende
TLS-Zertifikat aus (SNI). Die Zertifikate kommen aus froxlors vorhandener
Zertifikatsverwaltung (Let's Encrypt oder hochgeladen); bei Let's Encrypt wird
`mail.<domain>` automatisch als zusätzlicher SAN in das Zertifikat der Domain
aufgenommen.

Basis: offizielles froxlor-Tag `2.3.16` (DBVERSION `202608210`), Branch
`feature/mail-sni-2.3.16`.

---

## 1. Analyse

### 1.1 Ausgangsstände

| Codebasis | Stand | Mail-SNI-Ansatz |
|---|---|---|
| froxlor offiziell | `2.3.16` (2026-10-20), = Kopf von `v2` | nichts vorhanden. Nur `system.le_renew_services` (ein LE-Zertifikat für den System-Hostnamen in Postfix/Dovecot) |
| Fork `boonkerz/Froxlor` `main` | 8 Commits „add mail conf task“ (16.–19.02.2024) auf 2.2.0-dev1 | Klassen `Cron/Mail/Dovecot.php` + `Postfix.php`, `TaskId::REBUILD_MAIL_CONF = 13`, Settings `system.mail_sni_enabled`, `mda/mta_conf_dir`, `mda/mta_reload_command`, **DBVERSION `202402190`** |
| Fork Branch `le_mail` | „custom install“ (02.06.2024) | Zusätzlich Domains mit Präfix `mail.` berücksichtigen, `ssl_fullchain_file`, DBVERSION in `Froxlor.php` auf `202402190` |
| PR #1423 (floreno) | offen, „changes requested“, Basis `v2` / 2.3.14 | `Cron/Mail/MailSni.php` (Glob über `system.customer_ssl_path`), `mail.sni_enabled`, `system.mda/mta_reload_command`, Validierung + Rollback, Fingerprint gegen Erneuerungs-Problem, **DBVERSION `202610020`** |

Fork und heutiger Upstream haben keinen gemeinsamen Git-Vorfahren mehr (kein Merge-Base);
die Analyse erfolgte über die Diffs der Fork-eigenen Commits.

### 1.2 Bereits upstream vorhanden

- Let's Encrypt via acme.sh inkl. Erneuerung (`AcmeSh`), DNS-Vorabprüfung (`system.le_domain_dnscheck`)
- Ablage der Zertifikate in `panel_domain_ssl_settings` (inkl. `ssl_fullchain_file`) und Export nach `system.customer_ssl_path` (`DomainSSL`)
- LE-Zertifikat für den **System-Hostnamen** in Postfix/Dovecot (`system.le_renew_services`, `UPDATE_LE_SERVICES`)
- Mechanismus zur Neuausstellung bei geänderter SAN-Liste (`validtodate = NULL`)

### 1.3 Fehlte (und ist jetzt implementiert)

- Postfix-SNI-Tabelle und Dovecot-`local_name`-Konfiguration je Mail-Hostname
- `mail.<domain>` im ACME-Antrag
- Synchronisation bei Domain-/Zertifikatsänderungen, Erneuerung, Deaktivierung

### 1.4 Veraltete / fehlerhafte Implementierungen im Fork

| Fork | Problem |
|---|---|
| DBVERSION `202402190` + Update-Schritt in `update_2.2.inc.php` | Konkurrierender Zweig in froxlors linearer Update-Kette → offizielles Update auf 2.3.x brach. **Nicht übernommen.** |
| `TaskId::REBUILD_MAIL_CONF = 13` | Upstream nutzt 13 inzwischen für `UPDATE_LE_SERVICES` – Kollision. **Nicht übernommen**, kein neuer Task-Typ. |
| `local_name <domain>` statt `mail.<domain>` | falscher Hostname (Ausnahme `le_mail`: separate froxlor-Domain `mail.…`) |
| Schreiben mit `fopen/fwrite` | nicht atomar, keine Sicherung, keine Validierung |
| `postconf -e tls_server_sni_maps=…` bei jedem Lauf | überschreibt ggf. Admin-Konfiguration |
| Default `service … restart` | Neustart trennt Verbindungen, bei jedem Lauf mit Inhalt |
| Inhalt nur Pfade | Erneuerung (gleiche Pfade) wird nicht erkannt; bei `postmap -F` dauerhaft altes Zertifikat |
| kein Key/Zertifikat-Abgleich, kein Ablaufdatum | defekte Paare legen Dienste beim Reload lahm |
| `ssl_fullchain_file` nur für LE gesetzt | hochgeladene Zertifikate ohne Kette |
| Änderung in `DomainSSL` (`le_mail`) | setzte `ssl_fullchain_file` immer auf `''` – wirkungslos |

### 1.5 PR #1423 – übernommene Ideen

- Settings-Namen `mail.sni_enabled`, `system.mda_reload_command`, `system.mta_reload_command`
  (gleiche Namen → falls froxlor das Feature später übernimmt, ist `Settings::AddNew()` ein No-Op)
- Validierung mit `doveconf -n` / `postfix check`, Rollback, Reload statt Restart, nur bei Änderung
- Fingerprint im generierten Inhalt → Erneuerung führt zu genau einem Rewrite + Reload
- Deaktivieren entfernt nur selbst Erzeugtes
- Dovecot 2.4-Syntax (Review-Wunsch d00p)
- Reload-Befehl als Setting, Exit-Code wird geprüft und protokolliert (Review-Wunsch d00p)

### 1.6 PR #1423 – bewusst anders gelöst

| PR #1423 | hier | Grund |
|---|---|---|
| DBVERSION `202610020` | keine DBVERSION | gleiche Kollisionsgefahr wie beim Fork |
| Glob über `system.customer_ssl_path` | Datenbank (`panel_domain_ssl_settings`) | Quelle der Wahrheit; funktioniert auch für hochgeladene Zertifikate, unabhängig vom Webserver (nginx hängt die Kette an `.crt` an) |
| alle Domains mit Zertifikat | aktive E-Mail-Domains + konfigurierbare Präfixe | Anforderung `mail.<domain>`; keine SNI-Einträge für Domains ohne Mail |
| kein ACME-Teil | `mail.<domain>` als SAN, mit Prüfungen | Anforderung |
| Sync bei jedem Tasks-Lauf | ebenso | gleich (idempotent, billig) |

---

## 2. Funktionsweise

### 2.1 Zertifikate (ACME)

`AcmeSh` wurde an zwei Stellen erweitert (`lib/Froxlor/Cron/Mail/Sni/AcmeSanProvider.php`):

1. **Beim Antrag** (`runIssueFor`): nach froxlors eigener DNS-Prüfung werden die Mail-Hostnamen
   der Domain und ihrer Alias-Domains als SAN ergänzt – nur wenn
   - die (Alias-)Domain eine aktive E-Mail-Domain ist (`isemaildomain = 1`),
   - der Hostname **keine eigene froxlor-Domain** ist (die hat ihr eigenes Zertifikat → wiederverwendet, kein doppelter Antrag),
   - A/AAAA auf eine IP dieses Systems zeigt,
   - die MX-Records nicht ausschließlich auf fremde Server zeigen (**extern betriebener Maildienst → kein Hostname**),
   - eine HTTP-01-Challenge für den Hostnamen tatsächlich erreichbar ist (Testdatei im froxlor-Challenge-Verzeichnis).
   Schlägt ein Antrag mit Mail-Hostnamen fehl, werden diese 24 h weggelassen → der nächste Versuch
   (5 Minuten später) stellt das Web-Zertifikat ohne sie aus. Das Web-Zertifikat wird also nie blockiert.
2. **Planung** (`run()`, Prüfzweig des Let's-Encrypt-Crons): bestehende LE-Zertifikate, denen
   ein validierbarer Mail-Hostname fehlt, werden über froxlors vorhandenen Mechanismus
   (`validtodate = NULL`) zur Neuausstellung markiert – max. 5 pro Lauf (Rate-Limits).
   Ein Mail-Hostname, der dauerhaft (≥ 2 Prüfungen im Abstand von 6 h) nicht mehr validierbar ist,
   wird auf demselben Weg entfernt, weil acme.sh sonst die Erneuerung des **gesamten**
   Zertifikats nicht mehr schaffen würde.

Erneuerung: acme.sh erneuert mit der gespeicherten SAN-Liste, froxlor übernimmt das Zertifikat
wie bisher in die DB – die Mail-SNI-Synchronisation erkennt den neuen Fingerprint.

Prüfergebnisse werden in `<mail.sni_cert_path>/acme-state.json` (0600) gecacht.

### 2.2 Postfix / Dovecot

Bei **jedem Lauf des Tasks-Crons** (`TasksCron::run()` → `MailSni::sync()`):

1. Aktive E-Mail-Domains und Zertifikate aus der DB lesen.
2. Für jeden Hostnamen (`mail.<domain>`, Präfixe konfigurierbar) das Zertifikat suchen:
   eigene froxlor-Domain mit diesem Namen → Zertifikat der Domain (SAN) → Alias-Ziel → Elterndomain (Wildcard).
   Verwendet wird nur, was den Hostnamen abdeckt, parsebar, zeitlich gültig ist und **zum Schlüssel passt**.
   Alles andere wird übersprungen und protokolliert. Der System-Hostname bleibt beim Standardzertifikat.
3. Schlüssel + Fullchain atomar nach `/etc/ssl/froxlor-mail-sni/<host>.key` (0600) /
   `<host>_fullchain.pem` schreiben (Verzeichnis 0700, nur bei Inhaltsänderung).
4. **Postfix**: neue Tabelle neben der aktiven bauen (`postmap -F`, umask 077, `.db` 0600),
   jeden Eintrag per `postmap -F -q` prüfen, Sicherung, atomarer `rename()`, `postfix check`;
   bei Fehler Rollback. `tls_server_sni_maps` wird nur gesetzt, wenn leer (mit main.cf-Sicherung);
   ein anderer, vorhandener Wert wird nie verändert. Version ≥ 3.4 wird geprüft.
5. **Dovecot**: Sicherung, atomares Schreiben, `doveconf -n`; bei Fehler Rollback.
   Keine doppelten `local_name`-Blöcke (ein Eintrag pro Hostname). 2.3/2.4 automatisch.
6. Reload (nie Restart) **nur** bei tatsächlicher Änderung und erfolgreicher Validierung.
   Postfix und Dovecot sind voneinander unabhängig – ein Fehler bei einem blockiert den anderen nicht.
7. Zertifikatsdateien entfallener Hostnamen erst löschen, wenn keine (ggf. wiederhergestellte)
   Konfiguration sie mehr referenziert.

Standardzertifikate (`smtpd_tls_chain_files`/`smtpd_tls_cert_file`, Dovecot `ssl_cert`) werden nie angefasst.

Abgedeckte Ereignisse: neue/geänderte/gelöschte/deaktivierte Maildomain, neues oder erneuertes
Zertifikat (Fingerprint), Deaktivierung der Funktion (generierte Dateien werden geleert,
fremde/alte Dateien bleiben unberührt).

Sicherungen: `/etc/ssl/froxlor-mail-sni/backups/<UTC-Zeitstempel>-<pid>/` (0700, letzte 20).

### 2.3 Einstellungen (Einstellungen → Mailserver)

| Setting | Default | |
|---|---|---|
| `mail.sni_enabled` | `0` | Hauptschalter |
| `mail.sni_hostnames` | `mail` | Präfixe, `@` = Domain selbst, z.B. `@,mail,imap,smtp` |
| `mail.sni_acme` | `1` | Hostnamen in LE-Zertifikate aufnehmen |
| `mail.sni_cert_path` | `/etc/ssl/froxlor-mail-sni/` | eigenes Verzeichnis (≠ `system.customer_ssl_path`) |
| `mail.sni_postfix_map` | `/etc/postfix/99-froxlor.map` | |
| `mail.sni_dovecot_conf` | `/etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf` | |
| `system.mta_reload_command` | `systemctl reload postfix` | OTP-geschützt |
| `system.mda_reload_command` | `systemctl reload dovecot` | OTP-geschützt |

### 2.4 Datenbank – warum keine Migration

- **Keine DBVERSION, kein Update-Schritt, keine Änderung an `install/`.** `panel.db_version` bleibt `202608210`.
- Es werden ausschließlich 8 Zeilen in `panel_settings` ergänzt – über `Settings::AddNew()`,
  das nur einfügt, wenn das Setting fehlt (beim ersten Cron-Lauf, beim Speichern der
  Einstellungsseite oder per `froxlor-cli froxlor:mail-sni setup`). Bestehende Werte werden nie überschrieben.
- Fügt froxlor später dieselben Settings per Update hinzu, ist das ein No-Op – keine Kollision.
- Es wird nichts gelöscht. Alt-Settings des Forks (`system.mail_sni_enabled`, `system.mda_conf_dir`,
  `system.mta_conf_dir`) werden ignoriert und von `froxlor:mail-sni status` gemeldet; sie können
  manuell entfernt werden. Ein evtl. vorhandenes `system.mda_reload_command`/`system.mta_reload_command`
  aus dem Fork wird **weiterverwendet** – enthält es `restart`, warnt `status` (siehe Installation, Schritt 4).

---

## 3. Installation / Upgrade

Voraussetzung: froxlor **2.3.16** offiziell, Datenbank bereits erfolgreich auf `202608210` aktualisiert.

```bash
# 0. Sicherung (Dateien + DB + Mail-Konfiguration)
cd /var/www/froxlor            # Installationsverzeichnis anpassen
tar czf /root/froxlor-before-mailsni.tgz . /etc/postfix /etc/dovecot
mysqldump froxlor > /root/froxlor-before-mailsni.sql

# 1. Patch anwenden (prüft vorher, ob er sauber passt)
git apply --check /root/froxlor-2.3.16-mail-sni.patch && git apply /root/froxlor-2.3.16-mail-sni.patch
#    ohne git: patch -p1 --dry-run < …patch && patch -p1 < …patch
chown -R <froxlor-user>:<froxlor-user> lib/Froxlor/Cron/Mail/Sni lib/Froxlor/Cli/MailSniCommand.php

# 2. Settings anlegen (nur fehlende; db_version bleibt unverändert)
bin/froxlor-cli froxlor:mail-sni setup

# 3. Vorschau – ändert nichts, zeigt Hostnamen, Zertifikate, Gründe fürs Überspringen
bin/froxlor-cli froxlor:mail-sni status
```

4. **Reload-Befehle prüfen**: Falls aus dem alten Fork `system.mda_reload_command = service dovecot restart`
   o.ä. in der DB steht, in den Einstellungen (Expertenmodus) auf `systemctl reload dovecot` bzw.
   `systemctl reload postfix` ändern.
5. **Bestehende Dateien**: `/etc/postfix/99-froxlor.map` und `/etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf`
   des alten Forks werden beim ersten aktiven Lauf ersetzt; die alten Versionen landen unter
   `/etc/ssl/froxlor-mail-sni/backups/`. `tls_server_sni_maps = hash:/etc/postfix/99-froxlor.map`
   ist bereits gesetzt und wird übernommen.
6. Einstellungen → Mailserver → „Mail-SNI aktivieren“. Optional sofort statt nach ≤ 5 Minuten:
   ```bash
   bin/froxlor-cli froxlor:mail-sni sync --dry-run
   bin/froxlor-cli froxlor:mail-sni sync
   ```
7. Kontrolle:
   ```bash
   openssl s_client -connect localhost:993 -servername mail.example.de </dev/null 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName
   openssl s_client -starttls smtp -connect localhost:25 -servername mail.example.de </dev/null 2>/dev/null | openssl x509 -noout -subject
   ```
   Fehlt `mail.example.de` noch im Zertifikat, plant der Let's-Encrypt-Cron die Neuausstellung
   (Status: Abschnitt „Let's Encrypt checks“ in `froxlor:mail-sni status`).

Protokoll: Meldungen mit Präfix `[mail-sni]` im froxlor-Systemlog (Cron-Logging aktivieren:
Einstellungen → Logging), detailliert mit `froxlor:mail-sni status -vv`.

Bei bisheriger Lösung mit separaten froxlor-Domains `mail.<domain>` (Branch `le_mail`): diese
Domains und ihre Zertifikate werden automatisch wiederverwendet (es wird dann kein SAN ergänzt).

### Spätere offizielle froxlor-Updates

Branch rebasen (`git rebase <neues-tag>`) bzw. den Patch neu anwenden. Da keine DBVERSION und
keine `install/`-Dateien geändert werden, bleibt froxlors Update-Kette unberührt. Konfliktpotential
nur in `AcmeSh.php`, `TasksCron.php`, `Store.php`, `150.mail.php`, `lng/*.php` (jeweils kleine Hunks).
Wird ein offizielles froxlor-Update ohne den Patch eingespielt, bleiben die generierten Dateien
statisch bestehen (Postfix/Dovecot laufen weiter), werden aber nicht mehr aktualisiert.

---

## 4. Rollback

**Funktion abschalten (empfohlen, ohne Code-Rückbau):** Einstellung deaktivieren →
nächster Tasks-Lauf leert die generierten Dateien (Tabelle bleibt gültig), lädt neu, entfernt
die Zertifikatskopien. Standardzertifikate waren nie verändert.

**Code entfernen:**
```bash
cd /var/www/froxlor
# zuerst Funktion deaktivieren und einen Tasks-Lauf abwarten (s.o.), dann:
git apply -R /root/froxlor-2.3.16-mail-sni.patch      # bzw. patch -R -p1 < …
# optional: Settings-Zeilen entfernen (froxlor selbst benötigt sie nicht)
mysql froxlor -e "DELETE FROM panel_settings WHERE settinggroup='mail' AND varname LIKE 'sni\_%';"
```
`tls_server_sni_maps` ggf. wieder entfernen (`postconf -X tls_server_sni_maps`, dann
`postfix check && systemctl reload postfix`) – nur falls froxlor ihn gesetzt hatte und die leere
Tabelle nicht mehr gewünscht ist.

**Einzelne Konfigurationsdatei zurückholen:** Sicherungen liegen unter
`/etc/ssl/froxlor-mail-sni/backups/<zeitstempel>/` (Dateiname = Pfad mit `_` statt `/`):
```bash
cp -p /etc/ssl/froxlor-mail-sni/backups/<ts>/etc_postfix_99-froxlor.map.db /etc/postfix/99-froxlor.map.db
postfix check && systemctl reload postfix
cp -p /etc/ssl/froxlor-mail-sni/backups/<ts>/etc_dovecot_conf.d_99-froxlor-vhost.ssl.conf /etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf
doveconf -n >/dev/null && systemctl reload dovecot
```
(Vorher Funktion deaktivieren, sonst überschreibt der nächste Cron-Lauf die Dateien wieder.)

**Zertifikate:** Aufgenommene `mail.*`-SANs schaden nicht. Sollen sie entfernt werden:
`mail.sni_acme` ausschalten und die Neuausstellung über froxlors eigenen Mechanismus anstoßen:
`UPDATE domain_ssl_settings SET validtodate = NULL WHERE domainid = <id>;` – der nächste
Let's-Encrypt-Lauf stellt dann ohne Mail-Hostnamen aus.

---

## 5. Tests

| Test | Ausführung |
|---|---|
| Unit (31 Tests, ohne DB, mit echten Test-Zertifikaten, Postfix/Dovecot emuliert) | `vendor/bin/phpunit -c tests/MailSni/phpunit.xml` |
| Integration: **echtes Postfix 3.6.4 + Dovecot 2.3.16** (Ubuntu 22.04), TLS-Handshake mit SNI | `docker build -t froxlor-mailsni-test tests/MailSni/integration && docker run --rm -v $PWD:/src froxlor-mailsni-test bash /src/tests/MailSni/integration/run.sh` |
| DB: offizielles 2.3.16-Schema in MariaDB, Settings/Migration, SQL, CLI, Tasks-Cron | siehe Kopf von `tests/MailSni/integration/db-test.sh` |

Abgedeckte Fälle (Anforderung → Test):

1. neue Maildomain mit gültigem Zertifikat → `testNewMailDomainWithValidCertificate`, run.sh §1
2. ohne Zertifikat → `testNewMailDomainWithoutCertificate`
3. Erneuerung → `testRenewalOfExistingCertificate`, run.sh §3 (neues Zertifikat wird ausgeliefert)
4. ungültiges Paar / unlesbar / abgelaufen → `testInvalidCertificateKeyPair`, run.sh §1
5. Entfernung → `testRemovalOfMailDomain`, run.sh §4
6. mehrere Domains/Zertifikate (eigene Subdomain, SAN, Alias, Wildcard, hochgeladen) → `testMultipleDomainsWithDifferentCertificates`
7. deaktiviert → `testDisabledFeature`, run.sh §6
8. wiederholt ohne Änderung → `testRepeatedRunWithoutChanges`, run.sh §2
9. Fehler bei Generierung/Aktivierung → `testPostfixCheckFailureRollsBack`, `testDoveconfFailureRollsBack`, `testGenerationErrors`, run.sh §5

ACME: `AcmeSanProviderTest` (SAN-Aufnahme, Alias, externe MX, fremde DNS, keine Duplikate,
Backoff, Neuausstellung/Entfernung, Limit). Nicht automatisiert getestet: echter Antrag bei
Let's Encrypt (benötigt öffentliche DNS/Erreichbarkeit) – empfohlen: zunächst mit
`system.letsencryptca = letsencrypt_test` (Staging) an einer Testdomain prüfen.
