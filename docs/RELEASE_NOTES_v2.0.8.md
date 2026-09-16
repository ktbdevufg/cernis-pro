# CERNIS PRO 2.0.8

**Veröffentlicht:** August 2026

Diese Version macht sichtbar, woraus CERNIS PRO besteht: Jeder mitgelieferte Bestandteil ist im Programm mit seiner Lizenz und seinem Wortlaut nachlesbar, jedes Paket bringt dieselben Angaben als Beilage mit, und der Quelltext liegt dem Release bei. Dazu behebt sie einen Fehler, der auf macOS den Start ohne Internetverbindung verhinderte.

---

## Was neu ist

### Der Bereich Über CERNIS PRO

CERNIS PRO führt einen neuen Bereich, erreichbar über die Kopfzeile. Er zeigt die Fassung des Programms, seine eigene Lizenz und – das ist der eigentliche Zuwachs – eine vollständige Aufstellung aller mitgelieferten Bestandteile Dritter.

Für jeden Bestandteil steht dort, unter welcher Lizenz er steht und wer ihn geschrieben hat. Der vollständige Lizenztext lässt sich einsehen, nach Lizenzart gebündelt, im Originalwortlaut. Nichts davon wird gekürzt, umformuliert oder übersetzt.

**Wo eine Angabe nicht belegbar ist, steht das ausdrücklich da.** Bei einigen Bestandteilen liegt der Lizenztext vollständig vor, ein maschinenlesbarer Urhebervermerk aber nicht. Statt einen zu erfinden oder einen Platzhalter einzusetzen, benennt CERNIS die Lücke. Ein erfundener Urhebervermerk wäre schlimmer als eine ehrliche Leerstelle.

Ergänzend zeigt der Bereich, welche vorausgesetzten Systemprogramme auf Ihrer Installation tatsächlich gefunden wurden.

### Jedes Paket bringt die Lizenzangaben mit

Die Aufstellung liegt nicht nur im Programm, sondern in jedem Auslieferungspaket – und zwar dort, wo die jeweilige Plattform sie erwartet:

* **Debian und Ubuntu:** unter `/usr/share/doc/cernis-pro/`
* **Fedora und RHEL:** unter `/usr/share/licenses/cernis-pro/`
* **macOS:** im Programmbündel unter `Contents/Resources/`
* **Windows:** im Installationsverzeichnis

Wer die Angaben ohne laufendes Programm braucht – für eine Prüfung, ein Archiv oder eine Weitergabe –, findet sie dort mit den Bordmitteln des Systems.

### Der Quelltext liegt dem Release bei

Das Release enthält ein Quelltextarchiv mit dem vollständigen Stand, aus dem die Pakete gebaut wurden. Fassung, Änderungsstand und Prüfsumme stammen aus demselben Bauvorgang wie die Pakete selbst.

Hintergrund ist die Lizenz des Programms: Die GPLv2 verlangt bei der Weitergabe von Programmdateien, dass der zugehörige Quelltext beigegeben wird. Ein Verweis auf ein Verzeichnis im Netz erfüllt das nicht sicher – ein beiliegendes Archiv schon.

### Prüfsummen für jedes Paket

Zu jeder Paketdatei liegt eine Prüfsummendatei mit derselben Bezeichnung und der Endung `.sha256` bereit. Damit lässt sich vor der Installation nachrechnen, dass die geladene Datei unverändert ist.

Die Prüfung geht mit Bordmitteln, ohne Zusatzwerkzeug:

* **Linux:** `sha256sum -c CernisPro_2.0.8_amd64.deb.sha256`
* **macOS:** `shasum -a 256 -c CernisPro_2.0.8_aarch64.dmg.sha256`
* **Windows:** `Get-FileHash CernisPro_2.0.8_x64-setup.exe -Algorithm SHA256`

Bei den Vorgängerversionen war diese Möglichkeit in den Hinweisen zwar erwähnt, aber nicht bereitgestellt. Das ist mit dieser Version eingelöst.

### macOS: der Erststart braucht keine Internetverbindung mehr

**Dies war eine echte Fehlfunktion, und sie betraf die Vorgängerversion 2.0.7.** Wer sie auf einem Mac ohne Internetverbindung installierte, konnte sie nicht starten: macOS meldete, die Beglaubigung lasse sich nicht überprüfen, und bot als einzige Möglichkeit an, das Programm in den Papierkorb zu legen.

Die Ursache lag in der Auslieferung, nicht im Programm. Die Beglaubigung durch Apple war vorhanden, der Nachweis dafür war aber nur an das Installationsabbild geheftet, nicht an das Programm selbst. Solange der Rechner online war, holte macOS die Bestätigung bei Apple – ohne Netz fehlte sie.

Ab dieser Version tragen sowohl das Installationsabbild als auch das Programm einen eigenen, angehefteten Nachweis. **Der Start ohne Internetverbindung funktioniert damit.** Der Punkt entfällt aus der Liste der bekannten Einschränkungen, in der er seit 2.0.6 geführt wurde.

---

## Bekannte Einschränkungen

Diese Punkte sind uns bekannt, gemessen und für eine der nächsten Versionen vorgesehen. Keiner davon führt zu Datenverlust, und für jeden gibt es einen Weg.

### Aufzeichnungen zeigen nach Ablauf ihrer Höchstdauer weiterhin läuft

Erreicht eine Aufzeichnung – Live-Monitoring oder Außenkontakte – die eingestellte Höchstdauer, wird die Datensammlung wie vorgesehen beendet, die Anzeige wechselt jedoch nicht in den Zustand abgeschlossen. Die aufgezeichneten Daten sind vollständig und stehen unverändert zur Auswertung bereit; die Aufzeichnung lässt sich jederzeit über Stopp abschließen.

### Ein gelöschtes Überwachungsziel erscheint bis zum Neustart weiter in der Liste

Wird ein Ziel im Live-Monitoring gelöscht, verschwindet es aus der Ansicht, taucht beim erneuten Öffnen jedoch wieder auf – dann unter seiner technischen Kennung. Es wird nicht mehr überwacht und beeinflusst keine Messwerte. Nach einem Neustart der Anwendung ist es vollständig entfernt.

### macOS: Gerätenamen können in einzelnen Scans fehlen

Bei mehreren Scans kurz hintereinander kann es vorkommen, dass ein einzelner Scan keine Gerätenamen anzeigt. Der Gerätebestand behält die zuvor ermittelten Namen unverändert; ein erneuter Scan zeigt sie wieder. Ein erfundener Name wird nie angezeigt – bleibt ein Name unbekannt, bleibt das Feld leer.

### macOS: das Fehlerprotokoll enthält wiederholte Hinweise

Unter macOS schreibt CERNIS in bestimmten Fällen eine wiederkehrende Hinweiszeile in sein Fehlerprotokoll. Auf den Betrieb hat das keine Auswirkung.

### Fedora und RHEL: die Lizenzdateien tragen keine Kennzeichnung

Die Lizenzbeilage liegt im rpm-Paket am vorgesehenen Ort und ist vollständig lesbar. Sie ist dort jedoch nicht als Lizenzdatei markiert, weshalb der Befehl `rpm -qL cernis-pro` nichts ausgibt. Ursache ist eine Grenze des verwendeten Paketwerkzeugs, die sich ohne Änderung an diesem Werkzeug nicht beheben lässt. Die Dateien selbst finden Sie unter `/usr/share/licenses/cernis-pro/`.

### Der Durchsatz je Programm wird auf macOS und Windows nicht angezeigt

Das ist keine Einschränkung dieser Version, sondern eine bewusste Festlegung – sie sei hier der Vollständigkeit halber genannt:

* **Auf macOS** stellt das Betriebssystem die nötige Auskunftsstelle nicht bereit. Das lässt sich nicht freischalten.
* **Unter Windows** gibt das Betriebssystem diese Zahlen nur an Programme heraus, die dauerhaft mit erhöhten Rechten laufen. **Genau darauf verzichtet CERNIS bewusst.** Ein Programmteil, der ständig mit erhöhten Rechten mitläuft, wäre ein Sicherheitsrisiko, das in keinem Verhältnis zum Gewinn einer einzelnen Zahlenspalte steht.

In beiden Fällen wird vollständig angezeigt, **welches** Programm mit **welcher** Gegenstelle spricht – nur nicht, wie viel dabei fließt. Wo eine Angabe fehlt, steht ein Gedankenstrich statt einer erfundenen Null.

### SSDP-Dienste können hinter einer Firewall unsichtbar bleiben

Manche Linux-Distributionen filtern in ihrer Standardeinstellung die Antworten, mit denen sich Geräte per SSDP und UPnP melden. CERNIS zeigt die Spalte dann leer, obwohl die Geräte antworten. Die Anfrage selbst verlässt den Rechner; verworfen werden die Antworten. mDNS ist davon nicht betroffen.

### Windows: die Programmdateien sind nicht signiert

Für Windows liegt dem Projekt kein Signaturzertifikat vor. Windows kann deshalb beim Start des Installers eine Warnung anzeigen. Die Prüfsumme jedes Pakets liegt dem Release bei und lässt sich vor der Installation abgleichen.

### Auf ARM-Linux wird kein AppImage ausgeliefert

Das AppImage-Format lief auf keinem geprüften Linux-System zuverlässig und wird seit Version 2.0.5 nicht mehr ausgeliefert. Verwenden Sie stattdessen das deb- oder rpm-Paket.

---

## Die Pakete dieser Version

| Plattform | Datei |
|---|---|
| macOS (Apple Silicon) | CernisPro_2.0.8_aarch64.dmg |
| Linux x86-64 (Debian, Ubuntu) | CernisPro_2.0.8_amd64.deb |
| Linux x86-64 (Fedora, RHEL) | CernisPro-2.0.8-1.x86_64.rpm |
| Linux ARM64 (Debian, Ubuntu) | CernisPro_2.0.8_arm64.deb |
| Linux ARM64 (Fedora, RHEL) | CernisPro-2.0.8-1.aarch64.rpm |
| Windows x64 | CernisPro_2.0.8_x64-setup.exe |
| Windows ARM64 | CernisPro_2.0.8_arm64-setup.exe |
| Quelltext | CernisPro_2.0.8_source.tar.gz |

Zu jeder dieser Dateien liegt eine gleichnamige Prüfsummendatei mit der Endung `.sha256` bei.

---

## Zur Vorgängerversion 2.0.7

Version 2.0.7 wurde als Vorabfassung veröffentlicht und nicht freigegeben. Sie enthält denselben Funktionsumfang wie diese Version, startet auf macOS jedoch nicht ohne Internetverbindung. **Verwenden Sie stattdessen 2.0.8.**

---

## Hinweise zur Installation

**Linux:** Das Installationspaket richtet die Netzwerk-Berechtigung für den Mitschnitt-Helfer selbst ein. Sollte das Auslesen echter Domainnamen anschließend nicht verfügbar sein, prüfen Sie, ob libcap2-bin beziehungsweise libcap installiert ist.

**Windows:** Für das Auslesen echter Domainnamen und den Paketmitschnitt wird **Npcap** benötigt. CERNIS installiert es nicht mit; fehlt es, bietet die Anwendung die Nachinstallation an.

**macOS:** Beim ersten Öffnen der Außenkontakte fragt CERNIS einmalig nach Ihrer Zustimmung zum passiven Mitlesen der Domainnamen. Die Zustimmung lässt sich jederzeit widerrufen.

---

## Grundsätze, die für diese Version gelten

* **CERNIS ist passiv.** Es greift nie in den Datenverkehr ein.
* **CERNIS erweitert seine Rechte nicht, um Funktionen zu gewinnen.** Eine ehrlich benannte Lücke ist besser als eine Funktion, die auf Kosten der Sicherheit geht.
* **Fehlt eine Angabe, steht ein Gedankenstrich** – nie eine erfundene Null.
* **Was nicht belegbar ist, wird als unbelegt ausgewiesen** – nicht mit einem plausiblen Wert gefüllt.
* **Alle Einstellungen liegen in der Datenbank der Anwendung.** Es gibt keine Konfigurationsdateien, die von Hand zu pflegen wären.
