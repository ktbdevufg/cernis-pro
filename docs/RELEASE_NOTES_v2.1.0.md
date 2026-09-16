# CERNIS PRO 2.1.0

**Veröffentlicht:** August 2026

Diese Version erweitert die Zahl der Linux-Systeme, auf denen CERNIS PRO läuft — und sagt zum ersten Mal ausdrücklich, welche das sind und welche nicht. Am Programm selbst ändert sich nichts. Was sich ändert, ist die Art, wie es gebaut und verpackt wird.

---

## Was neu ist

### CERNIS PRO läuft auf mehr Linux-Systemen

Bisher setzte die Auslieferung eine sehr aktuelle Systemgrundlage voraus — neuer, als es nötig gewesen wäre. Diese Version baut auf einer älteren, breiter tragenden Grundlage und erreicht damit deutlich mehr Systeme, ohne auf einem einzigen etwas einzubüßen.

Konkret: Die Programmdatei verlangte zuvor eine Systembibliothek in einer Fassung, die erst in den jüngsten Distributionen enthalten ist. Sie tat das, ohne die betreffenden Funktionen überhaupt zu benötigen — die Anforderung entstand allein aus der Bauumgebung. Mit dieser Version ist sie verschwunden.

**Damit kommen hinzu:** Debian 12, Ubuntu 22.04 LTS, Linux Mint 21, Zorin OS 17 und alle darauf aufbauenden Distributionen.

### Ein rpm-Paket für alle RPM-Distributionen

Paketnamen unterscheiden sich zwischen den RPM-Familien: Was Fedora `openssl-libs` nennt, heißt auf openSUSE `libopenssl3`; `libcap` heißt dort `libcap2`. Ein Paket, das nach Namen fragt, passt deshalb immer nur zu einer Familie.

Diese Version fragt stattdessen nach dem, was das Programm tatsächlich braucht — nach den Bibliotheken selbst, nicht nach den Paketen, die sie zufällig enthalten. Jede Distribution löst die Anforderung dann mit ihrem eigenen Paket auf. **Ein rpm für Fedora, RHEL, Rocky, AlmaLinux und openSUSE.**

Wo sich ein Programm nicht über eine Bibliothek ausdrücken lässt, steht eine Alternative im Paket: `(iproute or iproute2)` etwa deckt beide gebräuchlichen Namen ab.

### Die Abhängigkeitsliste wurde vollständig überprüft

Jede einzelne Anforderung beider Pakete wurde gegen den Quelltext und gegen die Paketverzeichnisse aller Zielsysteme geprüft. Das Ergebnis:

* **Vier fehlten** und wurden ergänzt: die Werkzeuge für Netzwerkschnittstellen, Erreichbarkeitsprüfung und Namensauflösung sowie eine Bibliothek für die Textdarstellung. Sie werden vom Programm aufgerufen, standen aber in keiner Liste — auf Systemen, die sie nicht ohnehin mitbringen, hätten Funktionen ohne erkennbaren Grund gefehlt.
* **Eine war überflüssig** und wurde gestrichen: `net-tools` wird unter Linux an keiner Stelle aufgerufen. Die Fundstellen im Programm betreffen ausschließlich macOS und Windows.
* **Eine wurde zur Empfehlung:** `nmap` ist für einige Prüfungen nützlich, aber nicht notwendig. Auf openSUSE liegt es nicht in den Standardquellen. Statt die Installation daran scheitern zu lassen, wird es empfohlen — CERNIS meldet sein Fehlen mit einem eigenen Fehlercode, statt still etwas anderes zu tun.

---

## Systemvoraussetzungen

**Windows**
Windows 10 oder 11, 64 Bit (x64 oder ARM64).

**macOS**
Aktuelle Fassungen auf Apple Silicon (ARM64).

**Linux — Debian-Familie (`.deb`)**
Debian 12 und neuer, Ubuntu 22.04 LTS und neuer sowie darauf aufbauende Distributionen — darunter Linux Mint, Zorin OS, Kali Linux, Parrot OS, MX Linux, elementary OS und Pop!\_OS. Für x86-64 und ARM64. Raspberry Pi OS wird in der **64-Bit-Ausgabe** unterstützt.

**Linux — RPM-Familie (`.rpm`)**
Fedora in aktuellen Fassungen, RHEL, Rocky Linux und AlmaLinux **ab Fassung 10**, openSUSE Leap 16 und Tumbleweed. Für x86-64 und ARM64.

> **Hinweis für RHEL, Rocky Linux und AlmaLinux 10:** Vor der Installation müssen die Zusatzquellen **CRB** und **EPEL** aktiviert sein. Sie liefern die Bibliothek für die Programmoberfläche und die Anbindung an die Symbolleiste.
>
> ```
> sudo /usr/bin/crb enable
> sudo dnf install epel-release
> ```

---

## Was ausdrücklich nicht unterstützt wird

Diese Liste ist keine Bequemlichkeit, sondern eine Aussage: Auf diesen Systemen läuft CERNIS PRO nicht, und wir sagen das lieber, als es offenzulassen.

### RHEL, Rocky Linux, AlmaLinux 9 und älter, sowie CentOS

CERNIS PRO braucht für seine Oberfläche eine bestimmte Schnittstelle der Systemkomponente, die Webinhalte darstellt. RHEL 9 und seine Ableger führen ausschließlich deren Vorgängerfassung — und werden das bis zum Ende ihrer Laufzeit im Jahr 2032 tun, weil der Hersteller innerhalb einer Hauptfassung keine neue Schnittstelle nachreicht.

Das ist keine Frage der Zeit oder des Aufwands. Das Programmgerüst, auf dem CERNIS PRO aufbaut, hat die ältere Schnittstelle Anfang 2023 aufgegeben; die entsprechende Anfrage im dortigen Projekt liegt seit über zwei Jahren unbearbeitet.

Der Messteil von CERNIS PRO wäre auf diesen Systemen durchaus lauffähig — nur die Oberfläche ist es nicht. Ob sich daraus eine Betriebsart ohne eigenes Fenster ergibt, wird geprüft. Eine Zusage ist das nicht.

### Ubuntu 20.04 und älter, Debian 11 und älter

Dort fehlen die Entwicklungsgrundlagen, gegen die CERNIS PRO überhaupt gebaut werden kann.

### 32-Bit-Systeme

Es werden keine 32-Bit-Pakete gebaut. Das betrifft insbesondere die 32-Bit-Ausgabe von Raspberry Pi OS und damit ältere Pi-Modelle.

### Flatpak und Snap

Diese Formate führen Programme in einer abgeschotteten Umgebung aus, die den Mitschnitt von Netzwerkpaketen nicht zulässt. CERNIS PRO wäre darin ohne seine Kernfunktion. Ein Paket, das aussieht wie das Programm, aber nicht messen kann, wäre eine Täuschung — deshalb gibt es keines.

---

## Diese Fassung ist eine Vorabfassung

**Geprüft wurde bisher auf einem System:** Rocky Linux 10.2. Dort wurde das Paket installiert, die Anwendung gestartet und ein Scan mit Gerätefunden durchgeführt.

Die übrigen oben genannten Systeme sind **noch nicht geprüft**. Die Angaben zu ihnen beruhen auf dem Abgleich mit den Paketverzeichnissen der jeweiligen Distribution — das ist eine gute Grundlage, aber kein Ersatz für einen Lauf auf einem echten System.

Solange diese Prüfung aussteht, bleibt diese Fassung eine Vorabfassung. Wir sagen lieber, was wir gemessen haben, als was wir erwarten.

---

## Bekannte Einschränkungen

Diese Punkte sind uns bekannt, gemessen und für eine der nächsten Versionen vorgesehen. Keiner davon führt zu Datenverlust.

### Angekündigte Dienste werden nicht angezeigt

Die Spalten für mDNS und SSDP bleiben leer, obwohl Geräte im Netz antworten.

**In den Hinweisen zur Vorgängerversion stand dazu eine Erklärung, die sich als falsch erwiesen hat.** Dort hieß es, die Antworten würden von der Firewall des Systems verworfen. Eine Messung des Netzverkehrs zeigt: CERNIS fragt korrekt an, und die Antworten erreichen den Rechner vollständig — Drucker, Rechner und Mediengeräte melden sich mit allen Angaben. Angezeigt wird trotzdem nichts.

Die Ursache liegt damit in der Verarbeitung, nicht im Netz. Sie ist eingegrenzt und wird behoben. Die Gerätesuche selbst ist davon nicht betroffen: Geräte werden über die übrigen Verfahren zuverlässig gefunden.

### Bei der Deinstallation bleiben die eigenen Daten zurück

Wird CERNIS PRO entfernt, verschwinden alle Programmdateien vollständig. Die Datenbank mit Ihren Scans und Einstellungen bleibt erhalten — bei einer Aktualisierung ist das erwünscht, bei einer endgültigen Deinstallation nicht immer.

Ein Hinweis darauf fehlt derzeit. Sie finden die Datei unter `~/.local/share/cernis-pro/` und können sie von Hand entfernen. Eine bewusste Möglichkeit, alle Daten mitzulöschen, ist vorgesehen.

### Aufzeichnungen zeigen nach Ablauf ihrer Höchstdauer weiterhin läuft

Erreicht eine Aufzeichnung die eingestellte Höchstdauer, wird die Datensammlung wie vorgesehen beendet, die Anzeige wechselt jedoch nicht in den Zustand abgeschlossen. Die Daten sind vollständig; die Aufzeichnung lässt sich über Stopp abschließen.

### Ein gelöschtes Überwachungsziel erscheint bis zum Neustart weiter in der Liste

Es wird nicht mehr überwacht und beeinflusst keine Messwerte. Nach einem Neustart ist es vollständig entfernt.

### macOS: Gerätenamen können in einzelnen Scans fehlen

Bei mehreren Scans kurz hintereinander kann ein einzelner Scan keine Gerätenamen anzeigen. Der Gerätebestand behält die zuvor ermittelten Namen; ein erneuter Scan zeigt sie wieder. Ein erfundener Name wird nie angezeigt.

### macOS: das Fehlerprotokoll enthält wiederholte Hinweise

Auf den Betrieb hat das keine Auswirkung.

### Fedora und RHEL: die Lizenzdateien tragen keine Kennzeichnung

Die Lizenzbeilage liegt im rpm-Paket am vorgesehenen Ort und ist vollständig lesbar, ist dort aber nicht als Lizenzdatei markiert — `rpm -qL cernis-pro` gibt deshalb nichts aus. Ursache ist eine Grenze des verwendeten Paketwerkzeugs. Die Dateien finden Sie unter `/usr/share/licenses/cernis-pro/`.

### Der Durchsatz je Programm wird auf macOS und Windows nicht angezeigt

Das ist keine Einschränkung dieser Version, sondern eine bewusste Festlegung:

* **Auf macOS** stellt das Betriebssystem die nötige Auskunftsstelle nicht bereit.
* **Unter Windows** gibt das Betriebssystem diese Zahlen nur an Programme heraus, die dauerhaft mit erhöhten Rechten laufen. **Genau darauf verzichtet CERNIS bewusst.**

In beiden Fällen wird vollständig angezeigt, **welches** Programm mit **welcher** Gegenstelle spricht — nur nicht, wie viel dabei fließt. Wo eine Angabe fehlt, steht ein Gedankenstrich statt einer erfundenen Null.

### Windows: die Programmdateien sind nicht signiert

Für Windows liegt dem Projekt kein Signaturzertifikat vor. Windows kann beim Start des Installers eine Warnung anzeigen. Die Prüfsumme jedes Pakets liegt dem Release bei.

### Auf ARM-Linux wird kein AppImage ausgeliefert

Das AppImage-Format lief auf keinem geprüften Linux-System zuverlässig und wird seit Version 2.0.5 nicht mehr ausgeliefert. Verwenden Sie das deb- oder rpm-Paket.

---

## Prüfsummen

Zu jeder Paketdatei liegt eine Prüfsummendatei mit derselben Bezeichnung und der Endung `.sha256` bereit. Die Prüfung geht mit Bordmitteln:

* **Linux:** `sha256sum -c CernisPro_2.1.0_amd64.deb.sha256`
* **macOS:** `shasum -a 256 -c CernisPro_2.1.0_aarch64.dmg.sha256`
* **Windows:** `Get-FileHash CernisPro_2.1.0_x64-setup.exe -Algorithm SHA256`

---

## Die Pakete dieser Version

| Plattform | Datei |
|---|---|
| macOS (Apple Silicon) | CernisPro_2.1.0_aarch64.dmg |
| Linux x86-64 (Debian, Ubuntu) | CernisPro_2.1.0_amd64.deb |
| Linux x86-64 (Fedora, RHEL, openSUSE) | CernisPro-2.1.0-1.x86_64.rpm |
| Linux ARM64 (Debian, Ubuntu) | CernisPro_2.1.0_arm64.deb |
| Linux ARM64 (Fedora, RHEL, openSUSE) | CernisPro-2.1.0-1.aarch64.rpm |
| Windows x64 | CernisPro_2.1.0_x64-setup.exe |
| Windows ARM64 | CernisPro_2.1.0_arm64-setup.exe |
| Quelltext | CernisPro_2.1.0_source.tar.gz |

Zu jeder dieser Dateien liegt eine gleichnamige Prüfsummendatei mit der Endung `.sha256` bei.

---

## Hinweise zur Installation

**Linux:** Das Installationspaket richtet die Netzwerk-Berechtigung für den Mitschnitt-Helfer selbst ein. Sollte das Auslesen echter Domainnamen anschließend nicht verfügbar sein, prüfen Sie, ob `libcap2-bin` beziehungsweise `libcap` installiert ist.

**RHEL, Rocky Linux, AlmaLinux 10:** Aktivieren Sie vor der Installation CRB und EPEL (siehe oben). Ohne diese Quellen fehlen zwei Pakete, und die Installation bricht mit einer entsprechenden Meldung ab.

**Windows:** Für das Auslesen echter Domainnamen und den Paketmitschnitt wird **Npcap** benötigt. CERNIS installiert es nicht mit; fehlt es, bietet die Anwendung die Nachinstallation an.

**macOS:** Beim ersten Öffnen der Außenkontakte fragt CERNIS einmalig nach Ihrer Zustimmung zum passiven Mitlesen der Domainnamen. Die Zustimmung lässt sich jederzeit widerrufen.

---

## Grundsätze, die für diese Version gelten

* **CERNIS ist passiv.** Es greift nie in den Datenverkehr ein.
* **CERNIS erweitert seine Rechte nicht, um Funktionen zu gewinnen.** Eine ehrlich benannte Lücke ist besser als eine Funktion, die auf Kosten der Sicherheit geht.
* **Fehlt eine Angabe, steht ein Gedankenstrich** — nie eine erfundene Null.
* **Was nicht belegbar ist, wird als unbelegt ausgewiesen** — nicht mit einem plausiblen Wert gefüllt.
* **Was nicht geprüft ist, wird nicht zugesagt.** Diese Fassung nennt ausdrücklich, welche Systeme geprüft wurden und welche nicht.
* **Alle Einstellungen liegen in der Datenbank der Anwendung.** Es gibt keine Konfigurationsdateien, die von Hand zu pflegen wären.
