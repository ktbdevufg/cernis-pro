# CERNIS PRO 2.1.1

**Stand:** August 2026

> **Diese Fassung ist eine Vorabfassung und wird nicht zur Installation empfohlen.**
> Sie ist vollständig gebaut, geprüft und nachlesbar dokumentiert — aber sie ersetzt 2.1.0
> nicht. Der Grund steht weiter unten und ist derselbe Grundsatz wie immer: Was nicht
> ausreichend geprüft ist, wird nicht zugesagt.

Diese Version behebt Fehler. Neue Funktionen bringt sie keine. Zwei ihrer Korrekturen sind
schwerwiegend genug, um sie zuerst zu nennen: Die Sicherheitsbewertung zeigte über Wochen
falsche Werte, und beim Lesen eines gespeicherten Kennworts konnte ein Schlüssel überschrieben
werden.

---

## Die beiden wichtigsten Korrekturen

### Die Sicherheitsbewertung war verfälscht

Die Netz-Gesundheitsnote und der Sicherheitsbericht stützten sich auf eine Liste bekannter
Schwachstellen, die **nie bereinigt wurde**. Ein einmal gefundener Eintrag blieb dort stehen,
auch wenn ein späterer Scan zeigte, dass der zugehörige Dienst gar nicht mehr erreichbar war.

Die Wirkung war erheblich: In einem gemessenen Fall stand die Note bei 3 von 100, und 23 von
24 Geräten galten als kritisch — **alle mit demselben Höchstwert**. Eine Bewertung, die
23 verschiedene Geräte auf denselben Wert setzt, unterscheidet nichts mehr.

Drei Ursachen wirkten zusammen, alle drei sind behoben:

* **Die Liste wird jetzt ersetzt statt ergänzt.** Nach jedem Scan werden für jedes gesehene
  Gerät die Einträge neu gebildet. Ein Gerät ohne offene Dienste verliert seine Einträge
  vollständig. Geräte, die beim Scan nicht erreichbar waren, behalten ihre Einträge, bis ein
  Scan etwas anderes zeigt — Abwesenheit ist kein Beweis.
* **Örtlich abgefangene Dienste werden nicht mehr dem fremden Gerät zugeschrieben.**
  Sicherheitsprogramme mit Mailschutz fangen Mail-Zugänge auf dem eigenen Rechner ab. Für
  CERNIS sah das bisher so aus, als sei der Dienst auf jedem Gerät im Netz offen. Eine
  Gegenprobe gegen unbenutzte Adressen erkennt das jetzt; ein Hinweis am Scan-Ergebnis nennt
  die betroffenen Zugänge.
* **Netz- und Rundrufadressen zählen nicht mehr als Geräte.** Sie sind Adressierungsformen,
  keine Teilnehmer. Sie wurden bewertet, erhielten Schwachstellen zugeordnet und verfälschten
  die Gerätezahl.

Note und Bericht sind damit von selbst richtig, weil sie dieselbe Liste lesen.

**Zusätzlich:** Der Abgleich beginnt jetzt unmittelbar nach einem Scan, statt darauf zu
warten, dass ein Gerät fällig wird. Während er läuft, sagt die Ansicht das ausdrücklich und
nennt, wie viele Geräte noch ausstehen — statt eine halbfertige Liste als Ergebnis auszugeben.

### Beim Lesen eines gespeicherten Kennworts konnte ein Schlüssel überschrieben werden

Gespeicherte Zugangsdaten werden verschlüsselt abgelegt. Fehlte die Schlüsseldatei — etwa
weil sie versehentlich verschoben wurde —, legte CERNIS **auch beim Lesen** stillschweigend
einen neuen Schlüssel an. Damit war das vorhandene Geheimnis endgültig unlesbar, und die
Meldung sprach von einem falschen Schlüssel statt von einem fehlenden.

Der Vorgang, der den Verlust hätte melden können, vollzog ihn.

Behoben: Ein Schlüssel entsteht ausschließlich beim Speichern, nie beim Lesen. Fehlt er beim
Lesen, bricht der Vorgang mit einer benannten Meldung und einem eigenen Fehlercode ab und
nennt den erwarteten Ablageort. Es ist kein Schadensfall bekannt geworden; die Prüfung ergab,
dass in keiner untersuchten Installation ein solches Geheimnis gespeichert war.

---

## Was diese Version außerdem behebt

### Beim Beenden bleiben keine Rückstände mehr liegen

Bei jedem Start legt CERNIS ein temporäres Arbeitsverzeichnis von rund 174 MB an, das beim
ordentlichen Beenden wieder verschwindet. Weil das Programm sich selbst zu hart beendete,
kam es dazu oft nicht — die Verzeichnisse summierten sich mit jedem Start.

Jetzt wird auf das tatsächliche Ende gewartet, statt eine Frist zu schätzen. Beim Start
werden zurückgebliebene Verzeichnisse aufgeräumt — **ausschließlich eigene, unbenutzte und
zweifelsfrei zuordenbare**. Fremde Verzeichnisse bleiben unangetastet.

Bekannte Restlücke: Das Arbeitsverzeichnis des Mitschnitt-Helfers wird nicht aufgeräumt. Es
enthält keine Merkmale, an denen es sich sicher von dem eines fremden Programms unterscheiden
ließe, und ein Löschen auf Verdacht kommt nicht in Frage.

### CERNIS beendet keine fremden Programme mehr

Beim Start prüfte CERNIS, ob der eigene Zugang belegt ist — und beendete jeden Prozess, der
ihn hielt, **ohne zu prüfen, wessen er ist**. Ein fremdes Programm auf demselben Zugang wurde
ohne Vorwarnung hart beendet.

Jetzt wird der Halter zuerst identifiziert. Gehört er zu CERNIS, wird er geordnet beendet. Ist
er fremd oder nicht sicher zuzuordnen, bleibt er unangetastet, und CERNIS meldet mit eigenem
Fehlercode, dass der Zugang belegt ist.

Dasselbe galt für die Installationsskripte: Sie beendeten Prozesse allein anhand ihres Namens.
Ein gleichnamiges fremdes Programm hätte es getroffen. Auch dort wird jetzt der tatsächliche
Programmpfad geprüft.

### Das Entfernen hinterlässt keine stillen Reste mehr

* **Es gibt jetzt Deinstallationsskripte für deb und rpm.** Bisher wurden beim Entfernen
  **keine** laufenden Programme beendet — auf Linux gab es überhaupt kein solches Skript.
* **Beim endgültigen Entfernen erscheint ein Hinweis auf die zurückbleibenden Daten**, und er
  nennt beide betroffenen Verzeichnisse. Das zweite davon legt die Programmoberfläche selbst
  an; es wurde dem Anwender nirgends genannt.
* **Ein leer zurückbleibendes Lizenzverzeichnis wird entfernt** — aber nur, wenn es wirklich
  leer ist. Ein nicht leeres bleibt stehen, und das wird gemeldet.
* **Ein fehlgeschlagenes Setzen der Netzwerk-Berechtigung meldet sich jetzt.** Bisher wurde
  ein Fehlschlag als Erfolg ausgegeben; die Rechte fehlten dann still, und der Fehler zeigte
  sich erst im Betrieb.

### Fehlermeldungen nennen den wirklichen Grund

* Fehlte ein benötigtes Systemprogramm, behauptete die Oberfläche **bei jedem** Ausfall, es
  handele sich um die Routenmessung — unabhängig davon, was tatsächlich fehlte. Jetzt wird die
  Meldung des Programms selbst angezeigt. Ist kein Grund mitgeteilt worden, steht das
  ausdrücklich da, statt einen zu erfinden.
* An zwei Stellen wurde die Fehlermeldung vollständig verworfen; echte Ausfälle erreichten den
  Anwender nie.
* Der DNS-Wächter zeigte unter Windows ohne Npcap eine technische Rohmeldung mit Hinweisen auf
  Linux-Rechte. Er nennt jetzt dieselbe Ursache wie die übrigen Ansichten, mit dem vorhandenen
  Installationsangebot.
* Die Umgebungserkennung meldete eine Fassung von `0.0`, wenn sie nichts ermitteln konnte —
  ununterscheidbar von einer echten Angabe. Sie unterscheidet jetzt zwischen einem Wert und
  seinem Fehlen und nennt in jedem Fall den Grund.

### Die Lizenzangaben sind vollständig und auffindbar

* **Die Lizenzaufstellung wurde auf Linux zur Laufzeit nicht gefunden.** Programm und
  Aufstellung liegen im Paket an strukturell getrennten Orten; der Suchweg konnte den zweiten
  gar nicht erreichen. Behoben und durch eine automatische Prüfung im Bauablauf abgesichert.
* **Npcap wird in der Lizenzübersicht jetzt geführt** — als vorausgesetzter, nicht
  mitgelieferter Bestandteil. Wo eine Angabe nicht belegbar ist, steht das ausdrücklich da,
  statt eine plausible einzusetzen.
* Im Aufklappblock „Vollständiger Lizenztext" erschien für das eigene Werk eine interne
  Kennung statt des Textes.

### Ein Bedienelement ohne Wirkung

Das Häkchen für die Benachrichtigung per E-Mail war bedienbar, hatte aber **dauerhaft keine
Wirkung** — es gibt keine Oberfläche, um einen Postausgangs-Server zu hinterlegen. Es bleibt
sichtbar, ist jetzt aber gesperrt, mit einer Erklärung daneben. Bereits gespeicherte
Einstellungen bleiben erhalten.

Der zugehörige Hilfetext beschrieb eine Einrichtung, die es nicht gibt, und nannte einen
falschen Speicherort für die Zugangsdaten. Er ist berichtigt.

**Das Thema E-Mail-Benachrichtigung insgesamt ist auf Version 3 verschoben.**

### Innere Prüfungen, die den Anwender mittelbar betreffen

Drei Mängel in den Bauabläufen selbst sind behoben. Sie waren nie sichtbar, betrafen aber
genau die Stellen, an denen Vertrauen entsteht:

* Eine Prüfung öffnete unter Umständen ein **älteres** Paket und meldete dafür Erfolg.
* Fehlte die gebaute Oberfläche, warnte der Bau nur und lieferte ein Programm ohne Fenster
  aus.
* Nach dem Ende eines Programms wurde unter Umständen ein Signal an eine Kennung geschickt,
  die das System bereits neu vergeben haben konnte.

---

## Warum diese Fassung eine Vorabfassung bleibt

Beim Beheben von zwölf Fehlern in einer einzigen Arbeitsrunde fielen **drei bisher unbekannte
Defekte** und **sechs unzutreffende Angaben** in der eigenen Fehlerliste an. Das ist kein
Argument gegen die Korrekturen — es ist ein Hinweis auf den Reifegrad.

Solange dieser Eindruck nicht durch eine vollständige Prüfrunde über alle Zielsysteme
widerlegt ist, wird 2.1.1 nicht als reguläre Fassung ausgeliefert. Die Pakete liegen bei,
die Änderungen sind nachlesbar — eine Empfehlung zur Installation ist das nicht.

---

## Bekannte Einschränkungen

Diese Punkte sind bekannt, gemessen und benannt. Keiner davon führt zu Datenverlust.

### Windows: die Programmdateien sind nicht signiert

Dem Projekt liegt kein Signaturzertifikat für Windows vor. Manche Virenschutzprogramme
blockieren die Programmdateien deshalb beim Start und bei jeder Aufzeichnung, bis der Anwender
sie ausdrücklich freigibt. Die Prüfsumme jedes Pakets liegt bei.

### openSUSE: das rpm-Paket ist nicht signiert

`zypper` verweigert die Installation unsignierter Pakete. Die anderen RPM-Distributionen
nehmen dasselbe Paket mit einer Warnung an. Eine eigene Signatur ist vorgesehen.

### NVIDIA unter Wayland: das Fenster erscheint kurz und verschwindet

Betroffen ist das Zusammenspiel von Grafiktreiber, Fenstersystem und der Komponente, die
Webinhalte darstellt — nicht CERNIS selbst; ein zwölfzeiliges Fremdprogramm ohne unseren Code
stürzt identisch ab. Abhilfe ohne Leistungsverlust: die Umgebungsvariable
`__NV_DISABLE_EXPLICIT_SYNC=1` setzen.

### openSUSE: die Routenmessung steht nicht zur Verfügung

Dort liegt das benötigte Programm außerhalb des Suchpfads gewöhnlicher Benutzer. CERNIS meldet
es als nicht vorhanden. Die übrigen Funktionen sind nicht betroffen.

### Windows: die Deinstallation ist unvollständig

Der Deinstaller kennt den Mitschnitt-Helfer nicht. Er läuft nach dem Entfernen weiter und
blockiert dadurch Dateien. Auf Linux ist dieser Punkt mit dieser Version behoben, auf Windows
nicht.

### Ein Hintergrundvorgang kann still enden

Tritt in einem der vier Hintergrundvorgänge ein unerwarteter Fehler auf, endet dieser Vorgang
dauerhaft, ohne dass es im Betrieb sichtbar wird. Die betroffenen Zahlen wirken dann nur
eingefroren. Ein Neustart der Anwendung stellt den Zustand her.

### Bei schmalem Fenster wird eine Beschriftung abgeschnitten

In den Logging-Aufgaben wird die dritte Betriebsart bei geringer Fensterbreite mitten im Wort
abgeschnitten. Die Auswahl selbst bleibt bedienbar. Ein breiteres Fenster zeigt sie
vollständig.

### Angekündigte Dienste werden je nach System nicht angezeigt

Die Spalten für mDNS und SSDP können leer bleiben, obwohl Geräte im Netz antworten.

**Die Erklärung in den Hinweisen zu 2.1.0 war ihrerseits nicht richtig.** Dort hieß es, die
Ursache liege in der Verarbeitung und nicht im Netz. Messungen auf sechs Systemen zeigen ein
anderes Bild: Entscheidend ist die **Zonendefinition der jeweiligen Distribution**. Wo die
Systemfirewall die betreffenden Antworten durchlässt, sind beide Spalten ohne jeden Eingriff
gefüllt; wo sie es nicht tut, bleiben sie leer. Es ist also eine Systemvoraussetzung, kein
Programmfehler.

Die Gerätesuche selbst ist davon nicht betroffen — Geräte werden über die übrigen Verfahren
zuverlässig gefunden.

### Bei der Deinstallation bleiben die eigenen Daten zurück

Programmdateien verschwinden vollständig; die Datenbank mit Ihren Scans und Einstellungen
bleibt erhalten. Bei einer Aktualisierung ist das erwünscht, bei einer endgültigen
Deinstallation nicht immer. **Neu in dieser Version:** Das Entfernen weist jetzt ausdrücklich
darauf hin und nennt beide Verzeichnisse. Eine bewusste Möglichkeit, die Daten aus der
Anwendung heraus zu entfernen, ist weiterhin vorgesehen.

### Fedora und RHEL: die Lizenzdateien tragen keine Kennzeichnung

Die Lizenzbeilage liegt am vorgesehenen Ort und ist vollständig lesbar, ist dort aber nicht
als Lizenzdatei markiert. Ursache ist eine Grenze des verwendeten Paketwerkzeugs. Die Dateien
finden Sie unter `/usr/share/licenses/cernis-pro/`.

### Der Durchsatz je Programm wird auf macOS und Windows nicht angezeigt

Keine Einschränkung dieser Version, sondern eine bewusste Festlegung:

* **Auf macOS** stellt das Betriebssystem die nötige Auskunftsstelle nicht bereit.
* **Unter Windows** gibt das Betriebssystem diese Zahlen nur an Programme heraus, die dauerhaft
  mit erhöhten Rechten laufen. **Genau darauf verzichtet CERNIS bewusst.**

In beiden Fällen wird vollständig angezeigt, **welches** Programm mit **welcher** Gegenstelle
spricht — nur nicht, wie viel dabei fließt.

### Weitere Punkte, unverändert aus 2.1.0

* Eine Aufzeichnung, die ihre Höchstdauer erreicht, wechselt in der Anzeige nicht in den
  Zustand „abgeschlossen". Die Daten sind vollständig.
* Ein gelöschtes Überwachungsziel erscheint bis zum Neustart weiter in der Liste. Es wird nicht
  mehr überwacht.
* Auf macOS können Gerätenamen in einzelnen Scans fehlen. Ein erfundener Name wird nie
  angezeigt.
* Auf ARM-Linux wird kein AppImage ausgeliefert. Verwenden Sie das deb- oder rpm-Paket.

---

## Systemvoraussetzungen

**Unverändert gegenüber 2.1.0.** Windows 10 oder 11 (x64, ARM64) · aktuelle macOS-Fassungen
auf Apple Silicon · Debian 12 und neuer, Ubuntu 22.04 LTS und neuer samt aufbauenden
Distributionen · Fedora, RHEL, Rocky Linux und AlmaLinux ab Fassung 10, openSUSE Leap 16 und
Tumbleweed. Jeweils für x86-64 und ARM64.

> **Für RHEL, Rocky Linux und AlmaLinux 10** müssen vor der Installation die Zusatzquellen
> **CRB** und **EPEL** aktiviert sein:
>
> ```
> sudo /usr/bin/crb enable
> sudo dnf install epel-release
> ```

Nicht unterstützt bleiben RHEL 9 und älter samt Ablegern, Ubuntu 20.04 und älter, Debian 11
und älter, 32-Bit-Systeme sowie Flatpak und Snap. Die Begründungen stehen unverändert in den
Hinweisen zu 2.1.0.

---

## Prüfsummen

Zu jeder Paketdatei liegt eine Prüfsummendatei mit derselben Bezeichnung und der Endung
`.sha256` bereit:

* **Linux:** `sha256sum -c CernisPro_2.1.1_amd64.deb.sha256`
* **macOS:** `shasum -a 256 -c CernisPro_2.1.1_aarch64.dmg.sha256`
* **Windows:** `Get-FileHash CernisPro_2.1.1_x64-setup.exe -Algorithm SHA256`

---

## Die Pakete dieser Version

| Plattform | Datei |
|---|---|
| macOS (Apple Silicon) | CernisPro_2.1.1_aarch64.dmg |
| Linux x86-64 (Debian, Ubuntu) | CernisPro_2.1.1_amd64.deb |
| Linux x86-64 (Fedora, RHEL, openSUSE) | CernisPro-2.1.1-1.x86_64.rpm |
| Linux ARM64 (Debian, Ubuntu) | CernisPro_2.1.1_arm64.deb |
| Linux ARM64 (Fedora, RHEL, openSUSE) | CernisPro-2.1.1-1.aarch64.rpm |
| Windows x64 | CernisPro_2.1.1_x64-setup.exe |
| Windows ARM64 | CernisPro_2.1.1_arm64-setup.exe |
| Quelltext | CernisPro_2.1.1_source.tar.gz |

Zu jeder dieser Dateien liegt eine gleichnamige Prüfsummendatei mit der Endung `.sha256` bei,
außerdem eine Aufstellung aller enthaltenen Fremdbestandteile und ihrer Lizenzen mit der
Endung `.lizenzaufstellung.json`.

---

## Hinweise zur Installation

**Linux:** Das Installationspaket richtet die Netzwerk-Berechtigung für den Mitschnitt-Helfer
selbst ein. Schlägt das fehl, meldet die Installation das jetzt ausdrücklich, statt den
Fehlschlag zu verschweigen.

**RHEL, Rocky Linux, AlmaLinux 10:** Aktivieren Sie vor der Installation CRB und EPEL.

**Windows:** Für das Auslesen echter Domainnamen und den Paketmitschnitt wird **Npcap**
benötigt. CERNIS installiert es nicht mit; fehlt es, bietet die Anwendung die Nachinstallation
an.

**macOS:** Beim ersten Öffnen der Außenkontakte fragt CERNIS einmalig nach Ihrer Zustimmung
zum passiven Mitlesen der Domainnamen. Die Zustimmung lässt sich jederzeit widerrufen.

---

## Grundsätze, die für diese Version gelten

* **CERNIS ist passiv.** Es greift nie in den Datenverkehr ein.
* **CERNIS erweitert seine Rechte nicht, um Funktionen zu gewinnen.** Eine ehrlich benannte
  Lücke ist besser als eine Funktion, die auf Kosten der Sicherheit geht.
* **CERNIS beendet keine fremden Programme.** Wo etwas im Weg steht, wird es benannt, nicht
  beseitigt.
* **Fehlt eine Angabe, steht ein Gedankenstrich** — nie eine erfundene Null.
* **Was nicht belegbar ist, wird als unbelegt ausgewiesen** — nicht mit einem plausiblen Wert
  gefüllt.
* **Was nicht geprüft ist, wird nicht zugesagt.** Auch nicht die eigene Reife.
* **Alle Einstellungen liegen in der Datenbank der Anwendung.** Es gibt keine
  Konfigurationsdateien, die von Hand zu pflegen wären.
