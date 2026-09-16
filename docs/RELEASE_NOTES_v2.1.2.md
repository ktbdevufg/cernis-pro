# CERNIS PRO 2.1.2 — Versionshinweise

**Veröffentlicht:** 2026-08-15 · **Vorabfassung**

Diese Fassung hat ein Thema: **Ihre Daten überstehen ein Programm-Update.** Bis 2.1.1 trug die
Datenbank keinen Hinweis darauf, zu welcher Programmfassung sie gehört. Das ist jetzt anders —
und darauf bauen die übrigen Neuerungen auf.

---

## Was neu ist

### Die Datenbank kennt ihre Fassung

CERNIS PRO merkt sich ab dieser Version, nach welchem Bauplan Ihre Daten angelegt wurden. Beim
Start prüft das Programm diesen Stand, bevor es die Datenbank überhaupt anfasst, und zieht
fehlende Teile still nach. Sie merken davon im Normalfall nichts.

**Zwei Fälle merken Sie doch:**

Steht später einmal ein echter Umbau der Datenstruktur an, legt CERNIS PRO **vorher eine
Sicherung** neben Ihrer Datenbank ab — eine vorhandene Sicherung wird dabei nie überschrieben.
Scheitert die Sicherung, startet das Programm nicht. Lieber kein Start als ein Umbau ohne
Rückweg.

Und wenn Sie eine **ältere Programmfassung auf eine neuere Datenbank** treffen lassen — etwa
nach einem Rückschritt auf eine Vorversion —, verweigert CERNIS PRO den Start mit dem Hinweis
**E-105** und der Bitte, die aktuelle Fassung zu installieren. Es wird dabei **nichts** an Ihren
Daten geändert: keine Sicherung, kein Umbau, kein Vermerk. Eine ältere Fassung kennt die neuere
Struktur nicht und würde raten.

### Sehr große Netze werden nicht mehr angenommen

Ein Scan über 4.096 Adressen hinaus wird abgelehnt — das entspricht sechzehn üblichen
Heimnetzen. Gezählt wird die **Summe** aller angegebenen Netze, damit sich die Grenze nicht
durch Aufteilen umgehen lässt.

Der Grund ist die Laufzeit: Ein Scan dauert mit jeder Adresse länger, und bei sehr großen Netzen
kann er sich über Stunden ziehen, ohne dass Sie zwischendurch ein brauchbares Ergebnis sehen.
CERNIS PRO ist für kleine Netze in Wohnung, Praxis und Büro entwickelt. Die Meldung nennt Ihnen
die Zahl, die Sie angegeben haben, und die Grenze.

### Geräte eines anderen Netzes entfernen

In der Geräteverwaltung finden Sie den Knopf **„Nach Netz aufräumen"**. Er gruppiert Ihren
Gerätebestand nach dem Netz der zuletzt bekannten Adresse und lässt Sie ganze Gruppen entfernen.

Das brauchen Sie, wenn Sie umgezogen sind, den Router gewechselt haben oder nacheinander
verschiedene Netze geprüft haben: Ihre Geräteliste führt dann alle Netze zusammen, während die
Bewertung sich auf den letzten Scan bezieht. Vor dem Entfernen sehen Sie, wie viele Geräte je
Netz betroffen sind, und bestätigen in einem zweiten Schritt.

### Hintergrundarbeiten geben nicht mehr stillschweigend auf

CERNIS PRO erledigt einiges im Hintergrund — Erreichbarkeit messen, Außenkontakte mitschreiben,
Schwachstellen abgleichen. Trat dort ein Fehler auf, konnte die betreffende Arbeit **still
enden**: Sie sahen weiterhin die Oberfläche, aber die Werte wurden nicht mehr fortgeschrieben,
ohne dass irgendetwas darauf hinwies.

Das ist behoben. Alle fünf Hintergrundarbeiten überstehen einen Fehler, versuchen es erneut und
führen mit, wie oft es zuletzt nicht geklappt hat.

### Die Verkehrsbeobachtung sagt Ihnen, wenn sie aufhört

Die Beobachtung der angefragten Domainnamen kann sich beenden — etwa weil ihr Helfer nicht mehr
läuft oder die Datenquelle nicht mehr antwortet. Bisher wirkte die Ansicht dann einfach ruhig.
Jetzt erscheint ein Hinweis mit dem Grund und der Bitte, die Aufzeichnung erneut zu starten.

### Weniger Grundlast

Eine Hintergrundabfrage lief bisher auf **jedem** Betriebssystem zweimal pro Sekunde, ohne
Obergrenze und ohne sich zurückzuziehen. Sie ist jetzt begrenzt und gibt auf, wenn dauerhaft
nichts zu holen ist.

---

## Bekannte Einschränkungen

Diese Punkte sind uns bekannt und in Arbeit. Wir nennen sie lieber, als dass Sie sie selbst
entdecken.

### Windows: Der Virenschutz kann den Start blockieren

**Beobachtung:** CERNIS PRO ist auf Windows nicht mit einem Herausgeberzertifikat signiert.
Manche Virenschutzprogramme blockieren daraufhin den Start oder die Paketaufzeichnung.
**Auswirkung:** Sie müssen das Programm gegebenenfalls von Hand freigeben. **Zusage:** Ein
Zertifikat ist eine Kostenfrage, die wir noch nicht entschieden haben; sobald sie entschieden
ist, sagen wir es hier.

### openSUSE: Das RPM-Paket ist nicht signiert

**Beobachtung:** `zypper` verweigert die Installation unsignierter Pakete standardmäßig.
**Auswirkung:** Die Installation gelingt nur, wenn Sie die Signaturprüfung für dieses Paket
bewusst übergehen. **Zusage:** Eine eigene Paketsignatur ist vorbereitet und kommt in einer der
nächsten Fassungen.

### openSUSE: Die Routenmessung fällt aus

**Beobachtung:** Das benötigte Systemwerkzeug liegt dort außerhalb des Suchpfads, in dem CERNIS
PRO es erwartet. **Auswirkung:** Die Anzeige des Netzwegs zu einer Gegenstelle bleibt leer; alle
übrigen Funktionen arbeiten. **Zusage:** Behebung in der nächsten Fassung.

### Windows: Beim Deinstallieren bleibt ein Programmteil zurück

**Beobachtung:** Der Deinstaller kennt den Mitschnitt-Helfer nicht und beendet ihn nicht
zuverlässig. **Auswirkung:** Nach dem Deinstallieren kann eine Programmdatei gesperrt
zurückbleiben; ein Neustart des Rechners löst das. **Zusage:** Behebung in der nächsten Fassung.

### Entfernte Geräte können im Schwachstellen-Abgleich noch einmal auftauchen

**Beobachtung:** Entfernen Sie Geräte über „Nach Netz aufräumen", trägt der
Schwachstellen-Abgleich sie kurz darauf noch einmal nach — er stützt sich auf das Ergebnis des
letzten Scans, nicht auf Ihre Geräteliste. **Auswirkung:** Die entfernten Geräte erscheinen im
CVE-Abgleich erneut, und die Zahl der betroffenen Geräte ist dort zu hoch. Ihre Geräteliste
selbst bleibt korrekt, und ein neuer Scan bereinigt den Zustand. **Zusage:** Behebung in der
nächsten Fassung.

### Geplante Scans laufen, ihr Ausgang ist aber nicht sichtbar

**Beobachtung:** Sie können wiederkehrende Aufgaben anlegen, und CERNIS PRO merkt sich seit
dieser Fassung auch, wie der letzte Lauf ausgegangen ist — es gibt aber noch keine Ansicht
dafür. **Auswirkung:** Ob ein geplanter Lauf erfolgreich war, sehen Sie derzeit nur indirekt an
den Ergebnissen. **Zusage:** Eine Zeitplan-Ansicht ist vorgesehen.

### Zwei Geräteangaben können sich unterscheiden

**Beobachtung:** Der Sicherheitsbericht und der Schwachstellen-Abgleich zählen Geräte
unterschiedlich — ein Gerät ohne erkannte Hardware-Adresse zählt im einen mit, im anderen nicht.
**Auswirkung:** Die beiden Zahlen können um wenige Geräte auseinanderliegen. **Zusage:** Wir
vereinheitlichen das, sobald entschieden ist, welche der beiden Zählweisen die richtige ist.

### Nach dem Deinstallieren bleiben Ihre Daten liegen

**Beobachtung:** Das Entfernen des Pakets löscht Ihre Scans und Einstellungen nicht — sie liegen
in Ihrem persönlichen Ordner, und die Paketverwaltung fasst diesen bewusst nicht an.
**Auswirkung:** Nach dem Deinstallieren bleiben zwei Verzeichnisse zurück; die Pfade werden
Ihnen beim Entfernen auf der Konsole genannt. **Zusage:** Wenn Sie alle Daten loswerden wollen,
bringt der Punkt **„Werkszustand"** unter *Verwaltung → Daten löschen* das Programm in den
Zustand einer frischen Installation, bevor Sie es entfernen.

### NVIDIA-Grafik unter Wayland

**Beobachtung:** Auf Systemen mit NVIDIA-Grafik unter Wayland konnte der Start abbrechen.
**Auswirkung:** Das Programmfenster erschien nicht. **Zusage:** Eine Behebung ist eingebaut,
aber noch nicht auf einer Maschine mit dieser Zusammenstellung bestätigt.

---

## Was in dieser Fassung geprüft wurde — und was nicht

Wir halten es für redlich, das zu benennen.

**Geprüft auf Ubuntu 24.04 (64 Bit):** Installation, Rechtevergabe, Start, die Übernahme
bestehender Datenbestände aus 2.1.0 in beiden Ausprägungen, die Verweigerung bei zu neuer
Datenbank, die Ablehnung zu großer Netze in beiden Sprachen, das Aufräumen nach Netz und der
Wartungsdialog.

**Nicht geprüft:** Windows und macOS. Die Pakete sind gebaut und liegen bereit, wurden aber auf
keiner Maschine installiert oder gestartet. Ebenso wenig geprüft sind die Hinweise, die
erscheinen, wenn die Verkehrsbeobachtung sich selbst beendet oder der Schwachstellen-Abgleich
scheitert.

---

## Hinweise zur Nutzung

CERNIS PRO ist ein **passives** Werkzeug: Es beobachtet und ordnet ein, es greift nie in den
Netzverkehr ein.

Setzen Sie es ausschließlich in Netzen ein, die Ihnen gehören oder für die Sie ausdrücklich
autorisiert sind. Ein Netzwerk-Scan ist in fremden Netzen je nach Rechtslage unzulässig.

Die Angaben im Schwachstellen-Abgleich sind **Hinweise zur Prüfung**, keine bestätigten
Verwundbarkeiten. Sie entstehen aus dem Abgleich erkannter Dienste mit öffentlichen
CVE-Einträgen und sagen nichts darüber aus, ob ein Gerät tatsächlich angreifbar ist — dazu
gehört immer eine eigene Prüfung.

---

## Installation

Die Pakete finden Sie auf der Release-Seite, je mit einer Prüfsummendatei. Prüfen Sie sie vor
der Installation:

* Linux: `sha256sum -c <paketname>.sha256`
* macOS: `shasum -a 256 -c <paketname>.sha256`
* Windows: `Get-FileHash <paketname>`

Neben jedem Paket liegt eine Aufstellung sämtlicher enthaltener Fremdbestandteile mit ihren
Lizenzen.

CERNIS PRO steht unter **GPL-2.0-only**.
