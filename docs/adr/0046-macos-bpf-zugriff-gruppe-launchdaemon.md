# 0046 — macOS-Mitschnitt-Zugriff: eigene Gruppe cernis-capture statt Root-Dienst

Status: akzeptiert · Datum: 2026-07-20 · Bereich: domain/capture_access, ports/capture_access,
application/capture_access, infrastructure/capture_access_macos + capture_access_other,
api/capture_access, app.py (Plattform-Weiche + Verdrahtung), scripts/setup-bpf-access.sh,
scripts/revoke-bpf-access.sh, tauri.conf.json (resources),
infrastructure/sniffd/sniff_core.py (Rechteprobe), frontend (OutboundView, SettingsView)

## Kontext

ADR 0041 legte CAP_NET_RAW auf den schlanken Helfer `cernis-sniffd`. Auf macOS gibt es weder
`setcap` noch Capabilities: der rohe Mitschnitt laeuft dort ueber die BPF-Geraeteknoten
`/dev/bpf*`, die im Auslieferungszustand `root:wheel` mit `0600` gehoeren. Ohne Zugriff darauf
liefert die GESAMTE Sniff-Familie nichts -- SNI-Erfassung, pcap, LLDP und der DNS-Waechter.

In Sitzung 47 war fuer diesen Fall SMJobBless angekuendigt, also ein privilegierter
Helferdienst. Diese Ankuendigung wurde nach Messung verworfen (siehe Abgrenzung).

Ein zweiter Befund gehoert in den Kontext: die urspruengliche Rechteprobe pruefte auf macOS
einen Raw-Socket (`AF_INET`/`SOCK_RAW`). Der braucht dort root und ist damit das FALSCHE
Pruefobjekt -- die Probe meldete dauerhaft fehlende Rechte, obwohl der BPF-Weg gangbar gewesen
waere. Eine Probe, die etwas anderes prueft als den tatsaechlichen Bedarf, ist keine Probe,
sondern eine zweite Fehlerquelle.

## Entscheidung

Kein Root-Prozess. Stattdessen das ChmodBPF-Prinzip von Wireshark, aber enger gefasst:

- eine eigene Gruppe `cernis-capture`; Mitglied ist allein der einrichtende Nutzer,
- die BPF-Geraete gehoeren dieser Gruppe: `crw-rw---- root:cernis-capture`,
- ein LaunchDaemon `/Library/LaunchDaemons/de.cernis.capture.plist` (`root:wheel`, `644`) setzt
  die Rechte bei jedem Bootvorgang ueber `/usr/local/bin/cernis-bpf-access.sh`,
- ausdruecklich KEIN `o+rw` -- das war der v1-Fehler und haette die Geraete jedem Nutzer der
  Maschine geoeffnet,
- kein CERNIS-Prozess laeuft je als root.

**Warum `g+rw` und nicht `g+r`:** scapy oeffnet die BPF-Geraete SCHREIBEND, weil es den
Paketfilter per `ioctl` setzt. Mit `g+r` scheitert der Sniff mit "Permission denied" beim
Oeffnen von `/dev/bpf0`. Das war ein realer Fehlbefund, der erst am laufenden Bundle sichtbar
wurde. Wireshark vergibt seiner Capture-Gruppe aus demselben Grund `rw`.

**Die Zugriffsprobe testet daher `O_RDWR`** -- exakt das, was scapy braucht. Probe und
tatsaechlicher Bedarf duerfen nicht auseinanderklaffen, sonst meldet die Anwendung Zugriff und
der Sniff scheitert trotzdem; genau dieser Widerspruch trat real auf. Ein Test nagelt die
verwendeten open-Flags fest, damit ein spaeteres "harmloses" Umstellen auf `O_RDONLY` nicht
unbemerkt durchgeht.

Einrichtung und Widerruf laufen aus der Anwendung heraus ueber den nativen
Administrator-Dialog von macOS (`osascript`, `do shell script ... with administrator
privileges`, Touch ID moeglich) -- nicht ueber eine Terminal-Anleitung. Beide Wege sind
idempotent und symmetrisch: `scripts/setup-bpf-access.sh` richtet ein,
`scripts/revoke-bpf-access.sh` nimmt zurueck.

**Sicherheitsentscheidungen, jede gemessen begruendet:**

- **Der Skript-INHALT wird ueber stdin an `/bin/bash` uebergeben, niemals ein Dateipfad als
  Argument.** Grund: eine `.app` in `/Applications` gehoert dem installierenden Nutzer, nicht
  root, und die Bundle-Ressourcen sind ohne Signaturversiegelung nicht manipulationssicher. Ein
  Dateipfad liesse ein Zeitfenster zwischen Pruefung und Ausfuehrung offen, in dem die Datei
  getauscht werden koennte. Mit dem Inhalt im Speicher gibt es dieses Fenster nicht.
- **Kein Here-Dokument fuer diese Uebergabe.** Dessen Ende-Marker ist Teil des Shell-Texts; ein
  Inhalt, der zufaellig eine Marker-Zeile enthaelt, beendet das Heredoc vorzeitig, sodass der
  Rest in der AEUSSEREN Shell laeuft. Real nachgestellt und bestaetigt. Stattdessen wird der
  gesamte Inhalt als EIN quote-geschuetztes Shell-Wort uebergeben.
- **Zwei Escaping-Ebenen bleiben zwingend**, weil `do shell script` seinen String an `/bin/sh`
  weiterreicht: shell-seitiges Quoting und das Escaping fuers umgebende AppleScript-Literal.
  AppleScript-Injection war ein v1-Finding.
- **Der Abbruch durch den Nutzer wird an der AppleScript-Fehlernummer `-128` erkannt**, nicht am
  Meldungstext -- der ist lokalisiert und als Merkmal unbrauchbar. Ein Abbruch ist ein eigener
  Zustand, kein Fehler.
- **Die Pruefung der Skriptquelle beschraenkt sich auf das sinnvoll Pruefbare:** die Datei
  existiert, ist regulaer und ist nicht weltschreibbar. Die Bedingung "gehoert root" wurde
  ENTFERNT, weil sie fuer eine Bundle-Ressource nachweislich nie zutrifft und die Einrichtung
  dauerhaft unmoeglich gemacht haette. Der Schutz liegt in der Inhaltsuebergabe, nicht im
  Dateieigentuemer.

### Widerruf und die systemweite Ressource

Der Einrichtungsdialog verspricht, der Zugriff sei jederzeit widerrufbar; also MUSS der
Widerruf existieren. Er entfernt LaunchDaemon, Helferskript und Gruppe und setzt die Geraete
auf `root:wheel` `0600` zurueck.

Dabei liegen Daten und Rechte auf VERSCHIEDENEN Ebenen, und das ist fuer den Widerruf
entscheidend. Die Anwendungsdaten sind pro Nutzerkonto getrennt, weil der Datenpfad unter dem
jeweiligen Benutzerverzeichnis liegt (`~/Library/Application Support/de.cernis.pro/`). Die
BPF-Geraete, die Gruppe und der LaunchDaemon sind dagegen SYSTEMWEIT -- alle Konten der
Maschine teilen sie sich zwangslaeufig, weil es dieselbe Netzwerkkarte und dieselben
Geraeteknoten sind. Wireshark hat dieselbe Eigenschaft.

Ein blindes vollstaendiges Abraeumen wuerde daher anderen Konten, die den Zugriff ebenfalls
eingerichtet haben, die Faehigkeit zum Mitschnitt nehmen, ohne dass sie gefragt wurden. Der
Widerruf ermittelt deshalb VOR dem Abraeumen die uebrigen Gruppenmitglieder (`dscl . -read
/Groups/cernis-capture GroupMembership`, reine Leseoperation). Ist der Widerrufende der
einzige, wird ohne Rueckfrage vollstaendig abgeraeumt. Sind weitere vorhanden, nennt die
Oberflaeche sie und laesst waehlen zwischen "nur meine Mitgliedschaft entfernen" (Modus
`mitgliedschaft`) und "vollstaendig entfernen" (Modus `vollstaendig`).

Das ist ausdruecklich KEIN Vorgriff auf die geplante Mehrbenutzerfaehigkeit der Anwendung,
sondern die korrekte Behandlung einer geteilten Betriebssystem-Ressource, die heute schon
existiert. Ein spaeterer Mehrbenutzer-Block muss diese Stelle mitbetrachten.

## Konsequenzen

**Positiv:**
- Die Sniff-Familie laeuft auf macOS ohne Root-Prozess; am installierten, signierten Bundle
  verifiziert.
- Der Zugriff ist auf eine benannte Gruppe begrenzt statt auf alle Nutzer der Maschine.
- Die Einrichtung ist aus der Anwendung heraus erreichbar -- nicht nur beim ersten
  Einverstaendnis -- und vollstaendig zuruecknehmbar.

**Negativ / bewusst offen:**
- Die Einrichtung veraendert den Zustand des Systems AUSSERHALB der Anwendung: Gruppe,
  LaunchDaemon und eine Datei unter `/usr/local/bin`. Deshalb ist der symmetrische Widerruf
  Pflicht und nicht Kuer.
- Gruppenmitgliedschaften greifen NICHT in bereits laufenden Prozessen; Kindprozesse erben die
  Gruppen ihres Elternprozesses zum Zeitpunkt von dessen Start. Nach der Einrichtung kann daher
  ein Neustart der Anwendung oder eine neue Anmeldung noetig sein. Die Oberflaeche weist darauf
  hin, statt einen Fehler zu zeigen -- die Einrichtung ist ja gelungen, sie wirkt nur noch
  nicht.
- Beim Anlegen der Gruppe wurde KEINE feste Gruppen-ID vergeben; gemessen erhielt sie die
  `501`, die zugleich die Kennung des ersten Benutzerkontos ist. Fuer die Rechtevergabe ist das
  unschaedlich, weil die Aufloesung ueber den NAMEN laeuft, es ist aber unsauber. Eine eigene
  Kennung aus einem freien Bereich waere sauberer -- offener Punkt. In diesem Zusammenhang setzt
  der Widerruf die Geraeterechte auch deshalb zurueck, damit eine spaeter neu angelegte Gruppe
  mit derselben Kennung den Zugriff nicht erbt.
- macOS legt BPF-Geraeteknoten teils dynamisch nach; ob spaeter erzeugte Knoten die
  Gruppenrechte erhalten, ist offen und zu beobachten.

## Abgrenzung

- **SMJobBless und ein privilegierter Helferdienst wurden verworfen:** ein dauerhaft laufender
  Root-Dienst waere eine groessere Angriffsflaeche als ein einmalig gesetztes Geraeterecht, und
  er widerspraeche der Linie aus ADR 0041, moeglichst wenig privilegiert zu laufen. Der
  gewaehlte Weg kommt ohne JEDEN Root-Prozess aus.
- **Das v1-Skript `scripts/install-bpf-permissions.sh` wurde NICHT uebernommen**, sondern der
  Weg nach den v2-Regeln neu geschrieben. Uebernommen wurde allein die Erkenntnis, dass der
  Zugriff ueber die BPF-Geraete laeuft. Die beiden harten Unterschiede sind das Rechtemodell
  (eigene Gruppe statt `o+rw`) und die Fehlerbehandlung ohne stille Fehlschlaege.
- **Die Einrichtung laeuft ueber das Python-Backend, nicht ueber einen Tauri-Befehl:** das
  Projekt hat keine Tauri-Kommandos, und ein zweiter Kommunikationsweg waere unnoetige
  Komplexitaet.
- **Die Ressource wird bewusst nicht aus einem temporaeren Verzeichnis gelesen.** Ein solcher
  Pfad ist als Quelle fuer Code, der als root laeuft, ungeeignet; ein Rueckfall darauf ist
  ebenfalls ausgeschlossen, weil sich der bevorzugte Pfad gezielt zum Scheitern bringen liesse
  und so der unsichere Zweig erzwingbar waere.
- **Linux bleibt unveraendert bei CAP_NET_RAW im Paket-Postinstall;** auf
  Nicht-macOS-Plattformen meldet die Einrichtung ehrlich `not_applicable`, statt einen Weg
  anzubieten, den es dort nicht gibt.
