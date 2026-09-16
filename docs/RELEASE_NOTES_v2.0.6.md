# CERNIS PRO 2.0.6

**Veröffentlicht:** August 2026

Diese Version schließt die Finalisierung der Reihe 2.0 ab. Alle sieben Auslieferungspakete wurden auf ihren Zielplattformen installiert und geprüft.

---

## Was neu ist

### Der Durchsatz je Programm arbeitet unter Linux ohne erhöhte Rechte

Bisher meldete CERNIS auf Linux, für die Anzeige des Durchsatzes je Programm seien erhöhte Rechte nötig, und ließ die Werte leer. Das war sachlich falsch: Die Zahlen stammen aus dem Systemwerkzeug ss, das sie jedem Benutzer liefert. Die Rechteforderung ist entfallen, die Werte werden angezeigt. Voraussetzung ist allein, dass ss vorhanden ist – es gehört auf allen gängigen Distributionen zum Paket iproute2.

Der Hilfetext zu dieser Ansicht war widersprüchlich formuliert und wurde in beiden Sprachen richtiggestellt.

### Windows: Domainnamen, Paketmitschnitt und Netzwerk-Nachbarn verfügbar

Drei Funktionsbereiche standen unter Windows bisher nicht zur Verfügung – das Auslesen echter Domainnamen aus dem Datenverkehr, der Paketmitschnitt und die Erkennung von Netzwerk-Nachbarn über LLDP und CDP. Der Grund war eine fehlende Verbindung zwischen den beiden Programmteilen, nicht eine Grenze des Betriebssystems. Diese Verbindung ist gebaut und geprüft, auf beiden Windows-Architekturen.

**Voraussetzung bleibt Npcap.** Fehlt es, benennt CERNIS das ausdrücklich und bietet die Nachinstallation an.

### Windows: Routenverfolgung

Die Routenverfolgung meldete unter Windows, das Programm traceroute sei nicht verfügbar – CERNIS suchte nach dem Unix-Werkzeug. Sie nutzt jetzt die Windows-eigene Schnittstelle und liefert die vollständige Route mit Antwortzeit, Land und Betreiber.

### Windows: Installer und Deinstallierer auf Deutsch

Beide Assistenten erschienen bisher unabhängig von der Systemsprache auf Englisch. Auf einem deutschen System erscheinen sie jetzt deutsch, ohne dass eine Sprache abgefragt wird. Auf allen anderen Systemsprachen erscheinen sie englisch.

### Länderflaggen werden zuverlässig angezeigt

In der Routenansicht erschienen unter Windows statt der Flagge zwei Buchstaben, weil die Systemschrift keine Nationalflaggen führt. CERNIS liefert die Flaggen jetzt als eigene Dateien mit – auf allen Plattformen gleich, ohne Nachladen aus dem Netz.

### macOS: neues Programmsymbol

Das Symbol lag bisher nur in einer einzigen kleinen Auflösung vor und wurde für jede größere Darstellung hochgerechnet. Es liegt jetzt in sechs Auflösungen bis 1024 Pixel vor, jede einzeln aus der Quelle gerechnet. Dasselbe gilt für das Windows-Symbol, das nun zehn statt einer Größe enthält.

### Weitere Verbesserungen

* **Geplante Scans** zeigen wieder, wann sie zuletzt gelaufen sind und wann der nächste Lauf kommt.
* **Angekündigte SSDP- und UPnP-Dienste** erscheinen als eigene, zuschaltbare Spalte im Scan.
* **Der DNS-Wächter** berücksichtigt jetzt die Server, die Sie als erwartet festgelegt haben.
* **Der CVE-Abgleich** nennt geprüfte und erfasste Geräte getrennt statt als Bruch, dessen beide Zahlen Verschiedenes zählten.
* **Netzwerk-Nachbarn über CDP** gehen nicht mehr verloren, wenn ein einzelnes Feld unlesbar ist.
* **Fehlende Dateien** beantwortet die Anwendung mit einer Fehlermeldung statt mit der Startseite.
* **Die Erkennung von Npcap** stützt sich nur noch auf Npcap-eigene Spuren; eine fremde Bibliothek wird nicht mehr fälschlich als Npcap gemeldet.
* Die dauerhaft gesperrte Kachel **Prozesse** wurde entfernt. Die Funktion kommt in einer späteren Version, wenn sie vollständig gebaut ist.



---



## Bekannte Einschränkungen



Diese Punkte sind uns bekannt, gemessen und für die nächste Version vorgesehen. Keiner davon führt zu Datenverlust, und für jeden gibt es einen Weg.


### Aufzeichnungen zeigen nach Ablauf ihrer Höchstdauer weiterhin läuft



Erreicht eine Aufzeichnung – Live-Monitoring oder Außenkontakte – die eingestellte Höchstdauer, wird die Datensammlung wie vorgesehen beendet, die Anzeige wechselt jedoch nicht in den Zustand abgeschlossen. Die aufgezeichneten Daten sind vollständig und stehen unverändert zur Auswertung bereit; die Aufzeichnung lässt sich jederzeit über Stopp abschließen. Behoben in der nächsten Version.



### Ein gelöschtes Überwachungsziel erscheint bis zum Neustart weiter in der Liste


Wird ein Ziel im Live-Monitoring gelöscht, verschwindet es aus der Ansicht, taucht beim erneuten Öffnen jedoch wieder auf – dann unter seiner technischen Kennung. Es wird nicht mehr überwacht und beeinflusst keine Messwerte. Nach einem Neustart der Anwendung ist es vollständig entfernt. Behoben in der nächsten Version.


### macOS: Gerätenamen können in einzelnen Scans fehlen



Bei mehreren Scans kurz hintereinander kann es vorkommen, dass ein einzelner Scan keine Gerätenamen anzeigt. Der Gerätebestand behält die zuvor ermittelten Namen unverändert; ein erneuter Scan zeigt sie wieder. Ein erfundener Name wird nie angezeigt – bleibt ein Name unbekannt, bleibt das Feld leer. Wir untersuchen die Ursache für die nächste Version.



### macOS: das Fehlerprotokoll enthält wiederholte Hinweise


Unter macOS schreibt CERNIS in bestimmten Fällen eine wiederkehrende Hinweiszeile in sein Fehlerprotokoll. Auf den Betrieb hat das keine Auswirkung. Behoben in der nächsten Version.


### Der Durchsatz je Programm wird auf macOS und Windows nicht angezeigt




Das ist keine Einschränkung dieser Version, sondern eine bewusste Festlegung – sie sei hier der Vollständigkeit halber genannt:



* **Auf macOS** stellt das Betriebssystem die nötige Auskunftsstelle nicht bereit. Das lässt sich nicht freischalten.

* **Unter Windows** gibt das Betriebssystem diese Zahlen nur an Programme heraus, die dauerhaft mit erhöhten Rechten laufen. **Genau darauf verzichtet CERNIS bewusst.** Ein Programmteil, der ständig mit erhöhten Rechten mitläuft, wäre ein Sicherheitsrisiko, das in keinem Verhältnis zum Gewinn einer einzelnen Zahlenspalte steht.



In beiden Fällen wird vollständig angezeigt, **welches** Programm mit **welcher** Gegenstelle spricht – nur nicht, wie viel dabei fließt. Wo eine Angabe fehlt, steht ein Gedankenstrich statt einer erfundenen Null.



### SSDP-Dienste können hinter einer Firewall unsichtbar bleiben



Manche Linux-Distributionen filtern in ihrer Standardeinstellung die Antworten, mit denen sich Geräte per SSDP und UPnP melden. CERNIS zeigt die Spalte dann leer, obwohl die Geräte antworten. Die Anfrage selbst verlässt den Rechner; verworfen werden die Antworten. mDNS ist davon nicht betroffen.



### Windows: die Programmdateien sind nicht signiert



Für Windows liegt dem Projekt kein Signaturzertifikat vor. Windows kann deshalb beim Start des Installers eine Warnung anzeigen. Die Prüfsumme jedes Pakets ist auf der Release-Seite veröffentlicht und lässt sich vor der Installation abgleichen.



### macOS: der Erststart braucht eine Internetverbindung



Die Anwendung ist von Apple notariell beglaubigt. Die Prüfung dieser Beglaubigung findet beim ersten Start online statt. Ohne Netzverbindung kann macOS den Start deshalb ablehnen.



### Auf ARM-Linux wird kein AppImage ausgeliefert



Das AppImage-Format lief auf keinem geprüften Linux-System zuverlässig und wird ab Version 2.0.5 nicht mehr ausgeliefert. Verwenden Sie stattdessen das deb- oder rpm-Paket.



---



## Die Pakete dieser Version



| Plattform | Datei |

|---|---|

| macOS (Apple Silicon) | CernisPro_2.0.6_aarch64.dmg |

| Linux x86-64 (Debian, Ubuntu) | CernisPro_2.0.6_amd64.deb |

| Linux x86-64 (Fedora, RHEL) | CernisPro-2.0.6-1.x86_64.rpm |

| Linux ARM64 (Debian, Ubuntu) | CernisPro_2.0.6_arm64.deb |

| Linux ARM64 (Fedora, RHEL) | CernisPro-2.0.6-1.aarch64.rpm |

| Windows x64 | CernisPro_2.0.6_x64-setup.exe |

| Windows ARM64 | CernisPro_2.0.6_arm64-setup.exe |



**Geprüft wurde jedes dieser Pakete einzeln**, installiert auf einer eigenen Maschine der Zielplattform.



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

* **Alle Einstellungen liegen in der Datenbank der Anwendung.** Es gibt keine Konfigurationsdateien, die von Hand zu pflegen wären.
