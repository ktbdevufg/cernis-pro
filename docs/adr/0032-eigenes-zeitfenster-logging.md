# 0032 - Eigenes Zeitfenster-Logging getrennt vom fluechtigen Live-Monitor

## Status

Akzeptiert

## Kontext

Der Live-Monitor (RunMonitor-Loop) misst app-weit drei feste Ziele plus
benutzerdefinierte Ziele und haelt nur eine fluechtige Kurz-History: `rtt_history`
cappt pro Ziel hart auf 1000 Zeilen (~80 Minuten bei 5-Sekunden-Takt), `monitor_events`
kennt keinen Zeitraum-Filter. Das genuegt fuer die Live-Ansicht, nicht fuer eine
bewusste Langzeit-Beobachtung mit Auswertung ueber Tage oder Wochen.

Das freigegebene Monitoring-Konzept (Paragraph 3) fordert eine zweite, getrennte Ebene:
ein opt-in Langzeit-Monitoring, das nur fuer ein bewusst eingerichtetes Zeitfenster
persistent mitschreibt, mit eigener Aufbewahrungsfrist und spaeterer Auswertung. Die
Frage war, ob diese Funktion die bestehenden Live-Tabellen mitbenutzt oder eine eigene
Persistenz bekommt.

## Entscheidung

Das Zeitfenster-Logging erhaelt eine vollstaendig eigene Persistenz, getrennt vom
fluechtigen Live-Monitor:

- Eigene Domaene `domain/monitoring/logging_task.py` (LoggingTask plus die Enums
  CaptureMode, OperationMode, TaskState; reine, zeitfreie Zustands- und Fenster-Logik).
- Drei eigene Tabellen statt Mitbenutzung der Live-Tabellen: `monitoring_log_tasks`
  (Aufgaben-Definitionen mit Lebenszyklus), `monitoring_log_rtt` (dichte Messpunkte),
  `monitoring_log_events` (Ereignis-Flanken).
- Getrennte Aufbewahrung statt des Live-Zeilen-Caps: Messpunkte ein Monat, Ereignisse
  ein Jahr, durchgesetzt ueber zeitbasierte Loeschung (delete_older_than), nicht ueber
  einen festen Zeilen-Cap wie `rtt_history`.
- Das Logging-Ereignis-Vokabular bleibt am Persistenz-Rand ein roher String und wird
  bewusst NICHT an die Live-Monitor-Enum MonitorEventType gebunden.

## Begruendung

Die beiden Ebenen haben gegensaetzliche Anforderungen. Der Live-Monitor will einen
kleinen, selbstbegrenzenden Ringpuffer ohne Pflegeaufwand; das Langzeit-Logging will
ein definiertes Fenster lueckenlos behalten und nach einer fachlichen Frist aufraeumen.
Beide in dieselbe Tabelle zu legen wuerde den Live-Cap mit der Langzeit-Aufbewahrung
vermischen und eine der beiden Anforderungen verletzen.

Die Trennung haelt zudem die Domaenen-Grenze sauber: der Logging-Kern bindet sich nicht
an das up/down/degraded-Vokabular des Live-Monitors und kann sein eigenes
Ereignis-Vokabular spaeter unabhaengig bestimmen. Der RunMonitor-Loop bleibt voellig
unberuehrt.

## Konsequenzen

- Eine bewusste Einrichtung ueber die gefuehrte Maske schreibt persistent mit; im
  Normalbetrieb wird nichts dauerhaft gespeichert (sparsamer Default).
- Das tatsaechliche Befuellen der Mess-Tabellen aus echten Messungen (Loop-Anbindung),
  die Wiederaufnahme nach Neustart und der periodische Aufraeum-Lauf sind ein eigener
  Folgeschritt (B-II), nicht Teil dieser Entscheidung.
- Die Aufbewahrungsfristen sind als benannte Konstanten hinterlegt, aber uhrfrei: die
  konkreten Stichzeitpunkte rechnet der Aufrufer, nicht die Use-Cases oder Repositories.
