# 0034 — Schwellwert-Alarme: eigenes Regelmodell statt alerting-Wiederverwendung

## Status

Akzeptiert

## Kontext

Logging-Aufgaben sollen optional alarmieren, wenn ein Ziel eine Bedingung über
mehrere Messungen hinweg verletzt ("Latenz über X ms" oder "Ziel nicht erreichbar").
Es existiert bereits eine `alerting`-Domäne (`AlertRule`, `select_rules_to_fire`,
`RaiseAlert`), die regelbasierte Alarme an den up/down-Flanken des flüchtigen
Live-Monitors auslöst (ADR-Bezug A.7a, Composition-Root-Naht `_MonitorAlertRaiser`).

Die Frage war, ob Schwellwert-Alarme dieses bestehende `AlertRule`-Schema
mitbenutzen oder ein eigenes Regelmodell bekommen.

Befund am Code: Das `AlertRule`-Schema ist bewusst charakterisierungstreu aus dem
Altcode eingefroren. Es matcht über `rule_type` + `target` + Cooldown; sein
`threshold`-Feld ist ausschließlich der Cooldown in Sekunden (in A.1 verifiziert,
trotz des irreführenden Altcode-Namens), NICHT ein Mess-Grenzwert. Es kennt keinen
Zahlenvergleich, keine Vergleichsrichtung, keine "über N Messungen"-Hysterese und
keinen Bezug zu einem Logging-Task. Die reine Auswahl-Funktion `select_rules_to_fire`
ist eine Ereignis-Auswahl, kein Schwellwert-Auswerter.

## Entscheidung

Schwellwert-Alarme bekommen ein **eigenes Regelmodell in der monitoring-Domäne**,
verankert am Logging-Task — nicht im `AlertRule`-Schema.

Konkret:

- **Domäne** (`domain/monitoring/latency_threshold.py`): `LatencyThreshold`
  (frozen) mit `condition` (`ThresholdCondition`: latency_above/unreachable),
  `limit_ms`, `consecutive_n` (Hysterese), `notify_desktop`/`notify_email`. Dazu
  `ThresholdState` (frozen: streak + in_alarm) und die reine, zeitfreie Funktion
  `evaluate_sample`, die pro Messung den Zustand fortschreibt und eine Alarm-FLANKE
  meldet (fired=True genau im Aufruf, der die Schwelle erreicht; kein Dauerfeuer,
  Entspannung setzt zurück). Muster wie `logging_task.py` (frozen dataclasses,
  `dataclasses.replace`, keine Uhr/I/O).

- **Persistenz**: Der Schwellwert hängt 1:1 am Task und wird als zusätzliche,
  nullable Spalten in `monitoring_log_tasks` gespeichert (Schema-Guard wie
  effective_start/interval_s), KEINE eigene Tabelle.

- **Auswertung** im Logging-Sink (pro Tick je aktiver Aufgabe, Hysterese-Zustand
  in-memory wie `_letzter_rtt_ts`), NICHT über einen neuen RunMonitor-Port: der Sink
  sieht ohnehin jeden Tick je Task. Best-effort (wirft nie).

- **Benachrichtigung** über den vorhandenen alerting-`AlertNotifierPort` (Desktop +
  E-Mail) — wiederverwendet, aber über eine EIGENE schmale Naht
  (`ThresholdNotifierPort` + Composition-Root-Wrapper `_ThresholdNotifierWiring`,
  Muster `_MonitorAlertRaiser`), NICHT über `RaiseAlert`/`select_rules_to_fire`.

- **Hysterese (N-aus-M) ist Teil von v1**, nicht aufgeschoben: ohne sie wäre ein
  RTT-Schwellwert im realen Heimnetz unbrauchbar (einzelne Ausreißer feuern sofort).
  `consecutive_n` ist nutzerseitig einstellbar (Default 3, N=1 = sofort).

## Konsequenzen

**Positiv:**
- Die charakterisierungstreu eingefrorene `alerting`-Domäne bleibt unangetastet —
  keine Erweiterung einer Altcode-Naht für einen fremden Zweck.
- Der Schwellwert ist sauber am Task modelliert (eigenes Fenster, eigener
  Hysterese-Zustand), wo er fachlich hingehört.
- Volle Freiheit beim Zuschnitt (Vergleichsrichtung, Hysterese, Kanäle) ohne
  Rücksicht auf das generische `AlertRule`-Schema.
- Die independence-Contracts bleiben hart: weder die Domäne noch der neue Port nennt
  alerting; das Mapping auf den alerting-Notifier lebt allein im Composition Root.

**Negativ / Kosten:**
- Eine zweite Notifications-Naht neben `_MonitorAlertRaiser` (bewusst getrennt, da
  unterschiedlicher Belang: Live-Monitor-Flanke vs. Logging-Task-Schwellwert).
- Die Benachrichtigungs-Nachricht (View-Vokabular) lebt im Composition-Root-Wrapper,
  nicht in der Domäne — konsistent mit der `_MonitorAlertRaiser`-Entscheidung.

**Bewusst NICHT umgesetzt (kein Vorbau):**
- Kein separater Edit-Endpunkt für den Schwellwert: er wird in der Anlage-Maske
  gesetzt. Nachträgliches Editieren ist ein eigener späterer Schnitt, falls gebraucht.
