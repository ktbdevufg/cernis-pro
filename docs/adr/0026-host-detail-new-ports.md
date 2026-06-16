# ADR 0026 — host_detail-Frame: new_ports (neuer Port seit letztem Scan) als Baseline-Signal

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Direkte Erweiterung der ADR-0019/0020-Naht zwischen `scanning` (Event-Strom), `devices` (kuratierte Stammdaten + `last_ip` + `open_ports`) und `analysis`-Historie, verdrahtet ausschließlich im Composition Root (`ws_scan.py`).
- **Bezug:** Konzept §4 (Port-History, Achse A); ADR 0020 (host_detail-`is_changed` — identisches Vorzustand-/best-effort-/Timing-Muster, `GetDevice`-Lesepfad, Disjunktheit zu „neu"); ADR 0019 (host_detail-Baseline-Anreicherung, `GetDevice`-Naht, Leere-MAC-Linie); Konzept §4.

## Kontext

Seit ADR 0019/0020 trägt das `host_detail`-Frame `is_known` (Historie-Vorzustand) und `is_changed` (DHCP-IP-Wechsel) plus die kuratierten Felder aus der devices-DB. Das Konzept §4 (Port-History, Achse A) fordert ein weiteres wertneutrales Baseline-Signal:

> **`new_ports`** — „seit dem letzten Scan ist auf Host X Port Y neu offen".

Das ist ein **wertneutrales Faktum**, KEIN Urteil — NICHT die Auffälligkeits-Engine (Achse B). Es kennt keinen Acknowledge und ist selbsterledigend: beim Folgescan wird der neue Portstand zur Baseline.

Die Datenquelle existiert bereits: `device.open_ports` (`tuple[int, ...]`) aus der devices-DB, erreichbar über den schon verdrahteten `GetDevice`-Pfad — genau wie `last_ip`. **Kein** neues DB-Feld, **kein** zweiter DB-Zugriff — `open_ports` wird im selben `GetDevice`-Aufruf mitgelesen, der schon `label`/`tags`/`notes`/`last_ip` holt.

**Disjunktheit zu „neu" (`is_known=false`).** Ein NEUES Gerät hat kein gespeichertes `Device` -> keine `open_ports`-Baseline -> `new_ports` bleibt leer. Per Definition hat ein neues Gerät keine „neuen Ports seit letztem Scan" — es war nie da. „neuer Host" und „neuer Port" schließen sich damit automatisch aus, exakt symmetrisch zu `is_changed`.

## Entscheidung

1. **ANREICHERUNG AUSSCHLIESSLICH IM COMPOSITION ROOT.** `new_ports` wird in `ws_scan.py` (Loop) berechnet — **nicht** in `application/scanning`, **nicht** in den Domänen. `scanning` bleibt eine reine Funktion `ScanConfig -> Event-Strom` und kennt weiterhin weder `devices` noch den `open_ports`-Vorzustand. Identische Begründung wie ADR 0019/0020: der Composition Root darf alle Domänen, der Lesepfad (`GetDevice`) sitzt hier bereits.

2. **`open_ports` MUSS aus dem VORZUSTAND gelesen werden — VOR dem devices-Upsert.** Der devices-Schreibpfad ist `RecordScannedHost` (`_record_host`), der über `merge_scan` `open_ports` **unbedingt** mit dem aktuellen Scan-Portstand überschreibt und persistiert. Würde `_lese_kuratierung` (das `open_ports` mitliest) **nach** `_record_host` laufen, trüge `open_ports` schon den neuen Stand -> `new_ports` wäre immer leer. Deshalb reitet `new_ports` auf dem schon vorgezogenen `_lese_kuratierung`-Read (ADR 0020):
   1. `baseline_known = is_known(mac)` — Historie-Vorzustand (ADR 0019), VOR `record_seen`.
   2. `kuratiert = _lese_kuratierung(get_device, mac)` — kuratierte Felder, `last_ip` **und** `open_ports` aus dem devices-Vorzustand, **VOR** dem devices-Upsert.
   3. `record_host(...)` / `record_seen(...)` — die Schreib-Nähte (überschreiben jetzt `open_ports`, aber wir haben den Vorzustand schon gelesen).
   4. Frame bauen, mit `is_known`, den kuratierten Feldern, `is_changed` und `new_ports` anreichern, senden.

3. **AKTUELLER PORTSTAND IDENTISCH ZUR `_project`-PROJEKTION.** Der aktuelle offene Portstand wird `tuple(p.port for p in host.ports)`-äquivalent gebildet — `{p.port for p in event.host.ports}`, ALLE Portnummern aus `host.ports`, **OHNE** eigenen state-Filter. `_project` speichert `open_ports` exakt so; ein abweichender Filter verglich Ungleiches. Vorzustand: `set(kuratiert["open_ports"])`. `new_ports = sorted(aktuell - vorzustand)`.

4. **NUR ZUGÄNGE ZÄHLEN.** `new_ports` ist die Mengen-Differenz `aktuell - vorzustand` — nur neu dazugekommene Ports. Ein WEGGEFALLENER Port (im Vorzustand, nicht mehr im Scan) ist KEIN „neuer Port" und erscheint nicht. Ausgabe aufsteigend sortiert.

5. **`new_ports`-DEFAULT im Frame-Schema = `[]`.** `_host_detail_frame` setzt `new_ports: []` als Default („keine neuen Ports, sofern nicht angereichert"). Der Loop überschreibt — INNERHALB des `if kuratiert is not None:`-Blocks — mit dem echten Wert. So ist `new_ports` **immer** im Frame vorhanden (definiertes Schema), auch wenn die Anreicherung übersprungen wird. `_host_detail_frame` bleibt eine reine Projektion ohne I/O.

6. **DISJUNKT ZU „NEUES GERÄT".** `new_ports` wird nur gesetzt, wenn `kuratiert is not None` (ein devices-Vorzustand existiert). Liegt keine Kuratierung vor (`DeviceNotFoundError` -> `None`), bleibt `new_ports` der Default `[]`. Das erzwingt die Disjunktheit maschinell — wie `is_changed`: kein Vorzustand -> kein Signal.

7. **MAC-LOSE HOSTS: leer.** Leere MAC -> `_lese_kuratierung` liefert `None` -> `new_ports` bleibt `[]`. Konsistent mit der Leere-MAC-Linie aus ADR 0013/0019/0020.

8. **BEST-EFFORT, KEIN SCAN-ABBRUCH.** `new_ports` reitet auf demselben `_lese_kuratierung`-Lesevorgang wie die kuratierten Felder und `last_ip`. Dessen Fehlerpfade (ADR 0019) gelten unverändert: `DeviceNotFoundError` -> `None`, jeder andere Fehler -> Warn-Log (`host_get_device_failed`) + `None`. In beiden Fällen ist `new_ports` leer. Gleicher Pfad wie `is_changed`, kein zusätzlicher Fehlerpfad, kein stiller S3-Fallback.

## Abgrenzung

Die im Konzept §4 erwähnte **eigene Port-History-Tabelle** (volle Langzeit-Historie analog `device_ip_history`) ist bewusst ein SPÄTERER, eigener Schnitt — **nicht** Teil dieser Entscheidung. Hier nur das Vorzustand-Delta-Signal `new_ports` am `host_detail`-Frame, schlank und symmetrisch zu ADR 0020: kein neues DB-Feld, keine neue Tabelle, kein neuer Read. Es wird nichts vorgebaut.

## Konsequenzen

**Positiv**
- **Neue offene Ports sichtbar:** ein bekanntes Gerät mit seit dem letzten Scan neu offenem Port ist direkt am `host_detail`-Frame markiert — ohne dass ein neues Gerät fälschlich Ports als „neu" zeigt.
- **Kein neuer I/O:** `open_ports` kommt aus dem schon vorhandenen `GetDevice`-Aufruf; nur additiv ins Rückgabe-`dict` von `_lese_kuratierung` und ein Frame-Feld. Kein neues DB-Feld, kein zweiter Read.
- **Disjunktheit maschinell erzwungen:** `new_ports` setzt einen devices-Vorzustand voraus, den ein neues Gerät per Definition nicht hat (`if kuratiert is not None`).
- **Vorzustand-Korrektheit:** durch das schon vorgezogene `_lese_kuratierung` (ADR 0020) ist `open_ports` garantiert der ALTE Stand, nicht der gerade geschriebene.
- **Best-effort-Symmetrie:** gleiches Fehler-/Vorzustand-/Timing-Muster wie ADR 0020, kein neuer Pfad.

**Offen / später**
- **Eigene Port-History-Tabelle** (Konzept §4, volle Langzeit-Historie) — bewusst ein späterer Schnitt (siehe Abgrenzung).
- **Frontend-Kopplung** (CERNIS-Farbe für das Achse-A-Signal) — späterer Schnitt; dieser Schnitt liefert nur das Frame-Feld.
