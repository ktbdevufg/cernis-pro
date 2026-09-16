# ADR 0020 — host_detail-Frame: is_changed (DHCP-IP-Wechsel) als Baseline-Signal

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Direkte Erweiterung der ADR-0019-Naht zwischen `scanning` (Event-Strom), `devices` (kuratierte Stammdaten + `last_ip`) und `analysis`-Historie, verdrahtet ausschließlich im Composition Root (`ws_scan.py`).
- **Bezug:** ADR 0019 (host_detail-Baseline-Anreicherung — gleiches best-effort-/Vorzustand-Muster, `is_known`-Default, `GetDevice`-Lesepfad); ADR 0013 (analysis-Historie, MAC-Identität, Leere-MAC-Linie); ADR 0006 (devices↔scanning-Schichtung).

## Kontext

Seit ADR 0019 trägt das `host_detail`-Frame `is_known` (Historie-Vorzustand) plus die kuratierten Felder (`label`/`tags`/`notes`) aus der devices-DB. Es fehlt ein zweites Baseline-Signal:

> **`is_changed`** — „das Gerät ist bekannt, aber seine IP hat sich seit dem letzten Mal geändert" (typisch: DHCP-Lease-Wechsel).

Die Datenquelle existiert bereits: `device.last_ip` aus der devices-DB, erreichbar über den schon verdrahteten `GetDevice`-Pfad (liefert `DeviceWithHistory`, kuratierte Felder + Stammdaten auf `.device`). **Kein** neues DB-Feld, **kein** zweiter DB-Zugriff — `last_ip` wird im selben `GetDevice`-Aufruf mitgelesen, der schon `label`/`tags`/`notes` holt.

**Disjunktheit zu „neu" (`is_known=false`).** Ein NEUES Gerät hat kein gespeichertes `Device` (bzw. `last_ip = None`) -> nie `is_changed`. Ein BEKANNTES Gerät mit abweichender IP -> `is_known=true` (nicht „neu") **und** `is_changed=true`. „neu" und „geändert" schließen sich damit automatisch aus.

## Entscheidung

1. **ANREICHERUNG AUSSCHLIESSLICH IM COMPOSITION ROOT.** `is_changed` wird in `ws_scan.py` (Loop) berechnet — **nicht** in `application/scanning`, **nicht** in den Domänen. `scanning` bleibt eine reine Funktion `ScanConfig -> Event-Strom` und kennt weiterhin weder `devices` noch `last_ip`. Identische Begründung wie ADR 0019: der Composition Root darf alle Domänen, der Lesepfad (`GetDevice`) sitzt hier bereits.

2. **`last_ip` MUSS aus dem VORZUSTAND gelesen werden — VOR dem devices-Upsert.** Der devices-Schreibpfad ist `RecordScannedHost` (`_record_host`), der über `merge_scan` `last_ip` **unbedingt** mit der aktuellen Scan-IP überschreibt und persistiert. Würde `_lese_kuratierung` (das `last_ip` mitliest) **nach** `_record_host` laufen, trüge `last_ip` schon die neue IP -> `is_changed` wäre immer False. Deshalb wird `_lese_kuratierung` im Loop **vor** `_record_host`/`_record_seen_host` gezogen:
   1. `baseline_known = is_known(mac)` — Historie-Vorzustand (ADR 0019), VOR `record_seen`.
   2. `kuratiert = _lese_kuratierung(get_device, mac)` — kuratierte Felder **und** `last_ip` aus dem devices-Vorzustand, **VOR** dem devices-Upsert.
   3. `record_host(...)` / `record_seen(...)` — die Schreib-Nähte (überschreiben jetzt `last_ip`, aber wir haben den Vorzustand schon gelesen).
   4. Frame bauen, mit `is_known`, den kuratierten Feldern und `is_changed` anreichern, senden.

   Die Verlegung ist für `label`/`tags`/`notes` folgenlos (der Upsert berührt die kuratierten Felder nicht) — sie betrifft allein den korrekten Vorzustand von `last_ip`.

3. **`is_changed`-DEFAULT im Frame-Schema = False.** `_host_detail_frame` setzt `is_changed: False` als Default („keine IP-Änderung, sofern nicht angereichert"). Der Loop überschreibt mit dem echten Wert. So ist `is_changed` **immer** im Frame vorhanden (definiertes Schema), auch wenn die Anreicherung übersprungen wird. `_host_detail_frame` bleibt eine reine Projektion ohne I/O.

4. **VERGLEICHSREGEL.** `is_changed=true` genau dann, wenn Kuratierung vorliegt **und** `last_ip` nicht `None` ist **und** `last_ip != event.host.ip`. Liegt keine Kuratierung vor (`DeviceNotFoundError` -> `None`) oder ist `last_ip` `None` (frisch angelegtes Gerät ohne IP-Historie), bleibt `is_changed=false`. Das erzwingt die Disjunktheit zu „neu" maschinell: ein Gerät ohne devices-Vorzustand kann nie „geändert" sein.

5. **MAC-LOSE HOSTS: nie „geändert".** Leere MAC -> `_lese_kuratierung` liefert `None` -> `is_changed=false` (wie bei „neu"/Kuratierung). Konsistent mit der Leere-MAC-Linie aus ADR 0013/0019.

6. **BEST-EFFORT, KEIN SCAN-ABBRUCH.** `is_changed` reitet auf demselben `_lese_kuratierung`-Lesevorgang wie die kuratierten Felder. Dessen Fehlerpfade (ADR 0019) gelten unverändert: `DeviceNotFoundError` -> `None` (keine Kuratierung, kein Fehler), jeder andere Fehler -> Warn-Log (`host_get_device_failed`) + `None`. In beiden Fällen ist `is_changed=false`. Kein zusätzlicher Fehlerpfad, kein stiller S3-Fallback.

## Konsequenzen

**Positiv**
- **DHCP-Lease-Wechsel sichtbar:** ein bekanntes Gerät mit neuer IP ist direkt am `host_detail`-Frame als `is_changed` markiert — ohne dass es fälschlich als „neu" erscheint.
- **Kein neuer I/O:** `last_ip` kommt aus dem schon vorhandenen `GetDevice`-Aufruf; nur additiv ins Rückgabe-`dict`. Kein neues DB-Feld, kein zweiter Read.
- **Disjunktheit maschinell erzwungen:** `is_changed` setzt einen devices-Vorzustand mit IP voraus, den ein neues Gerät per Definition nicht hat.
- **Vorzustand-Korrektheit:** durch das Vorziehen von `_lese_kuratierung` vor den devices-Upsert ist `last_ip` garantiert die ALTE IP, nicht die gerade geschriebene.
- **Best-effort-Symmetrie:** gleiches Fehler-/Vorzustand-Muster wie ADR 0019, kein neuer Pfad.

**Offen / später**
- **`is_changed` auch an `host_found`** (heute bewusst nicht — wie `is_known` erst am `host_detail`-Frame, kein verlässlicher Vorzustand zum frühen Zeitpunkt).
- **Bulk-Lesen** des devices-Vorzustands (Muster wie `is_known`/`get_device`), falls die Per-Host-Reads zum Engpass werden.
