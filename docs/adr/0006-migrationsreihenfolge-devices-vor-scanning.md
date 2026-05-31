# ADR 0006 — Migrationsreihenfolge: devices vor scanning

- **Status:** Akzeptiert
- **Datum:** 2026-05-28
- **Phase:** Phase 2, Vorklärung zur ersten Bestands-Domänen-Migration
- **Bezug:** Reihenfolge in `pre_release_202605.md` (Phase 2), ADR 0004 (Phase-2-Strategie), Phase-0-Befund devices/known_devices-Redundanz

## Kontext

Die Ist-Analyse der `scanning`-Domäne vor ihrer Migration zeigte, dass der WebSocket `/ws/scan` (`main.py:1666`) quer in die `devices`-Domäne greift:

- **schreibt** pro gefundenem Host über `update_device_from_scan` (`modules/devices_db.py`) in die `devices`-Tabelle,
- **liest** über `get_known_devices`, um bekannte/unbekannte Geräte zu markieren und Labels/Tags/Notes anzureichern.

Die Abhängigkeit läuft also **scanning → devices**, nicht umgekehrt. Die vorläufige Reihenfolge (`settings → scanning → …`) hätte erzwungen, `scanning` zu migrieren, bevor ein `DeviceRepository`-Port existiert — mit der Folge, einen **temporären Port/Adapter auf den `devices`-Altcode** zu legen und ihn nach der späteren `devices`-Migration wieder umzubauen. Wegwerf-Arbeit, die der Strangler-Linie widerspricht.

## Entscheidung

`devices` wird **vor** `scanning` migriert.

Leitprinzip: **Migration in Abhängigkeitsrichtung** — zuerst die Domäne, von der abhängig geschrieben/gelesen wird, dann die abhängige. Damit existiert der `DeviceRepository`-Port bereits, wenn `scanning` ihn braucht; `scanning` verdrahtet sich gegen den fertigen Port statt gegen Altcode.

Neue Reihenfolge: `settings` (✓) → `devices` → `scanning` → `monitoring` → `alerting` → `capture` → `agent` → Hilfsmodule. Die „vorläufig, in Phase 0 finalisiert"-Klausel der Reihenfolge deckt diese Verfeinerung ab.

## Konsequenzen

**Positiv**
- **Kein Wegwerf-Adapter:** Der `DeviceRepository`-Port steht, wenn `scanning` ihn konsumiert — keine temporäre Übergangskopplung auf devices-Altcode, die später rückgebaut wird.
- Bei der `devices`-Migration wird zugleich die bekannte **devices/known_devices-Redundanz** (Phase-0-Befund) aufgelöst, statt sie über eine scanning-zuerst-Migration zu zementieren.

**Risiko / Restfenster**
- `scanning` bleibt die am stärksten verwobene Domäne (greift zusätzlich in settings, fritz, mdns/ssdp, ipv6) und folgt als **zweite** — dann aber mit dem an `devices` erprobten Muster (Characterization → `domain` → `ports` → `infrastructure` → `application` → `api` → Verdrahtung in `app.py`).
