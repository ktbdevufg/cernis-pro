# ADR 0007 — systemnahe Infrastructure-Adapter dürfen `modules/` importieren (eng eingezäunt)

- **Status:** Akzeptiert
- **Datum:** 2026-05-28 (Erweiterung um monitoring: 2026-06-03, Schritt M.4)
- **Phase:** Phase 2, Schritt S.3 (scanning-Ports); erweitert in M.4 (monitoring-Adapter)
- **Bezug:** `vision_features_202605.md` Abschnitt 5.2 (die eine gekapselte Ausnahme: systemnahe Adapter); CLAUDE.md (Importregeln, „neue Ringe importieren NICHT den Altcode"); ADR 0003 (`ignore_imports`/Optionen am Contract als Präzedenz); `pyproject.toml` `[tool.importlinter]`

## Kontext

Der `import-linter`-Contract „neue Ringe importieren NICHT den Altcode (modules/)" verbietet allen fünf Ringen (`domain`, `ports`, `application`, `infrastructure`, `api`) den Import aus `modules/`. Das hält den Altcode strikt aus den sauberen Ringen heraus; der einzige Legacy-Bezug liegt im Composition Root (`app.py`, nicht analysiert).

Die scanning-Domäne ist die systemnächste des Bestands: Host-Discovery (ICMP/ARP), Portscan (socket/nmap), mDNS/SSDP, IPv6 (NDP/EUI-64) und FRITZ!Box (TR-064). Genau diese Schicht ist in `vision_features_202605.md` Abschnitt 5.2 als **die eine geplante, gekapselte Ausnahme** benannt: Sie soll hinter einem stabilen Port so liegen, dass sie **bei Bedarf in einer systemnäheren Sprache neu geschrieben werden kann, ohne den Rest anzufassen** — aber **nicht jetzt**, mitten im Rewrite.

Die scanning-Adapter (S.4) gegen den bestehenden, funktionierenden `modules/`-Code zu verdrahten statt ihn zeilenweise in `infrastructure/scanning/` zu reimplementieren, vermeidet **Wegwerf-Arbeit**: Eine sorgfältige Python-Reimplementierung der systemnahen Schicht würde — falls 5.2 eintritt — kurz darauf wieder verworfen. Das widerspricht der Strangler-Linie (kein temporärer Umbau, der absehbar zurückgebaut wird) und dem Snapshot-Grundsatz „erst Struktur, Sprachwechsel falls nötig lokal und später".

## Entscheidung

Die scanning-**Infrastructure-Adapter** dürfen `modules/` importieren — und **nur sie**. Die Ports (`backend/ports/scanning.py`) kennen weiterhin ausschließlich `domain/scanning` + stdlib; die Domänen- und Logik-Ringe (`domain`, `ports`, `application`, `api`) bleiben CI-hart von `modules/` getrennt.

Maschinisch umgesetzt **subtraktiv** über `ignore_imports` am bestehenden Contract, **nicht** als zweiter Contract:

```toml
[[tool.importlinter.contracts]]
name = "neue Ringe importieren NICHT den Altcode (modules/)"
type = "forbidden"
source_modules = ["domain", "ports", "application", "infrastructure", "api"]
forbidden_modules = ["modules"]
ignore_imports = [
    "infrastructure.scanning.** -> modules",
]
```

**Warum subtraktiv und nicht additiv:** Ein `forbidden`-Contract kann nur *verbieten*, nie *erlauben*. Ein separater zweiter Contract könnte die Sperre des ersten also gar nicht aufheben — die Lockerung *muss* am bestehenden Contract hängen. `ignore_imports` schneidet ausschließlich Importe aus dem Paket `infrastructure.scanning` (beliebige Tiefe via `**`) in den Altcode heraus; `source_modules`/`forbidden_modules` bleiben unverändert. Jeder andere Ring und jeder andere infrastructure-Adapter bleibt vom **selben** Contract weiter gegen `modules/` geblockt.

**Pattern-Form (in S.4a empirisch korrigiert):** Die Zielseite ist `modules` **ohne** Suffix. Der `forbidden`-Contract löst die Kanten gegen das verbotene *Paket* `modules` auf (nicht gegen `modules.resolver` o. ä.) — `import-linter` meldet die Verletzung als `infrastructure.scanning.X -> modules`, also matcht nur die Form `... -> modules`. Eine ursprünglich (in S.3) gewählte Form `infrastructure.scanning.* -> modules.*` matcht im Contract-Kontext **nichts** (`lint-imports`: „No matches for ignored import"). In S.3 war zusätzlich `unmatched_ignore_imports_alerting = "none"` gesetzt, weil noch kein scanning-Adapter existierte — dieser Schalter **maskierte** den Pattern-Fehler: Der Contract galt scheinbar als `KEPT`, obwohl die Ausnahme gar nicht griff. Mit dem ersten echten Adapter (S.4a) fiel das auf. Korrektur: treffende Form `infrastructure.scanning.** -> modules` **und** `unmatched_ignore_imports_alerting` entfernt — eine nicht-matchende Expression soll künftig wieder hart auffallen, nicht still durchgehen (kein stiller Fallback, vgl. ADR 0001 / Finding S3).

## Konsequenzen / Sicherheitsnachweis

Die Mechanik wurde nach der S.4a-Korrektur mit zwei temporären Proben empirisch belegt (jeweils `PYTHONPATH=backend uv run lint-imports`, danach zurückgebaut):

1. **`modules`-Import außerhalb scanning** (Probe-Import in `infrastructure/_probe_outside.py`): **BROKEN.** Der Guardrail greift unverändert für alle nicht-scanning-Adapter.
2. **Beliebiges *neues* `modules`-Ziel in `infrastructure/scanning/`** (Probe-Import `modules.portscan` in `infrastructure/scanning/_probe_inside.py`): **KEPT**, ohne „No matches" — das `**` auf der Quellseite deckt also auch die noch folgenden scanning-Adapter (S.4b) automatisch ab.

Nach der Korrektur: **7 Contracts, 7 kept, 0 broken** (mit den realen S.4a-Adaptern `vendor_lookup`/`hostname_resolver`, deren `modules`-Importe sauber ignoriert werden). Die sechs übrigen Contracts (domain-Reinheit, Schichtung, Framework-Freiheit) sind von der Änderung unberührt.

**Positiv**
- Keine Wegwerf-Reimplementierung der systemnahen Schicht; die scanning-Adapter verdrahten sich gegen den erprobten `modules/`-Code hinter stabilen Ports.
- Die Ausnahme ist maschinell auf `infrastructure.scanning` begrenzt — sie kann nicht unbemerkt in andere Adapter oder Ringe lecken; jeder Versuch bricht CI (Probe 1).
- Logik-Ringe bleiben rein: `ports/scanning.py` importiert nur `domain/scanning`; `application`/`domain`/`api` sehen `modules/` nie.

**Kosten / Restfenster (temporär)**
- Die Ausnahme ist **bewusst temporär.** Sie fällt weg, sobald die systemnahe Schicht ersetzt ist (Sprachwechsel gemäß 5.2 *oder* eine native Reimplementierung nach Stabilisierung). Dann werden die `ignore_imports`-Zeilen gelöscht und der Contract steht wieder lückenlos für alle Ringe.
- Solange sie besteht, sind `infrastructure/scanning/` und `infrastructure/monitoring/` die einzigen Stellen, an denen Alt- und Neu-Code aneinanderstoßen. Das ist gewollt und genau die in 5.2 vorgesehene Kapselungsgrenze.

## Erweiterung M.4 — monitoring (2026-06-03)

Dieselbe Begründung greift für die **monitoring**-Domäne: Auch sie ist systemnah. Der Live-Connectivity-Monitor pingt Targets (`_ping_burst`/`_ping_once` — `subprocess`/`asyncio.create_subprocess_exec` mit Interface-Bindung, RTT-Regex-Parsing) und löst Desktop-Notifications aus (`_notify_macos` — `osascript`). Diese zwei Operationen in `infrastructure/monitoring/` zeilenweise zu reimplementieren wäre dieselbe Wegwerf-Arbeit vor einem möglichen Sprachwechsel, die ADR 0007 für scanning vermeidet.

Daher wird die Ausnahme **auf monitoring ausgedehnt**, mit einer zweiten `ignore_imports`-Zeile am **selben** Contract (nicht als neuer ADR — es ist dieselbe Entscheidung, nur eine zweite Domäne):

```toml
ignore_imports = [
    "infrastructure.scanning.** -> modules",
    "infrastructure.monitoring.** -> modules",
]
```

**SCOPED — bewusst minimaler modules-Footprint:** Der `**`-Scope erlaubt dem *ganzen* Paket `infrastructure.monitoring` den modules-Import, aber real nutzen ihn **nur zwei** Adapter:

- `pinger.py` → wrappt `modules.monitor._ping_burst` (Executor),
- `notifier.py` → wrappt `modules.monitor._notify_macos` (Executor).

Die übrigen drei M.4-Adapter kommen **bewusst ohne `modules`** aus:

- `rtt_history.py` / `monitor_events.py` → eigenes SQLite-Schema (Muster `SqliteScanHistoryRepository`); kein `modules`-Bezug nötig. `rtt_history` ergänzt dabei die `alive`-Spalte (M.1-Wurzel-Fix, siehe unten).
- `target_source.py` → liest `monitor_custom_targets` über den **migrierten** `ports/settings.SettingsRepository`-Port (Adapter→Port ist erlaubt: der `infrastructure`-Contract verbietet nur `application`/`api`, nicht `ports`). Einziger modules-Bezug wäre `modules.interfaces.get_interfaces` (unmigriertes Hilfsmodul) — durch dieselbe `**`-Zeile abgedeckt.

Diese Disziplin (Scope maschinell breit, realer Footprint schmal) ist absichtlich: Sie hält die Alt/Neu-Grenze auf das systemnahe Minimum (Ping/Notification), statt den ganzen monitoring-Adapter-Block an `modules` zu binden.

**Begleitende Schema-Entscheidung (M.4, kein Teil dieses ADR, hier nur referenziert):** Der `rtt_history`-Adapter legt die Tabelle **mit** einer `alive`-Spalte an (`CREATE TABLE IF NOT EXISTS` + idempotenter `ALTER TABLE … ADD COLUMN alive INTEGER DEFAULT 0`-Guard für bereits vom Altcode-Loop angelegte Tabellen). Das heilt die in M.1 dokumentierte gemeinsame Wurzel dreier toter Stränge (metrics-`alive`-Block, homeassistant, influx). Es ist eine v2-Abweichung vom Altcode-Schema — die M.1-Charakterisierer bleiben unberührt, weil sie `modules.monitor` (Altcode) testen, nicht den v2-Adapter.

**lint-imports nach der Erweiterung:** weiterhin 7 Contracts, 7 kept (die neue Zeile matcht ab dem ersten monitoring-Adapter real; vor dem ersten Adapter würde sie als „No matches" hart auffallen — kein `unmatched`-Schalter, wie schon für scanning entschieden).
