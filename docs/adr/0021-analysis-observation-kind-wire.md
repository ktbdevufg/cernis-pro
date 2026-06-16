# ADR 0021 — kind-Feld in der Observation (Wire): Host-/Verbindungs-/Prozess-Befunde unterscheidbar

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Reine, additive Erweiterung der analysis-Domäne (`domain/analysis`) plus ihres Wire (`api/analysis`); keine neue Domäne, kein neuer Use-Case, keine Verdrahtung im Composition Root.
- **Bezug:** ADR 0012 (analysis-Domäne — `Rule` als Daten, `Observation` wertneutral, Engine als reine Funktion); ADR 0002 (domain bleibt framework-/URL-frei); ADR 0013 (analysis-Historie, `host_new`-Regel).

## Kontext

Das geplante „auffällig"-Flag der Scan-Tabelle muss im Frontend **Host-Befunde** (eine `Observation`, die ein GERÄT betrifft — `kind` `host_remote_port` / `host_new`) von **Verbindungs-/Prozess-Befunden** (`connection_remote_port`, `process_temp_path`, `process_masquerade`, `pid_connection_count`) unterscheiden, um nur die geräte-bezogenen Befunde an der Host-Zeile zu markieren.

Heute trägt nur die `Rule` ein deklaratives `kind` (`RuleKind`, das die Engine dispatcht). Die erzeugte `domain.analysis.Observation` trägt es **nicht** — sie führt `rule_id`, `severity`, `title`, `detail`, `help_kind`, `subject`. Das Frontend könnte Host-Befunde derzeit nur über eine **gepflegte `rule_id`-Liste** (`host_remote_access_port`, `new_host_seen`, …) erkennen. Das ist fragil: jede neue Host-Regel müsste in dieser Frontend-Liste nachgezogen werden, sonst fällt ihr Befund stillschweigend aus dem „auffällig"-Flag.

Das `kind` der erzeugenden Regel ist an jeder Observation-Konstruktion in der Engine bereits im Scope (neben `rule_id=rule.id` steht überall ein `rule`-Objekt). Es ist die stabile, semantische Klassen-Achse („host\_\*" vs. „connection\_\*" vs. „process\_\*"), die das Frontend ohnehin meint — nur bislang nicht ausgegeben.

## Entscheidung

1. **`kind: RuleKind` als neues Feld der frozen `Observation`-Dataclass** (`domain/analysis/rules.py`), nach `subject`. `RuleKind` ist in derselben Datei definiert — kein neuer Import, domain bleibt rein (stdlib + dataclasses + typing). Das Feld ist Pflicht (kein Default): jede Observation entsteht aus genau einer Regel, deren `kind` bekannt ist.

2. **Die Engine füllt `kind=rule.kind` an JEDER der sechs `Observation(...)`-Konstruktionen** (`domain/analysis/engine.py`, eine je Auswertungs-Zweig). `rule` ist überall im Scope; rein additiv, keine Logik-, keine Severity-Änderung. Die Sortier-/Dedup-Logik bleibt unberührt — `kind` geht **NICHT** in den Sortierschlüssel `(severity-Rang, rule_id, subject)` ein (es ist je `rule_id` konstant, also für die Ordnung redundant).

3. **Der Wire gibt `kind` aus** (`api/analysis.py`, `_resolved_to_dict`): ein neuer Key `"kind": r.observation.kind` nach `"subject"`. Reiner Attribut-Zugriff wie die übrigen Felder, kein domain-Import im api-Ring.

4. **Keine Werturteils-Verschiebung.** `kind` ist eine *Klassifikations*-Achse (welche Art Befund), keine *Wertungs*-Achse. Die rote Linie aus ADR 0012 bleibt: analysis zeigt + ordnet ein, urteilt nie. `severity` (info/notable) bleibt die einzige Einordnungs-Stufe; `kind` sagt nur, *worüber* der Befund spricht.

## Konsequenzen

**Positiv**
- **Frontend filtert Host-Befunde sauber:** `kind.startsWith("host_")` (bzw. ein Set `{host_remote_port, host_new}`) statt einer gepflegten `rule_id`-Liste. Eine neue Host-Regel mit `kind` `host_*` fällt automatisch ins „auffällig"-Flag — kein Frontend-Nachzug nötig.
- **Rein additiv:** ein Feld, ein Wire-Key. Bestehende Konsumenten, die `kind` ignorieren, sind unberührt; kein Vertrag wird gebrochen (nur erweitert).
- **domain bleibt rein:** `RuleKind` ist domain-eigenes Vokabular, kein Framework-/URL-Bezug; der api-Ring serialisiert per Attribut-Zugriff ohne domain-Import.
- **Determinismus unverändert:** `kind` ist kein Sortierschlüssel; gleiche Eingabe -> gleiche, gleich sortierte Ausgabe wie zuvor.

**Offen / später**
- **Konsumenten-seitige `kind`-Gruppierung** (z. B. ein eigener Reiter „Geräte" vs. „Verbindungen" vs. „Prozesse" in der Befund-Ansicht) ist mit dem Feld jetzt möglich, aber nicht Teil dieses Schnitts.
- **`help_kind` vs. `kind`:** beide bleiben getrennt — `help_kind` zeigt auf einen Hilfe-Typ (eine Hilfe-Quelle kann mehrere `kind` bedienen, z. B. `remote_access_port` für `connection_remote_port` **und** `host_remote_port`), `kind` ist die Regel-Pruefart. Keine Zusammenlegung.
